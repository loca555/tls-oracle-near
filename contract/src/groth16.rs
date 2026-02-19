//! Groth16 ZK-верификатор для NEAR через alt_bn128 host functions
//!
//! Портировано из zeropoolnetwork/near-groth16-verifier,
//! адаптировано под near-sdk 5.6.
//!
//! Верификационное уравнение:
//!   e(A, B) == e(α, β) · e(vk_x, γ) · e(C, δ)
//!
//! Где vk_x = IC[0] + Σ(pub_input[i] · IC[i+1])
//!
//! NEAR host functions:
//!   - alt_bn128_g1_multiexp: multi-scalar multiplication на G1
//!   - alt_bn128_g1_sum: сумма точек G1
//!   - alt_bn128_pairing_check: проверка pairing equation

use near_sdk::env;

use crate::bn254_types::{G1Point, G2Point, Scalar, SCALAR_ONE};

/// Verification key для Groth16
#[derive(Clone)]
pub struct VerificationKey {
    pub alpha_g1: G1Point,
    pub beta_g2: G2Point,
    pub gamma_g2: G2Point,
    pub delta_g2: G2Point,
    /// IC[0..=n] где n = количество public inputs
    pub ic: Vec<G1Point>,
}

/// Groth16 proof
pub struct Proof {
    pub a: G1Point,
    pub b: G2Point,
    pub c: G1Point,
}

/// Вычисляет multi-scalar multiplication: Σ(scalar[i] · point[i])
/// через env::alt_bn128_g1_multiexp
fn g1_multiexp(pairs: &[(Scalar, G1Point)]) -> G1Point {
    // Формат для NEAR: [(scalar_32bytes, g1_point_64bytes), ...]
    // Каждый элемент: 32 (scalar) + 64 (G1) = 96 байт
    let mut data = Vec::with_capacity(pairs.len() * 96);
    for (scalar, point) in pairs {
        data.extend_from_slice(&scalar.to_bytes());
        data.extend_from_slice(&point.to_bytes());
    }

    let result = env::alt_bn128_g1_multiexp(&data);
    assert!(result.len() == 64, "alt_bn128_g1_multiexp: ожидалось 64 байт");

    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&result[..32]);
    y.copy_from_slice(&result[32..]);
    G1Point { x, y }
}

/// Сумма точек G1 через env::alt_bn128_g1_sum
/// Знак: false = сложение, true = вычитание
fn g1_sum(points: &[(bool, G1Point)]) -> G1Point {
    // Формат для NEAR: [(sign_byte, g1_point_64bytes), ...]
    // sign: 0 = add, 1 = subtract
    let mut data = Vec::with_capacity(points.len() * 65);
    for (negate, point) in points {
        data.push(if *negate { 1u8 } else { 0u8 });
        data.extend_from_slice(&point.to_bytes());
    }

    let result = env::alt_bn128_g1_sum(&data);
    assert!(result.len() == 64, "alt_bn128_g1_sum: ожидалось 64 байт");

    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&result[..32]);
    y.copy_from_slice(&result[32..]);
    G1Point { x, y }
}

/// Проверяет Groth16 proof
///
/// Верификационное уравнение:
///   e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1
///
/// Где:
///   vk_x = IC[0] + Σ(pub_input[i] · IC[i+1])
///
/// Возвращает true если proof корректен
pub fn verify(vk: &VerificationKey, proof: &Proof, public_inputs: &[Scalar]) -> bool {
    assert!(
        vk.ic.len() == public_inputs.len() + 1,
        "Неверное количество public inputs: ожидалось {}, получено {}",
        vk.ic.len() - 1,
        public_inputs.len()
    );

    // 1. Вычисляем vk_x = IC[0] + Σ(pub_input[i] · IC[i+1])
    //    Сначала multi-scalar multiplication для IC[1..] * pub_inputs
    let msm_pairs: Vec<(Scalar, G1Point)> = public_inputs
        .iter()
        .zip(vk.ic[1..].iter())
        .map(|(scalar, point)| (scalar.clone(), point.clone()))
        .collect();

    let msm_result = g1_multiexp(&msm_pairs);

    // vk_x = IC[0] + msm_result
    let vk_x = g1_sum(&[(false, vk.ic[0].clone()), (false, msm_result)]);

    // 2. Отрицание A
    let neg_a = proof.a.neg();

    // 3. Pairing check: e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1
    //
    // Формат для NEAR alt_bn128_pairing_check:
    // [(G1_64bytes, G2_128bytes), ...] = 192 байт на пару, 4 пары = 768 байт
    let mut pairing_data = Vec::with_capacity(4 * 192);

    // Пара 1: e(-A, B)
    pairing_data.extend_from_slice(&neg_a.to_bytes());
    pairing_data.extend_from_slice(&proof.b.to_bytes());

    // Пара 2: e(α, β)
    pairing_data.extend_from_slice(&vk.alpha_g1.to_bytes());
    pairing_data.extend_from_slice(&vk.beta_g2.to_bytes());

    // Пара 3: e(vk_x, γ)
    pairing_data.extend_from_slice(&vk_x.to_bytes());
    pairing_data.extend_from_slice(&vk.gamma_g2.to_bytes());

    // Пара 4: e(C, δ)
    pairing_data.extend_from_slice(&proof.c.to_bytes());
    pairing_data.extend_from_slice(&vk.delta_g2.to_bytes());

    env::alt_bn128_pairing_check(&pairing_data)
}
