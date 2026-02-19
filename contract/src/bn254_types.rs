//! Типы для работы с кривой BN254 (alt_bn128) на NEAR
//!
//! NEAR host functions (env::alt_bn128_*) ожидают точки в формате:
//! - G1: 64 байта (x: 32 LE + y: 32 LE)
//! - G2: 128 байт (x_im: 32 LE + x_re: 32 LE + y_im: 32 LE + y_re: 32 LE)
//! - Scalar (Fr): 32 байта LE

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};

/// Точка на G1 (кривая E(Fq))
#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct G1Point {
    pub x: [u8; 32], // Fq, little-endian
    pub y: [u8; 32], // Fq, little-endian
}

/// Точка на G2 (кривая E'(Fq2))
/// NEAR формат: x_im, x_re, y_im, y_re (каждый 32 байта LE)
#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct G2Point {
    pub x_im: [u8; 32], // Fq (мнимая часть x)
    pub x_re: [u8; 32], // Fq (действительная часть x)
    pub y_im: [u8; 32], // Fq (мнимая часть y)
    pub y_re: [u8; 32], // Fq (действительная часть y)
}

/// Скаляр поля Fr (порядок подгруппы BN254)
#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct Scalar(pub [u8; 32]); // little-endian

/// Единичный скаляр (1)
pub const SCALAR_ONE: Scalar = Scalar([
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0,
]);

/// Парсит decimal string в 32 байта little-endian
/// Для конвертации public signals из snarkjs формата
pub fn decimal_to_le_bytes(s: &str) -> [u8; 32] {
    let mut result = [0u8; 32];

    // Парсим decimal string вручную (без big integer crate)
    // Работаем с массивом u8 как с числом в base-256 little-endian
    let mut temp = [0u8; 32];
    for ch in s.chars() {
        if !ch.is_ascii_digit() {
            continue;
        }
        let digit = (ch as u8) - b'0';

        // temp = temp * 10 + digit
        let mut carry: u16 = digit as u16;
        for byte in temp.iter_mut() {
            let val = (*byte as u16) * 10 + carry;
            *byte = (val & 0xff) as u8;
            carry = val >> 8;
        }
    }

    result.copy_from_slice(&temp);
    result
}

impl G1Point {
    /// Создаёт G1 точку из двух decimal strings [x, y]
    pub fn from_decimal(x: &str, y: &str) -> Self {
        Self {
            x: decimal_to_le_bytes(x),
            y: decimal_to_le_bytes(y),
        }
    }

    /// Отрицание точки G1: -P = (x, -y mod q)
    /// q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
    pub fn neg(&self) -> Self {
        // q в little-endian
        let q: [u8; 32] = [
            0x47, 0xFD, 0x7C, 0xD8, 0x16, 0x8C, 0x20, 0x3C, 0x8d, 0xca, 0x71, 0x68, 0x91, 0x6a,
            0x81, 0x97, 0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8, 0x29, 0xa0, 0x31, 0xe1,
            0x72, 0x4e, 0x64, 0x30,
        ];

        // -y = q - y
        let mut neg_y = [0u8; 32];
        let mut borrow: i16 = 0;
        for i in 0..32 {
            let val = q[i] as i16 - self.y[i] as i16 - borrow;
            if val < 0 {
                neg_y[i] = (val + 256) as u8;
                borrow = 1;
            } else {
                neg_y[i] = val as u8;
                borrow = 0;
            }
        }

        Self {
            x: self.x,
            y: neg_y,
        }
    }

    /// Сериализация для NEAR: 64 байта (x ++ y)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x);
        out[32..].copy_from_slice(&self.y);
        out
    }
}

impl G2Point {
    /// Сериализация для NEAR: 128 байт (x_im ++ x_re ++ y_im ++ y_re)
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        out[..32].copy_from_slice(&self.x_im);
        out[32..64].copy_from_slice(&self.x_re);
        out[64..96].copy_from_slice(&self.y_im);
        out[96..128].copy_from_slice(&self.y_re);
        out
    }
}

impl Scalar {
    /// Создаёт скаляр из decimal string
    pub fn from_decimal(s: &str) -> Self {
        Self(decimal_to_le_bytes(s))
    }

    /// Сериализация: 32 байта LE
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}
