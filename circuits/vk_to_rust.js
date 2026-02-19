/**
 * Конвертер Verification Key из snarkjs JSON → Rust code для NEAR контракта
 *
 * snarkjs выдаёт координаты как decimal strings (big-endian).
 * NEAR env::alt_bn128_* принимает little-endian bytes.
 *
 * Использование: node vk_to_rust.js build/verification_key.json > ../contract/src/vk_data.rs
 */

import { readFileSync } from "fs";

const vkFile = process.argv[2] || "build/verification_key.json";
const vk = JSON.parse(readFileSync(vkFile, "utf8"));

/**
 * Decimal string → 32-byte little-endian array
 */
function decimalToLeBytes(s) {
  let n = BigInt(s);
  const bytes = [];
  for (let i = 0; i < 32; i++) {
    bytes.push(Number(n & 0xffn));
    n >>= 8n;
  }
  return bytes;
}

/**
 * Format [u8; 32] as Rust literal
 */
function rustBytes32(bytes) {
  const chunks = [];
  for (let i = 0; i < 32; i += 8) {
    chunks.push(bytes.slice(i, i + 8).join(", "));
  }
  return `[${chunks.join(",\n            ")}]`;
}

/**
 * G1 point [x, y] → Rust bytes (64 bytes = x_le ++ y_le)
 */
function g1Rust(point) {
  const x = decimalToLeBytes(point[0]);
  const y = decimalToLeBytes(point[1]);
  return `G1Point {
        x: ${rustBytes32(x)},
        y: ${rustBytes32(y)},
    }`;
}

/**
 * G2 point [[x1, x2], [y1, y2]] → Rust bytes
 * snarkjs format: x = x1 + x2*i, y = y1 + y2*i
 * NEAR format: x_im, x_re, y_im, y_re (each 32 bytes LE)
 */
function g2Rust(point) {
  // snarkjs: [[x1, x2], [y1, y2]] where x = x1 + x2*u
  // NEAR alt_bn128: x_im (x2), x_re (x1), y_im (y2), y_re (y1)
  const x_re = decimalToLeBytes(point[0][0]); // x1
  const x_im = decimalToLeBytes(point[0][1]); // x2
  const y_re = decimalToLeBytes(point[1][0]); // y1
  const y_im = decimalToLeBytes(point[1][1]); // y2
  return `G2Point {
        x_im: ${rustBytes32(x_im)},
        x_re: ${rustBytes32(x_re)},
        y_im: ${rustBytes32(y_im)},
        y_re: ${rustBytes32(y_re)},
    }`;
}

// Генерируем Rust код
const icEntries = vk.IC.map(
  (ic, i) => `    // IC[${i}]\n    ${g1Rust(ic)}`,
).join(",\n");

const rust = `//! Автогенерированный Verification Key для Groth16 ZK-верификации
//!
//! Сгенерировано: node vk_to_rust.js ${vkFile}
//! Дата: ${new Date().toISOString()}
//!
//! НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ — перегенерировать через build.sh

use crate::bn254_types::{G1Point, G2Point};
use crate::groth16::VerificationKey;

/// Возвращает verification key для circuit AttestationVerifier(17)
pub fn get_vk() -> VerificationKey {
    VerificationKey {
        alpha_g1: ${g1Rust(vk.vk_alpha_1)},
        beta_g2: ${g2Rust(vk.vk_beta_2)},
        gamma_g2: ${g2Rust(vk.vk_gamma_2)},
        delta_g2: ${g2Rust(vk.vk_delta_2)},
        ic: vec![
${icEntries},
        ],
    }
}
`;

process.stdout.write(rust);
