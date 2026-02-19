#!/bin/bash
set -e

# ── Компиляция и trusted setup для AttestationVerifier circuit ──
#
# Требования: circom, snarkjs, node
# Выход: build/verification_key.json, build/att_final.zkey, build/attestation_js/

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Установка зависимостей ==="
npm install

echo "=== Компиляция circom → R1CS + WASM ==="
mkdir -p build
circom attestation.circom --r1cs --wasm --sym -o build/

echo "=== Circuit info ==="
snarkjs r1cs info build/attestation.r1cs

echo "=== Powers of Tau (BN128, 2^13) ==="
# 2^13 = 8192 constraints — достаточно для ~4607 constraints (Poseidon tree)
snarkjs powersoftau new bn128 13 build/pot13_0.ptau -v
snarkjs powersoftau contribute build/pot13_0.ptau build/pot13_1.ptau \
  --name="TLS Oracle Phase 1" -v -e="random-entropy-$(date +%s)"
snarkjs powersoftau prepare phase2 build/pot13_1.ptau build/pot13_final.ptau -v

echo "=== Groth16 Setup (Phase 2) ==="
snarkjs groth16 setup build/attestation.r1cs build/pot13_final.ptau build/att_0.zkey
snarkjs zkey contribute build/att_0.zkey build/att_final.zkey \
  --name="TLS Oracle Phase 2" -v -e="random-entropy-phase2-$(date +%s)"

echo "=== Экспорт Verification Key ==="
snarkjs zkey export verificationkey build/att_final.zkey build/verification_key.json

echo "=== Генерация Rust VK ==="
node vk_to_rust.js build/verification_key.json > ../contract/src/vk_data.rs
echo "Rust VK записан в ../contract/src/vk_data.rs"

echo ""
echo "=== Готово ==="
echo "Proving key:      build/att_final.zkey"
echo "Verification key: build/verification_key.json"
echo "Circuit WASM:     build/attestation_js/attestation.wasm"
echo ""
echo "Для тестирования:"
echo "  node input_generator.js --test"
echo "  snarkjs groth16 fullprove input.json build/attestation_js/attestation.wasm build/att_final.zkey proof.json public.json"
echo "  snarkjs groth16 verify build/verification_key.json public.json proof.json"
