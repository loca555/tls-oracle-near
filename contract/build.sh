#!/bin/bash
# Сборка TLS Oracle контракта для NEAR
#
# NEAR VM (protocol <=82) не поддерживает bulk-memory, sign-ext и другие
# WASM-фичи, включённые в Rust 1.82+. После сборки cargo
# нужна пост-обработка через wasm-opt.
#
# Зависимости: cargo, wasm-opt (npm install -g binaryen)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== TLS Oracle — Сборка контракта ==="

# 1. Сборка через cargo
echo "-> cargo build --release..."
RUSTFLAGS='-C link-arg=-s' cargo build --target wasm32-unknown-unknown --release

WASM_IN="target/wasm32-unknown-unknown/release/tls_oracle.wasm"
WASM_OUT="target/wasm32-unknown-unknown/release/tls_oracle_mvp.wasm"

# 2. Пост-обработка: понижение WASM-фич до MVP
echo "-> wasm-opt: понижение bulk-memory, sign-ext, nontrapping-fptoint..."
wasm-opt \
  --enable-bulk-memory \
  --enable-mutable-globals \
  --enable-sign-ext \
  --enable-nontrapping-float-to-int \
  --llvm-memory-copy-fill-lowering \
  --signext-lowering \
  --llvm-nontrapping-fptoint-lowering \
  -Oz \
  --strip-debug \
  "$WASM_IN" \
  -o "$WASM_OUT"

SIZE=$(stat -c%s "$WASM_OUT" 2>/dev/null || stat -f%z "$WASM_OUT" 2>/dev/null || wc -c < "$WASM_OUT")
echo ""
echo "OK: $WASM_OUT ($SIZE bytes)"
echo "  Deploy: near deploy <account> $WASM_OUT --networkId testnet"
