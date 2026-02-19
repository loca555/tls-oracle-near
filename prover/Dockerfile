FROM rust:1.85-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN CARGO_BUILD_JOBS=2 cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 \
    nodejs npm && rm -rf /var/lib/apt/lists/*
# Глобальный snarkjs для ZK proof generation
RUN npm install -g snarkjs@0.7.6

COPY --from=builder /app/target/release/prover-service /usr/local/bin/prover-service
# ZK артефакты: circuit WASM, proving key, generate_proof.js
COPY zk/ /app/zk/
RUN cd /app/zk && npm install --production

WORKDIR /app
ENV ZK_DIR=/app/zk
EXPOSE 7048
CMD ["prover-service"]
