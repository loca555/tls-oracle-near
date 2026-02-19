FROM rust:1.85-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
# Ограничиваем параллелизм — экономим память на free tier
RUN CARGO_BUILD_JOBS=2 cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/notary-server /usr/local/bin/notary-server
EXPOSE 7047
CMD ["notary-server"]
