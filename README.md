# TLS Oracle — NEAR Blockchain

Universal oracle powered by TLS Notary for the NEAR blockchain. Cryptographically proves data from any website and stores attestations on-chain with Ed25519 signature verification.

## Architecture

```
[User] → [Frontend (React)] → [Backend (Express)]
                                      ↓ HTTP
                              [Prover Service (Rust/Axum)]
                                      ↕ MPC-TLS
                              [Notary Server (Rust/Axum)]
                                      ↓
                              [Ed25519 Attestation]
                                      ↓
                              [NEAR Smart Contract]
                              env::ed25519_verify → store
```

**Trust model:** The Notary signs data obtained from a real TLS connection. The Prover cannot forge data — the Notary verifies MPC commitments before signing. The contract verifies the Ed25519 signature via NEAR's native host function.

## Components

| Component | Stack | Port |
|-----------|-------|------|
| `contract/` | Rust, near-sdk 5.6 | — |
| `notary/` | Rust, Axum, ed25519-dalek | 7047 |
| `prover/` | Rust, Axum | 7048 |
| `backend/` | Node.js, Express | 4001 |
| `frontend/` | React 18, Vite 5 | 3001 |

## Live Deployment

| Service | URL |
|---------|-----|
| Frontend + API | https://tls-oracle-backend.onrender.com |
| Notary Server | https://tls-notary-server.onrender.com |
| Prover Service | https://tls-prover-service.onrender.com |
| NEAR Contract | `tls-oracle.nearcast-oracle.testnet` |

## Local Setup

```bash
# 1. Contract (build + deploy)
cd contract && bash build.sh
near deploy <account> target/wasm32-unknown-unknown/release/tls_oracle_mvp.wasm
near call <account> new '{"owner": "<owner>"}' --accountId <owner>

# 2. Notary Server
cd notary && cargo run --release
# → http://localhost:7047 (generates Ed25519 key on first run)

# 3. Prover Service
cd prover && cargo run --release
# → http://localhost:7048

# 4. Backend + Frontend
cp .env.example .env  # fill in variables
npm install && cd frontend && npm install && cd ..
npm run dev
# → Backend http://localhost:4001, Frontend http://localhost:3001
```

## Environment Variables

```env
NEAR_NETWORK=testnet
TLS_ORACLE_CONTRACT=tls-oracle.nearcast-oracle.testnet
ORACLE_ACCOUNT_ID=...
ORACLE_PRIVATE_KEY=...
PROVER_URL=http://127.0.0.1:7048
NOTARY_URL=http://127.0.0.1:7047
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/prove` | Request a TLS attestation `{url}` |
| POST | `/api/submit` | Submit attestation to NEAR contract |
| POST | `/api/prove-and-submit` | Prove + Submit in a single request |
| GET | `/api/attestations` | List attestations |
| GET | `/api/attestations/:id` | Attestation details |
| GET | `/api/notaries` | Trusted notaries |
| GET | `/api/stats` | Statistics |
| GET | `/api/templates` | URL presets |
| GET | `/api/health` | Service health status |

## Smart Contract

**Methods:**
- `add_notary(pubkey, name, url)` — register a trusted notary (owner only)
- `remove_notary(pubkey)` — remove a notary (owner only)
- `submit_attestation(source_url, server_name, timestamp, response_data, notary_pubkey, signature)` — submit attestation (verifies Ed25519)
- `get_attestation(id)` / `get_attestations(from_index, limit)` — read data
- `get_notaries()` / `get_stats()` — info

## License

MIT
