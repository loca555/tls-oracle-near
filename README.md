# TLS Oracle — NEAR Blockchain

Universal oracle powered by TLS Notary for the NEAR blockchain. Cryptographically proves data from any website via MPC-TLS protocol and stores attestations on-chain with Groth16 ZK-proof verification through alt_bn128.

## Architecture

```
[User] → [Frontend (React)] → [Backend (Express)]
                                      ↓ HTTP POST /prove
                              [Prover Service (Rust/Axum)]
                                 ┌────────────────────┐
                                 │  MPC-TLS Prover     │
                                 │     ↕ duplex        │
                                 │  Embedded Notary    │
                                 │  (secp256k1 sign)   │
                                 └────────┬────────────┘
                                          ↓ TCP
                                 [Target HTTPS Server]
                                          ↓
                                 [snarkjs Groth16 proof]
                                          ↓
                              [NEAR Smart Contract]
                              env::alt_bn128_pairing_check → store
```

**Trust model:**
- **MPC-TLS**: Prover and Notary (Verifier) jointly perform a TLS handshake. The Notary participates in the MPC protocol and confirms data authenticity without seeing plaintext. The Prover cannot forge data.
- **ZK-Proof**: A Groth16 proof proves on-chain that the Prover knows the data, server name, and notary pubkey with correct Poseidon hashes. The contract verifies the proof via `alt_bn128_pairing_check` (~15 TGas).
- **Trusted Notary**: The contract stores Poseidon hashes of trusted notary pubkeys. ECDSA signature is verified off-chain in the Prover (ECDSA in circuit = 500K+ constraints — to be added later).

## Components

| Component | Stack | Port | Description |
|-----------|-------|------|-------------|
| `contract/` | Rust, near-sdk 5.6 | — | NEAR contract: Groth16 verification via alt_bn128, attestation storage |
| `prover/` | Rust, Axum, tlsn, k256 | 7048 | MPC-TLS Prover + embedded Notary + ZK proof generation (snarkjs) |
| `notary/` | Rust, Axum | 7047 | Legacy standalone Notary (for VPS deployment) |
| `circuits/` | Circom 2.1, snarkjs | — | Poseidon-based ZK circuit (4607 constraints), trusted setup |
| `backend/` | Node.js, Express | 4001 | API server, proxies requests to Prover |
| `frontend/` | React 18, Vite 5 | 3001 | UI: request attestations, feed, notaries |

## Live Deployment

| Service | URL |
|---------|-----|
| Frontend + API | https://tls-oracle-backend.onrender.com |
| Prover (MPC-TLS + ZK) | https://tls-oracle-prover.onrender.com |
| NEAR Contract | `tls-oracle-v2.nearcast-oracle.testnet` |

## Local Setup

```bash
# 1. Circuit (compile + trusted setup)
cd circuits && bash build.sh
# Generates: build/att_final.zkey, build/attestation_js/attestation.wasm
# Updates: contract/src/vk_data.rs

# 2. Contract (build + deploy)
cd contract && bash build.sh
near deploy <account> target/wasm32-unknown-unknown/release/tls_oracle.wasm
near call <account> new '{"owner": "<owner>"}' --accountId <owner>
near call <account> add_notary '{"pubkey_hash": "<poseidon_hash>", "name": "...", "url": "..."}' --accountId <owner>

# 3. Prover Service (MPC-TLS + embedded Notary)
# Copy circuit artifacts:
cp circuits/build/attestation_js/attestation.wasm prover/zk/attestation_js/
cp circuits/build/att_final.zkey prover/zk/attestation_final.zkey
cd prover/zk && npm install
cd ../.. && cd prover && cargo run --release
# → http://localhost:7048, generates secp256k1 key on first run

# 4. Backend + Frontend
cp .env.example .env  # fill in variables
npm install && cd frontend && npm install && cd ..
npm run dev
# → Backend http://localhost:4001, Frontend http://localhost:3001
```

## Environment Variables

```env
# NEAR
NEAR_NETWORK=testnet
TLS_ORACLE_CONTRACT=tls-oracle-v2.nearcast-oracle.testnet

# Prover Service
PROVER_URL=http://127.0.0.1:7048
PROVER_PORT=7048
PROVER_BIND=127.0.0.1
NOTARY_KEY_PATH=notary_key.bin   # secp256k1 key
ZK_DIR=zk                        # path to circuit artifacts

# Backend
PORT=4001
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/prove` | Request MPC-TLS attestation + ZK proof. Body: `{"url": "https://..."}`. Requires API key (X-API-Key) |
| GET | `/api/attestations` | List attestations. Query: `?from=0&limit=20` |
| GET | `/api/attestations/:id` | Attestation details by ID |
| GET | `/api/attestations/source/:domain` | Attestations by domain |
| GET | `/api/notaries` | Trusted notaries |
| GET | `/api/stats` | Statistics (attestation count, notary count) |
| GET | `/api/templates` | URL presets (CoinGecko, httpbin, etc.) |
| GET | `/api/health` | Service health status (backend, prover, contract) |
| GET | `/api/near-config` | NEAR config for frontend |

### `/api/prove` response format

```json
{
  "sourceUrl": "https://api.coingecko.com/...",
  "serverName": "api.coingecko.com",
  "timestamp": 1740000000,
  "responseData": "{\"bitcoin\":{\"usd\":95000}}",
  "proofA": ["12345...", "67890..."],
  "proofB": [["111...", "222..."], ["333...", "444..."]],
  "proofC": ["555...", "666..."],
  "publicSignals": ["<dataCommitment>", "<serverNameHash>", "<timestamp>", "<notaryPubkeyHash>"]
}
```

## Smart Contract

**Contract:** `tls-oracle-v2.nearcast-oracle.testnet`
**Owner:** `nearcast-oracle.testnet`

### Write methods

| Method | Caller | Description |
|--------|--------|-------------|
| `new(owner)` | — | Initialize contract |
| `add_notary(pubkey_hash, name, url)` | owner | Add notary by Poseidon hash of secp256k1 pubkey |
| `remove_notary(pubkey_hash)` | owner | Remove notary |
| `set_owner(new_owner)` | owner | Transfer ownership |
| `submit_attestation(...)` | anyone (payable) | Submit attestation with Groth16 ZK proof |

### `submit_attestation` parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `source_url` | String | Full request URL (max 2KB) |
| `server_name` | String | Domain (api.coingecko.com) |
| `timestamp` | u64 | UNIX timestamp of MPC-TLS session |
| `response_data` | String | Response data, JSON (max 4KB) |
| `proof_a` | [String; 2] | Groth16 G1 point A (decimal strings) |
| `proof_b` | [[String; 2]; 2] | Groth16 G2 point B |
| `proof_c` | [String; 2] | Groth16 G1 point C |
| `public_signals` | [String; 4] | [dataCommitment, serverNameHash, timestamp, notaryPubkeyHash] |

**On-chain verification:**
1. Timestamp check (±10 min from block timestamp)
2. `notaryPubkeyHash` must be in trusted notary list
3. Replay protection via `dataCommitment` (Poseidon hash)
4. Groth16 verify via `env::alt_bn128_pairing_check` (~15 TGas)

### View methods

| Method | Returns |
|--------|---------|
| `get_attestation(id)` | `Option<Attestation>` |
| `get_attestations(from_index?, limit?)` | `Vec<Attestation>` (newest first) |
| `get_attestations_by_source(server_name, limit?)` | `Vec<Attestation>` by domain |
| `get_notaries()` | `Vec<NotaryInfo>` |
| `get_stats()` | `{attestationCount, notaryCount, owner}` |
| `get_owner()` | `AccountId` |

## Usage Examples / Примеры использования

### Get a crypto price attestation / Получить аттестацию цены криптовалюты

**Via UI:**
1. Open https://tls-oracle-backend.onrender.com
2. Connect your NEAR wallet → click "Get API Key"
3. Select "CoinGecko — BTC/USD" from presets or enter:
   ```
   https://api.coingecko.com/api/v3/simple/price?ids=near&vs_currencies=usd
   ```
4. Click **"Get Attestation"** — MPC-TLS + ZK proof takes ~30-60 seconds
5. Review the result: domain, timestamp, data, ZK proof
6. Click **"Submit to NEAR (0.05 NEAR)"** — writes attestation on-chain with Groth16 verification

**Via API (curl):**
```bash
# 1. Get API key (register via UI first)

# 2. Request attestation
curl -X POST https://tls-oracle-backend.onrender.com/api/prove \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"url": "https://api.coingecko.com/api/v3/simple/price?ids=near&vs_currencies=usd"}'

# Response:
# {
#   "sourceUrl": "https://api.coingecko.com/...",
#   "serverName": "api.coingecko.com",
#   "timestamp": 1740000000,
#   "responseData": "{\"near\":{\"usd\":3.42}}",
#   "proofA": [...], "proofB": [...], "proofC": [...],
#   "publicSignals": ["<dataCommitment>", "<serverNameHash>", "<timestamp>", "<notaryPubkeyHash>"]
# }

# 3. Submit on-chain (via NEAR CLI)
near call tls-oracle-v2.nearcast-oracle.testnet submit_attestation \
  '{"source_url":"...","server_name":"api.coingecko.com","timestamp":1740000000,"response_data":"...","proof_a":[...],"proof_b":[...],"proof_c":[...],"public_signals":[...]}' \
  --accountId your-account.testnet --deposit 0.05 --gas 200000000000000
```

### Prove sports data for prediction markets / Доказать спортивные данные для рынков предсказаний

```bash
# ESPN match result (used by NearCast prediction markets)
curl -X POST https://tls-oracle-backend.onrender.com/api/prove \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"url": "https://site.api.espn.com/apis/site/v2/sports/soccer/eng.1/summary?event=401326..."}'
```

### Read attestations from blockchain / Чтение аттестаций из блокчейна

```bash
# List all attestations
curl https://tls-oracle-backend.onrender.com/api/attestations?limit=10

# By domain
curl https://tls-oracle-backend.onrender.com/api/attestations/source/api.coingecko.com

# Directly from NEAR contract (view call, free)
near view tls-oracle-v2.nearcast-oracle.testnet get_attestations '{"limit": 10}'
near view tls-oracle-v2.nearcast-oracle.testnet get_attestation '{"id": 1}'
```

---

### Примеры (RU)

**Через UI:**
1. Открыть https://tls-oracle-backend.onrender.com
2. Подключить NEAR кошелёк → нажать "Get API Key"
3. Выбрать пресет или ввести URL (например цену NEAR):
   ```
   https://api.coingecko.com/api/v3/simple/price?ids=near&vs_currencies=usd
   ```
4. Нажать **"Get Attestation"** — MPC-TLS + ZK proof занимает ~30-60 секунд
5. Проверить результат: домен, время, данные, ZK proof (Groth16 BN254)
6. Нажать **"Submit to NEAR (0.05 NEAR)"** — записать аттестацию в блокчейн с верификацией ZK proof

**Что происходит под капотом:**
```
Ваш запрос → Backend → Prover (MPC-TLS с api.coingecko.com) → ZK Proof (Groth16)
→ Кошелёк подписывает TX → NEAR контракт верифицирует proof (alt_bn128) → Аттестация в блокчейне
```

**Безопасность:**
- Никто не может подделать данные — MPC-TLS гарантирует подлинность
- ZK proof подтверждает данные без раскрытия приватных входов
- Контракт проверяет: свежесть (±10 мин), доверенный нотариус, уникальность (защита от повтора)

## ZK Circuit

**File:** `circuits/attestation.circom`
**Constraints:** 4607 (Poseidon tree)
**Public signals:** 4 (dataCommitment, serverNameHash, timestamp, notaryPubkeyHash)
**Private inputs:** 27 (responseData[17], serverName[8], notaryPubkey[2])

Two-level Poseidon tree for data (17 blocks × 31 bytes = 527 bytes max):
- `hash1 = Poseidon(9)(blocks[0..8])`
- `hash2 = Poseidon(8)(blocks[9..16])`
- `dataCommitment = Poseidon(2)(hash1, hash2)`

## Roadmap

- [x] MPC-TLS protocol (tlsn v0.1.0-alpha.14, embedded Prover + Notary)
- [x] ZK-proof on-chain verification (Groth16 via alt_bn128_pairing_check)
- [x] Poseidon-based circuit (4607 constraints, <1 sec proof generation)
- [x] Replay protection (Poseidon data commitment)
- [x] API keys via NEAR wallet verification
- [x] SSRF protection in Prover (url_validator)
- [ ] ECDSA secp256k1 verification in circuit — trustless proof (circom-ecdsa, ~500K constraints)
- [ ] NearCast integration as oracle provider
- [ ] Selective disclosure (reveal only parts of data)
- [ ] Multiple notaries (N-of-M threshold)
- [ ] *(low priority)* TEE attestation for Notary (Intel TDX/SGX)
- [ ] *(low priority)* WebSocket streaming for MPC-TLS session progress

## License

MIT
