# TLS Oracle — Документация (RU)

Универсальный оракул на базе TLS Notary для NEAR. Криптографически доказывает данные с любого веб-сайта через MPC-TLS протокол и записывает аттестацию on-chain с верификацией Groth16 ZK-proof через alt_bn128.

## Архитектура

```
[Пользователь] → [Frontend (React)] → [Backend (Express)]
                                              ↓ HTTP POST /prove
                                      [Prover Service (Rust/Axum)]
                                         ┌────────────────────┐
                                         │  MPC-TLS Prover    │
                                         │     ↕ duplex       │
                                         │  Embedded Notary   │
                                         │  (secp256k1 sign)  │
                                         └────────┬───────────┘
                                                  ↓ TCP
                                         [Целевой HTTPS сервер]
                                                  ↓
                                         [snarkjs Groth16 proof]
                                                  ↓
                                      [NEAR Smart Contract]
                                      env::alt_bn128_pairing_check → store
```

**Модель доверия:**
- **MPC-TLS**: Prover и Notary (Verifier) совместно выполняют TLS handshake. Notary участвует в MPC-протоколе и подтверждает подлинность данных, не видя plaintext. Prover не может подделать данные.
- **ZK-Proof**: Groth16 proof доказывает on-chain, что Prover знает данные, server name и notary pubkey с правильными Poseidon-хешами. Контракт проверяет proof через `alt_bn128_pairing_check` (~15 TGas).
- **Доверенный Notary**: Контракт хранит Poseidon-хеши pubkey доверенных нотариусов. ECDSA подпись верифицируется off-chain в Prover (ECDSA в circuit = 500K+ constraints — будет добавлено позже).

## Компоненты

| Компонент | Стек | Порт | Описание |
|-----------|------|------|----------|
| `contract/` | Rust, near-sdk 5.6 | — | NEAR контракт: Groth16 верификация через alt_bn128, хранение аттестаций |
| `prover/` | Rust, Axum, tlsn, k256 | 7048 | MPC-TLS Prover + embedded Notary + ZK proof generation (snarkjs) |
| `notary/` | Rust, Axum | 7047 | Legacy standalone Notary (для VPS deployment) |
| `circuits/` | Circom 2.1, snarkjs | — | Poseidon-based ZK circuit (4607 constraints), trusted setup |
| `backend/` | Node.js, Express | 4001 | API сервер, проксирует запросы к Prover |
| `frontend/` | React 18, Vite 5 | 3001 | UI: запрос аттестаций, лента, нотариусы |

## Развёрнутые сервисы

| Сервис | URL |
|--------|-----|
| Frontend + API | https://tls-oracle-backend.onrender.com |
| Prover (MPC-TLS + ZK) | https://tls-oracle-prover.onrender.com |
| NEAR Contract | `tls-oracle-v2.nearcast-oracle.testnet` |

## Локальный запуск

```bash
# 1. Circuit (компиляция + trusted setup)
cd circuits && bash build.sh
# Генерирует: build/att_final.zkey, build/attestation_js/attestation.wasm
# Обновляет: contract/src/vk_data.rs

# 2. Контракт (сборка + деплой)
cd contract && bash build.sh
near deploy <account> target/wasm32-unknown-unknown/release/tls_oracle.wasm
near call <account> new '{"owner": "<owner>"}' --accountId <owner>
near call <account> add_notary '{"pubkey_hash": "<poseidon_hash>", "name": "...", "url": "..."}' --accountId <owner>

# 3. Prover Service (MPC-TLS + embedded Notary)
# Скопировать circuit артефакты:
cp circuits/build/attestation_js/attestation.wasm prover/zk/attestation_js/
cp circuits/build/att_final.zkey prover/zk/attestation_final.zkey
cd prover/zk && npm install
cd ../.. && cd prover && cargo run --release
# → http://localhost:7048, генерирует secp256k1 ключ при первом запуске

# 4. Backend + Frontend
cp .env.example .env  # заполнить переменные
npm install && cd frontend && npm install && cd ..
npm run dev
# → Backend http://localhost:4001, Frontend http://localhost:3001
```

## Переменные окружения

```env
# NEAR
NEAR_NETWORK=testnet
TLS_ORACLE_CONTRACT=tls-oracle-v2.nearcast-oracle.testnet

# Prover Service
PROVER_URL=http://127.0.0.1:7048
PROVER_PORT=7048
PROVER_BIND=127.0.0.1
NOTARY_KEY_PATH=notary_key.bin   # secp256k1 ключ
ZK_DIR=zk                        # путь к circuit артефактам

# Backend
PORT=4001
```

## API эндпоинты

| Метод | Эндпоинт | Описание |
|-------|----------|----------|
| POST | `/api/prove` | Запросить MPC-TLS аттестацию + ZK proof. Body: `{"url": "https://..."}`. Требует API-ключ (X-API-Key) |
| GET | `/api/attestations` | Список аттестаций. Query: `?from=0&limit=20` |
| GET | `/api/attestations/:id` | Детали аттестации по ID |
| GET | `/api/attestations/source/:domain` | Аттестации по домену |
| GET | `/api/notaries` | Список доверенных нотариусов |
| GET | `/api/stats` | Статистика (кол-во аттестаций, нотариусов) |
| GET | `/api/templates` | Пресеты URL (CoinGecko, httpbin и т.д.) |
| GET | `/api/health` | Статус сервисов (backend, prover, contract) |
| GET | `/api/near-config` | Конфиг NEAR для фронтенда |

### Формат ответа `/api/prove`

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

## Смарт-контракт

**Контракт:** `tls-oracle-v2.nearcast-oracle.testnet`
**Owner:** `nearcast-oracle.testnet`

### Методы записи

| Метод | Кто вызывает | Описание |
|-------|-------------|----------|
| `new(owner)` | — | Инициализация контракта |
| `add_notary(pubkey_hash, name, url)` | owner | Добавить нотариуса по Poseidon-хешу secp256k1 pubkey |
| `remove_notary(pubkey_hash)` | owner | Удалить нотариуса |
| `set_owner(new_owner)` | owner | Передать владение |
| `submit_attestation(...)` | любой (payable) | Отправить аттестацию с Groth16 ZK proof |

### Параметры `submit_attestation`

| Параметр | Тип | Описание |
|----------|-----|----------|
| `source_url` | String | Полный URL запроса (макс 2KB) |
| `server_name` | String | Домен (api.coingecko.com) |
| `timestamp` | u64 | UNIX timestamp MPC-TLS сессии |
| `response_data` | String | Данные ответа, JSON (макс 4KB) |
| `proof_a` | [String; 2] | Groth16 G1 точка A (decimal strings) |
| `proof_b` | [[String; 2]; 2] | Groth16 G2 точка B |
| `proof_c` | [String; 2] | Groth16 G1 точка C |
| `public_signals` | [String; 4] | [dataCommitment, serverNameHash, timestamp, notaryPubkeyHash] |

**Верификация on-chain:**
1. Проверка timestamp (±10 мин от block timestamp)
2. Проверка `notaryPubkeyHash` в списке доверенных нотариусов
3. Replay-защита по `dataCommitment` (Poseidon hash)
4. Groth16 verify через `env::alt_bn128_pairing_check` (~15 TGas)

### View методы

| Метод | Возвращает |
|-------|-----------|
| `get_attestation(id)` | `Option<Attestation>` |
| `get_attestations(from_index?, limit?)` | `Vec<Attestation>` (новые первыми) |
| `get_attestations_by_source(server_name, limit?)` | `Vec<Attestation>` по домену |
| `get_notaries()` | `Vec<NotaryInfo>` |
| `get_stats()` | `{attestationCount, notaryCount, owner}` |
| `get_owner()` | `AccountId` |

## ZK Circuit

**Файл:** `circuits/attestation.circom`
**Constraints:** 4607 (Poseidon tree)
**Public signals:** 4 (dataCommitment, serverNameHash, timestamp, notaryPubkeyHash)
**Private inputs:** 27 (responseData[17], serverName[8], notaryPubkey[2])

Двухуровневый Poseidon tree для данных (17 блоков × 31 байт = 527 байт макс):
- `hash1 = Poseidon(9)(blocks[0..8])`
- `hash2 = Poseidon(8)(blocks[9..16])`
- `dataCommitment = Poseidon(2)(hash1, hash2)`

## Поток данных

```
1. Пользователь вводит URL в UI (или выбирает пресет)
2. Frontend → POST /api/prove {url} (с API-ключом)
3. Backend → Prover Service POST /prove
4. Prover запускает MPC-TLS:
   a. tokio::io::duplex() → (prover_io, verifier_io)
   b. Embedded Notary (Verifier) в фоновом task
   c. MPC-TLS handshake с целевым сервером
   d. HTTP запрос через MPC-TLS соединение
   e. Prover.prove() → Attestation (secp256k1)
5. snarkjs Groth16 fullProve → proof + publicSignals
6. Ответ с данными + ZK proof возвращается пользователю
7. Пользователь нажимает "Записать в NEAR" (подписывает из своего кошелька)
8. Кошелёк → NEAR contract: submit_attestation(..., proof_a/b/c, public_signals)
9. Контракт: alt_bn128_pairing_check → сохраняет аттестацию on-chain
```

## Roadmap

- [x] MPC-TLS протокол (tlsn v0.1.0-alpha.14, embedded Prover + Notary)
- [x] ZK-proof верификация on-chain (Groth16 через alt_bn128_pairing_check)
- [x] Poseidon-based circuit (4607 constraints, <1 сек proof generation)
- [x] Replay-защита (Poseidon data commitment)
- [x] API-ключи через NEAR wallet verification
- [x] SSRF-защита в Prover (url_validator)
- [ ] ECDSA secp256k1 верификация в circuit — trustless proof (circom-ecdsa, ~500K constraints)
- [ ] Интеграция с NearCast как oracle-провайдер
- [ ] Selective disclosure (раскрытие только части данных)
- [ ] Множественные нотариусы (N-of-M threshold)
- [ ] *(low priority)* TEE attestation для Notary (Intel TDX/SGX)
- [ ] *(low priority)* WebSocket streaming для прогресса MPC-TLS сессии
