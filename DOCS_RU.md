# TLS Oracle — Документация (RU)

Универсальный оракул на базе TLS Notary для NEAR. Криптографически доказывает данные с любого веб-сайта и записывает аттестацию on-chain с верификацией Ed25519 подписи.

## Архитектура

```
[Пользователь] → [Frontend (React)] → [Backend (Express)]
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

**Модель доверия:** Notary подписывает данные, полученные из реального TLS-соединения. Prover не может подделать данные — Notary верифицирует MPC-commitments перед подписью. Контракт проверяет Ed25519 подпись через нативную host-функцию NEAR.

## Компоненты

| Компонент | Стек | Порт | Описание |
|-----------|------|------|----------|
| `contract/` | Rust, near-sdk 5.6 | — | NEAR смарт-контракт, хранит аттестации, проверяет Ed25519 |
| `notary/` | Rust, Axum, ed25519-dalek | 7047 | Нотариус — делает HTTP-запрос, подписывает ответ Ed25519 |
| `prover/` | Rust, Axum | 7048 | Прувер — проксирует запросы к нотариусу (MVP); в будущем MPC-TLS |
| `backend/` | Node.js, Express | 4001 | API сервер, связка Prover ↔ NEAR контракт |
| `frontend/` | React 18, Vite 5 | 3001 | UI: форма запроса, лента аттестаций, список нотариусов |

## Развёрнутые сервисы

| Сервис | URL |
|--------|-----|
| Frontend + API | https://tls-oracle-backend.onrender.com |
| Notary Server | https://tls-notary-server.onrender.com |
| Prover Service | https://tls-prover-service.onrender.com |
| NEAR Contract | `tls-oracle.nearcast-oracle.testnet` |

## Локальный запуск

```bash
# 1. Контракт (сборка + деплой)
cd contract && bash build.sh
near deploy <account> target/wasm32-unknown-unknown/release/tls_oracle_mvp.wasm
near call <account> new '{"owner": "<owner>"}' --accountId <owner>

# 2. Notary Server
cd notary && cargo run --release
# → http://localhost:7047, генерирует Ed25519 ключ при первом запуске

# 3. Prover Service
cd prover && cargo run --release
# → http://localhost:7048

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
TLS_ORACLE_CONTRACT=tls-oracle.nearcast-oracle.testnet
ORACLE_ACCOUNT_ID=...          # аккаунт для submit_attestation
ORACLE_PRIVATE_KEY=...         # приватный ключ

# Сервисы
PROVER_URL=http://127.0.0.1:7048
NOTARY_URL=http://127.0.0.1:7047
NOTARY_PORT=7047
PROVER_PORT=7048
PORT=4001
```

## API эндпоинты

| Метод | Эндпоинт | Описание |
|-------|----------|----------|
| POST | `/api/prove` | Запросить TLS-аттестацию. Body: `{"url": "https://..."}` |
| POST | `/api/submit` | Записать аттестацию в NEAR контракт |
| POST | `/api/prove-and-submit` | Prove + Submit в одном запросе |
| GET | `/api/attestations` | Список аттестаций. Query: `?from=0&limit=20` |
| GET | `/api/attestations/:id` | Детали аттестации по ID |
| GET | `/api/attestations/source/:domain` | Аттестации по домену |
| GET | `/api/notaries` | Список доверенных нотариусов |
| GET | `/api/stats` | Статистика (кол-во аттестаций, нотариусов) |
| GET | `/api/templates` | Пресеты URL (CoinGecko, httpbin и т.д.) |
| GET | `/api/health` | Статус сервисов (backend, prover, contract) |
| GET | `/api/near-config` | Конфиг NEAR для фронтенда |

## Смарт-контракт

**Контракт:** `tls-oracle.nearcast-oracle.testnet`
**Owner:** `nearcast-oracle.testnet`

### Методы записи

| Метод | Кто вызывает | Описание |
|-------|-------------|----------|
| `new(owner)` | — | Инициализация контракта |
| `add_notary(pubkey, name, url)` | owner | Добавить доверенного нотариуса (pubkey — base64, 32 байта) |
| `remove_notary(pubkey)` | owner | Удалить нотариуса |
| `set_owner(new_owner)` | owner | Передать владение |
| `submit_attestation(...)` | любой | Отправить аттестацию (контракт проверяет Ed25519 подпись) |

### Параметры `submit_attestation`

| Параметр | Тип | Описание |
|----------|-----|----------|
| `source_url` | String | Полный URL запроса (макс 2KB) |
| `server_name` | String | Домен (api.coingecko.com) |
| `timestamp` | u64 | UNIX timestamp TLS-сессии |
| `response_data` | String | Данные ответа, JSON (макс 4KB) |
| `notary_pubkey` | Base64 | Ed25519 публичный ключ нотариуса (32 байта) |
| `signature` | Base64 | Ed25519 подпись (64 байта) |

**Верификация:** контракт вычисляет `sha256(source_url|server_name|timestamp|response_data)` и проверяет подпись через `env::ed25519_verify`.

### View методы

| Метод | Возвращает |
|-------|-----------|
| `get_attestation(id)` | `Option<Attestation>` |
| `get_attestations(from_index?, limit?)` | `Vec<Attestation>` (новые первыми) |
| `get_attestations_by_source(server_name, limit?)` | `Vec<Attestation>` по домену |
| `get_notaries()` | `Vec<NotaryInfo>` |
| `get_stats()` | `{attestationCount, notaryCount, owner}` |
| `get_owner()` | `AccountId` |

## Поток данных

```
1. Пользователь вводит URL в UI (или выбирает пресет)
2. Frontend → POST /api/prove {url}
3. Backend → Prover Service → Notary Server
4. Notary делает HTTP-запрос к целевому серверу
5. Notary подписывает ответ: Ed25519(sha256(url|domain|ts|data))
6. Аттестация возвращается пользователю
7. Пользователь нажимает "Записать в NEAR"
8. Backend → NEAR contract: submit_attestation(...)
9. Контракт: ed25519_verify → сохраняет аттестацию on-chain
```

## Roadmap

- [ ] Полный MPC-TLS протокол (tlsn-prover) вместо прямого HTTP в Notary
- [ ] Множественные нотариусы (N-of-M подписи)
- [ ] TEE attestation для Notary (Intel TDX/SGX)
- [ ] ZK-proof верификация on-chain (через alt_bn128)
- [ ] Интеграция с NearCast как oracle-провайдер
