# TLS Oracle — NEAR Blockchain

Универсальный оракул на базе TLS Notary для NEAR. Криптографически доказывает данные с любого веб-сайта и записывает аттестацию on-chain с верификацией Ed25519 подписи.

## Архитектура

```
[Пользователь] → [Frontend] → [Backend (Express)]
                                      ↓
                              [Prover Service (Rust)]
                                      ↕ MPC-TLS
                              [Notary Server (Rust)]
                                      ↓
                              [Ed25519 Attestation]
                                      ↓
                              [NEAR Smart Contract]
                              env::ed25519_verify → store
```

**Trust model:** Notary подписывает данные, полученные из реального TLS-соединения. Prover не может подделать данные — Notary верифицирует перед подписью. Контракт проверяет Ed25519 подпись через нативную host-функцию NEAR.

## Компоненты

| Компонент | Стек | Порт |
|-----------|------|------|
| `contract/` | Rust, near-sdk 5.6 | — |
| `notary/` | Rust, Axum, ed25519-dalek | 7047 |
| `prover/` | Rust, Axum | 7048 |
| `backend/` | Node.js, Express | 4001 |
| `frontend/` | React 18, Vite 5 | 3001 |

## Деплой

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
NEAR_NETWORK=testnet
TLS_ORACLE_CONTRACT=tls-oracle.nearcast-oracle.testnet
ORACLE_ACCOUNT_ID=...
ORACLE_PRIVATE_KEY=...
PROVER_URL=http://127.0.0.1:7048
NOTARY_URL=http://127.0.0.1:7047
```

## API

| Метод | Эндпоинт | Описание |
|-------|----------|----------|
| POST | `/api/prove` | Запросить TLS-аттестацию `{url}` |
| POST | `/api/submit` | Записать аттестацию в NEAR контракт |
| POST | `/api/prove-and-submit` | Prove + Submit в одном запросе |
| GET | `/api/attestations` | Список аттестаций |
| GET | `/api/attestations/:id` | Детали аттестации |
| GET | `/api/notaries` | Доверенные нотариусы |
| GET | `/api/stats` | Статистика |
| GET | `/api/templates` | Пресеты URL |
| GET | `/api/health` | Статус сервисов |

## Смарт-контракт

**Методы:**
- `add_notary(pubkey, name, url)` — добавить нотариуса (owner)
- `remove_notary(pubkey)` — удалить нотариуса (owner)
- `submit_attestation(source_url, server_name, timestamp, response_data, notary_pubkey, signature)` — отправить аттестацию (проверяет Ed25519)
- `get_attestation(id)` / `get_attestations(from_index, limit)` — чтение
- `get_notaries()` / `get_stats()` — информация
