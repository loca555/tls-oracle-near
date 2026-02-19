//! Prover Service — HTTP API для MPC-TLS аттестаций с ZK proof.
//!
//! Embedded Notary (Verifier) через tokio::io::duplex — не требует отдельного сервера.
//! MPC-TLS протокол: Prover ↔ Verifier (in-process) → целевой сервер.
//! После MPC-TLS генерируется Groth16 ZK proof через snarkjs (Node.js subprocess).
//!
//! Порт по умолчанию: 7048

mod mpc_session;
mod url_validator;
mod zk_prover;

use axum::{
    extract::State,
    http::{HeaderValue, Method, StatusCode},
    routing::{get, post},
    Json, Router,
};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::{error, info};

// ── Типы ─────────────────────────────────────────────────────

struct AppState {
    /// secp256k1 signing key (Notary)
    signing_key: Arc<SigningKey>,
    /// Base64 compressed secp256k1 pubkey
    notary_pubkey_b64: String,
}

/// Запрос от backend
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProveRequest {
    /// URL для доказательства
    url: String,
    /// HTTP метод (по умолчанию GET)
    method: Option<String>,
    /// Дополнительные заголовки
    headers: Option<HashMap<String, String>>,
}

/// Ответ с MPC-TLS аттестацией + ZK proof
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProveResponse {
    source_url: String,
    server_name: String,
    timestamp: u64,
    response_data: String,
    /// Groth16 proof: A point [x, y]
    proof_a: [String; 2],
    /// Groth16 proof: B point [[x1, x2], [y1, y2]]
    proof_b: [[String; 2]; 2],
    /// Groth16 proof: C point [x, y]
    proof_c: [String; 2],
    /// Public signals: [dataCommitment, serverNameHash, timestamp, notaryPubkeyHash]
    public_signals: [String; 4],
}

/// Информация о нотариусе
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NotaryInfoResp {
    /// secp256k1 compressed pubkey (base64)
    pubkey_base64: String,
    /// Тип ключа
    key_type: String,
}

// ── Обработчики ──────────────────────────────────────────────

async fn health() -> &'static str {
    "ok"
}

/// GET /notary-info — получить публичный ключ embedded Notary
async fn notary_info(State(state): State<Arc<AppState>>) -> Json<NotaryInfoResp> {
    Json(NotaryInfoResp {
        pubkey_base64: state.notary_pubkey_b64.clone(),
        key_type: "secp256k1".to_string(),
    })
}

/// POST /prove — выполнить MPC-TLS сессию + ZK proof
///
/// 1. Валидация URL (SSRF-защита)
/// 2. MPC-TLS сессия (Prover + embedded Verifier/Notary)
/// 3. Генерация Groth16 ZK proof (snarkjs)
/// 4. Возврат attestation data + proof + public signals
async fn prove(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProveRequest>,
) -> Result<Json<ProveResponse>, (StatusCode, String)> {
    info!("Запрос MPC-TLS аттестации: {}", req.url);

    // 1. SSRF-защита
    url_validator::validate_url(&req.url).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("URL невалиден: {e}"))
    })?;

    let method = req.method.unwrap_or_else(|| "GET".to_string());

    // 2. MPC-TLS сессия
    let session_result = mpc_session::run(
        state.signing_key.clone(),
        &req.url,
        &method,
        req.headers,
    )
    .await
    .map_err(|e| {
        error!("MPC-TLS ошибка: {e:#}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("MPC-TLS ошибка: {e}"),
        )
    })?;

    info!(
        "MPC-TLS завершена: {} ({} байт), генерация ZK proof...",
        session_result.server_name,
        session_result.response_data.len()
    );

    // 3. Генерация ZK proof
    let zk_result = zk_prover::generate_proof(&session_result)
        .await
        .map_err(|e| {
            error!("ZK proof ошибка: {e:#}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("ZK proof ошибка: {e}"),
            )
        })?;

    info!(
        "ZK proof сгенерирован: dataCommitment={}...",
        &zk_result.public_signals[0][..20.min(zk_result.public_signals[0].len())]
    );

    Ok(Json(ProveResponse {
        source_url: session_result.source_url,
        server_name: session_result.server_name,
        timestamp: session_result.timestamp,
        response_data: session_result.response_data,
        proof_a: zk_result.proof_a,
        proof_b: zk_result.proof_b,
        proof_c: zk_result.proof_c,
        public_signals: zk_result.public_signals,
    }))
}

// ── main ─────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let _ = dotenvy::dotenv();

    let port = std::env::var("PROVER_PORT")
        .unwrap_or_else(|_| "7048".to_string())
        .parse::<u16>()
        .expect("PROVER_PORT должен быть числом");

    let bind_addr =
        std::env::var("PROVER_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());

    // Загружаем или генерируем secp256k1 ключ для Notary
    let signing_key = load_or_generate_signing_key();
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.to_sec1_bytes();
    let notary_pubkey_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pubkey_bytes);

    info!("Notary pubkey (secp256k1): {notary_pubkey_b64}");

    let state = Arc::new(AppState {
        signing_key: Arc::new(signing_key),
        notary_pubkey_b64,
    });

    // CORS: только разрешённый origin
    let allowed_origin = std::env::var("ALLOWED_ORIGIN")
        .unwrap_or_else(|_| "http://127.0.0.1:4001".to_string());

    let cors = CorsLayer::new()
        .allow_origin(
            allowed_origin
                .parse::<HeaderValue>()
                .expect("ALLOWED_ORIGIN должен быть валидным"),
        )
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE]);

    let app = Router::new()
        .route("/health", get(health))
        .route("/notary-info", get(notary_info))
        .route("/prove", post(prove))
        .layer(cors)
        .with_state(state);

    let addr = format!("{bind_addr}:{port}");
    info!("Prover Service (MPC-TLS + ZK) запущен на {addr}");

    let listener = TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Загружает secp256k1 ключ из файла или генерирует новый
fn load_or_generate_signing_key() -> SigningKey {
    let key_path = std::env::var("NOTARY_KEY_PATH")
        .unwrap_or_else(|_| "notary_key.bin".to_string());

    if let Ok(bytes) = std::fs::read(&key_path) {
        if bytes.len() == 32 {
            if let Ok(key) = SigningKey::from_bytes(bytes.as_slice().into()) {
                info!("Notary ключ загружен из {key_path}");
                return key;
            }
        }
        tracing::warn!("Файл {key_path} повреждён, генерирую новый ключ");
    }

    // Генерируем новый ключ
    let key = SigningKey::random(&mut rand::thread_rng());
    if let Err(e) = std::fs::write(&key_path, key.to_bytes().as_slice()) {
        tracing::warn!("Не удалось сохранить ключ в {key_path}: {e}");
    } else {
        info!("Новый Notary ключ сгенерирован и сохранён в {key_path}");
    }
    key
}
