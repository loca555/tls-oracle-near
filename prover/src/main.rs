//! Prover Service — HTTP API для запроса TLS-аттестаций.
//!
//! MVP: проксирует запросы к Notary Server.
//! Продакшн: будет выполнять MPC-TLS протокол с Notary (tlsn-prover).
//!
//! Порт по умолчанию: 7048

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::{error, info};

// ── Типы ─────────────────────────────────────────────────────

struct AppState {
    notary_url: String,
    http_client: reqwest::Client,
}

/// Запрос от backend
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProveRequest {
    /// URL для доказательства
    url: String,
    /// HTTP метод
    method: Option<String>,
    /// Заголовки
    headers: Option<std::collections::HashMap<String, String>>,
}

/// Ответ нотариуса (проксируемый)
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProveResponse {
    source_url: String,
    server_name: String,
    timestamp: u64,
    response_data: String,
    data_hash: String,
    notary_pubkey: String,
    signature: String,
}

/// Информация о нотариусе
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotaryInfo {
    pubkey_hex: String,
    pubkey_base64: String,
}

// ── Обработчики ──────────────────────────────────────────────

async fn health() -> &'static str {
    "ok"
}

/// GET /notary-info — получить публичный ключ нотариуса
async fn notary_info(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NotaryInfo>, (StatusCode, String)> {
    let resp = state
        .http_client
        .get(format!("{}/info", state.notary_url))
        .send()
        .await
        .map_err(|e| {
            error!("Notary недоступен: {e}");
            (StatusCode::BAD_GATEWAY, format!("Notary недоступен: {e}"))
        })?;

    let info: NotaryInfo = resp.json().await.map_err(|e| {
        (StatusCode::BAD_GATEWAY, format!("Ошибка парсинга: {e}"))
    })?;

    Ok(Json(info))
}

/// POST /prove — запросить аттестацию через Notary
///
/// MVP: просто перенаправляет запрос к Notary.
/// Продакшн: инициирует MPC-TLS сессию, Prover держит свою долю ключа.
async fn prove(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProveRequest>,
) -> Result<Json<ProveResponse>, (StatusCode, String)> {
    info!("Запрос аттестации: {}", req.url);

    // Формируем запрос к Notary
    let notary_request = serde_json::json!({
        "url": req.url,
        "method": req.method.unwrap_or_else(|| "GET".to_string()),
        "headers": req.headers,
    });

    let resp = state
        .http_client
        .post(format!("{}/attest", state.notary_url))
        .json(&notary_request)
        .send()
        .await
        .map_err(|e| {
            error!("Ошибка запроса к Notary: {e}");
            (StatusCode::BAD_GATEWAY, format!("Notary ошибка: {e}"))
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        error!("Notary вернул {status}: {body}");
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("Notary ошибка ({status}): {body}"),
        ));
    }

    let attestation: ProveResponse = resp.json().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("Ошибка парсинга ответа Notary: {e}"),
        )
    })?;

    info!(
        "Аттестация получена: {} ({} байт данных)",
        attestation.server_name,
        attestation.response_data.len()
    );

    Ok(Json(attestation))
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

    let notary_url = std::env::var("NOTARY_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:7047".to_string());

    info!("Notary URL: {notary_url}");

    let state = Arc::new(AppState {
        notary_url,
        http_client: reqwest::Client::new(),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/notary-info", get(notary_info))
        .route("/prove", post(prove))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    info!("Prover Service запущен на {addr}");

    let listener = TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
