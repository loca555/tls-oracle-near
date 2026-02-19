//! TLS Notary Server — подписывает аттестации Ed25519.
//!
//! MVP-версия: Notary сам делает HTTP-запрос к целевому серверу,
//! получает ответ и подписывает его. В будущем — полный MPC-TLS протокол.
//!
//! Порт по умолчанию: 7047

mod url_validator;

use axum::{
    extract::State,
    http::{HeaderValue, Method, StatusCode},
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

// ── Типы ─────────────────────────────────────────────────────

/// Состояние сервера
struct AppState {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

/// Запрос на создание аттестации
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttestRequest {
    /// URL для запроса
    url: String,
    /// HTTP метод (GET по умолчанию)
    method: Option<String>,
    /// Дополнительные заголовки
    headers: Option<std::collections::HashMap<String, String>>,
}

/// Результат аттестации
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttestResponse {
    source_url: String,
    server_name: String,
    timestamp: u64,
    response_data: String,
    data_hash: String,
    notary_pubkey: String,
    signature: String,
}

/// Информация о нотариусе
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NotaryInfoResponse {
    pubkey_hex: String,
    pubkey_base64: String,
}

// ── Обработчики ──────────────────────────────────────────────

/// GET /health — проверка доступности
async fn health() -> &'static str {
    "ok"
}

/// GET /info — публичный ключ нотариуса
async fn info(State(state): State<Arc<AppState>>) -> Json<NotaryInfoResponse> {
    let pubkey_bytes = state.verifying_key.to_bytes();
    Json(NotaryInfoResponse {
        pubkey_hex: hex::encode(pubkey_bytes),
        pubkey_base64: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            pubkey_bytes,
        ),
    })
}

/// POST /attest — выполнить запрос и подписать результат
///
/// SSRF-защита: только HTTPS, блок приватных IP, фильтрация заголовков.
async fn attest(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AttestRequest>,
) -> Result<Json<AttestResponse>, (StatusCode, String)> {
    // Валидация URL (SSRF-защита)
    let parsed_url = url_validator::validate_url(&req.url).map_err(|e| {
        warn!("URL отклонён: {} — {}", req.url, e);
        (StatusCode::BAD_REQUEST, e)
    })?;

    let server_name = parsed_url
        .host_str()
        .ok_or((StatusCode::BAD_REQUEST, "URL без хоста".to_string()))?
        .to_string();

    // Валидация HTTP-метода
    let method = req.method.as_deref().unwrap_or("GET");
    let client = reqwest::Client::new();

    let mut request_builder = match method.to_uppercase().as_str() {
        "GET" => client.get(&req.url),
        "POST" => client.post(&req.url),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Неподдерживаемый метод: {method}"),
            ))
        }
    };

    // Фильтрация заголовков (убираем опасные)
    if let Some(headers) = &req.headers {
        let safe_headers = url_validator::filter_headers(headers);
        for (k, v) in &safe_headers {
            request_builder = request_builder.header(k, v);
        }
    }

    let response = request_builder.send().await.map_err(|e| {
        error!("HTTP запрос к {} не удался: {}", req.url, e);
        (
            StatusCode::BAD_GATEWAY,
            format!("Ошибка запроса к {}: {e}", server_name),
        )
    })?;

    let response_data = response.text().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("Ошибка чтения ответа: {e}"),
        )
    })?;

    // Ограничиваем размер ответа (4KB как в контракте)
    if response_data.len() > 4096 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Ответ слишком большой: {} байт (макс 4096)",
                response_data.len()
            ),
        ));
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Формируем сообщение для подписи (тот же формат что в контракте)
    let message = format!(
        "{}|{}|{}|{}",
        req.url, server_name, timestamp, response_data
    );
    let message_hash = Sha256::digest(message.as_bytes());

    // Подписываем Ed25519
    let signature = state.signing_key.sign(&message_hash);

    let pubkey_bytes = state.verifying_key.to_bytes();

    info!(
        "Аттестация создана: {} ({} байт)",
        server_name,
        response_data.len()
    );

    Ok(Json(AttestResponse {
        source_url: req.url,
        server_name,
        timestamp,
        response_data,
        data_hash: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            message_hash.as_slice(),
        ),
        notary_pubkey: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            pubkey_bytes,
        ),
        signature: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signature.to_bytes(),
        ),
    }))
}

// ── main ─────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Логирование
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let _ = dotenvy::dotenv();

    let port = std::env::var("NOTARY_PORT")
        .unwrap_or_else(|_| "7047".to_string())
        .parse::<u16>()
        .expect("NOTARY_PORT должен быть числом");

    let bind_addr = std::env::var("NOTARY_BIND")
        .unwrap_or_else(|_| "0.0.0.0".to_string());

    // Загружаем или генерируем Ed25519 ключ
    let signing_key = load_or_generate_key();
    let verifying_key = signing_key.verifying_key();

    info!(
        "Notary pubkey: {}",
        hex::encode(verifying_key.to_bytes())
    );
    info!(
        "Notary pubkey (base64): {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            verifying_key.to_bytes()
        )
    );

    let state = Arc::new(AppState {
        signing_key,
        verifying_key,
    });

    // CORS: только разрешённый origin (по умолчанию — только Prover)
    let allowed_origin = std::env::var("ALLOWED_ORIGIN")
        .unwrap_or_else(|_| "http://127.0.0.1:7048".to_string());

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
        .route("/info", get(info))
        .route("/attest", post(attest))
        .layer(cors)
        .with_state(state);

    let addr = format!("{bind_addr}:{port}");
    info!("TLS Notary Server запущен на {addr}");

    let listener = TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Загружает ключ из файла или генерирует новый
fn load_or_generate_key() -> SigningKey {
    let key_path = std::env::var("NOTARY_KEY_PATH")
        .unwrap_or_else(|_| "notary_key.bin".to_string());

    if let Ok(bytes) = std::fs::read(&key_path) {
        if bytes.len() == 32 {
            info!("Ключ загружен из {key_path}");
            return SigningKey::from_bytes(&bytes.try_into().unwrap());
        }
    }

    info!("Генерация нового Ed25519 ключа...");
    let key = SigningKey::generate(&mut OsRng);
    if let Err(e) = std::fs::write(&key_path, key.to_bytes()) {
        error!("Не удалось сохранить ключ в {key_path}: {e}");
    } else {
        info!("Ключ сохранён в {key_path}");
    }
    key
}
