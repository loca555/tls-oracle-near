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

/// Запрос ESPN аттестации
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EspnProveRequest {
    /// ESPN Event ID
    espn_event_id: String,
    /// Вид спорта (soccer, basketball, etc.)
    sport: String,
    /// Лига (eng.1, nba, etc.)
    league: String,
}

/// Компактные данные ESPN (записываются в response_data)
#[derive(Serialize, Deserialize)]
struct EspnCompactData {
    /// Home team name
    ht: String,
    /// Away team name
    at: String,
    /// Home score
    hs: i32,
    /// Away score (поле "as" — зарезервированное слово, используем rename)
    #[serde(rename = "as")]
    away_score: i32,
    /// Event status: "final", "in", "pre"
    st: String,
    /// ESPN Event ID
    eid: String,
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

/// POST /prove-espn — MPC-TLS аттестация ESPN данных с извлечением scores
///
/// 1. Формирует ESPN URL из параметров
/// 2. MPC-TLS сессия к ESPN API
/// 3. Парсит полный JSON → компактный формат {ht, at, hs, as, st, eid}
/// 4. Генерирует ZK proof для компактных данных
async fn prove_espn(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EspnProveRequest>,
) -> Result<Json<ProveResponse>, (StatusCode, String)> {
    let url = format!(
        "https://site.api.espn.com/apis/site/v2/sports/{}/{}/summary?event={}",
        req.sport, req.league, req.espn_event_id
    );

    info!("Запрос ESPN MPC-TLS аттестации: {} (event {})", url, req.espn_event_id);

    // 1. SSRF-защита
    url_validator::validate_url(&url).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("URL невалиден: {e}"))
    })?;

    // 2. MPC-TLS сессия
    let session_result = mpc_session::run(
        state.signing_key.clone(),
        &url,
        "GET",
        None,
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
        "MPC-TLS завершена: {} ({} байт), извлечение ESPN данных...",
        session_result.server_name,
        session_result.response_data.len()
    );

    // 3. Парсим ESPN JSON → компактный формат
    let compact = extract_espn_scores(&session_result.response_data, &req.espn_event_id)
        .map_err(|e| {
            error!("ESPN парсинг ошибка: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("ESPN парсинг ошибка: {e}"),
            )
        })?;

    let compact_json = serde_json::to_string(&compact).unwrap();
    info!(
        "ESPN данные: {} vs {} — {}:{} (status: {})",
        compact.ht, compact.at, compact.hs, compact.away_score, compact.st
    );

    // 4. Подменяем response_data на компактный JSON для ZK proof
    let mut session_for_zk = session_result;
    session_for_zk.response_data = compact_json;

    // 5. Генерация ZK proof
    let zk_result = zk_prover::generate_proof(&session_for_zk)
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
        source_url: session_for_zk.source_url,
        server_name: session_for_zk.server_name,
        timestamp: session_for_zk.timestamp,
        response_data: session_for_zk.response_data,
        proof_a: zk_result.proof_a,
        proof_b: zk_result.proof_b,
        proof_c: zk_result.proof_c,
        public_signals: zk_result.public_signals,
    }))
}

/// Извлекает компактные данные ESPN из полного JSON ответа summary endpoint
///
/// ESPN summary format:
/// { header: { competitions: [{ competitors: [
///   { team: { displayName }, homeAway: "home"|"away", score: "2" }, ...
/// ], status: { type: { name: "STATUS_FINAL" } } }] } }
fn extract_espn_scores(
    raw_json: &str,
    espn_event_id: &str,
) -> Result<EspnCompactData, String> {
    let json: serde_json::Value =
        serde_json::from_str(raw_json).map_err(|e| format!("Невалидный JSON: {e}"))?;

    // Извлекаем competition из header
    let competition = json
        .pointer("/header/competitions/0")
        .or_else(|| json.pointer("/competitions/0"))
        .ok_or("ESPN: не найден competitions[0]")?;

    let competitors = competition
        .get("competitors")
        .and_then(|c| c.as_array())
        .ok_or("ESPN: не найден competitors")?;

    let mut home_team = String::new();
    let mut away_team = String::new();
    let mut home_score: i32 = -1;
    let mut away_score: i32 = -1;

    for comp in competitors {
        let team_name = comp
            .pointer("/team/displayName")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");

        let score_str = comp
            .get("score")
            .and_then(|v| v.as_str())
            .unwrap_or("0");

        let score = score_str.parse::<i32>().unwrap_or(0);

        let home_away = comp
            .get("homeAway")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        match home_away {
            "home" => {
                home_team = team_name.to_string();
                home_score = score;
            }
            "away" => {
                away_team = team_name.to_string();
                away_score = score;
            }
            _ => {}
        }
    }

    if home_team.is_empty() || away_team.is_empty() {
        return Err("ESPN: не удалось определить home/away команды".to_string());
    }

    // Статус матча
    let status_name = competition
        .pointer("/status/type/name")
        .and_then(|v| v.as_str())
        .unwrap_or("STATUS_UNKNOWN");

    let st = match status_name {
        "STATUS_FINAL" | "STATUS_FULL_TIME" => "final",
        "STATUS_IN_PROGRESS" | "STATUS_FIRST_HALF" | "STATUS_SECOND_HALF"
        | "STATUS_HALFTIME" | "STATUS_OVERTIME" => "in",
        "STATUS_SCHEDULED" | "STATUS_PREGAME" => "pre",
        _ => "unknown",
    }
    .to_string();

    Ok(EspnCompactData {
        ht: home_team,
        at: away_team,
        hs: home_score,
        away_score,
        st,
        eid: espn_event_id.to_string(),
    })
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
        std::env::var("PROVER_BIND").unwrap_or_else(|_| "0.0.0.0".to_string());

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
        .route("/prove-espn", post(prove_espn))
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
