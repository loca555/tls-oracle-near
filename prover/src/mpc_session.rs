//! MPC-TLS сессия: Prover + встроенный Verifier (Notary)
//!
//! Prover и Verifier общаются через tokio::io::duplex (in-process).
//! Prover подключается к целевому серверу через MPC-TLS,
//! Verifier (Notary) участвует в MPC-протоколе и подписывает attestation.

use anyhow::{Context, Result};
use futures::AsyncWriteExt;
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use k256::ecdsa::SigningKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{error, info, warn};

use tlsn::attestation::request::{Request as AttestationRequest, RequestConfig};
use tlsn::attestation::signing::Secp256k1Signer;
use tlsn::attestation::{Attestation, AttestationConfig, CryptoProvider};
use tlsn::config::prover::ProverConfig;
use tlsn::config::tls::TlsClientConfig;
use tlsn::config::tls_commit::mpc::MpcTlsConfig;
use tlsn::config::tls_commit::TlsCommitConfig;
use tlsn::config::verifier::VerifierConfig;
use tlsn::webpki::RootCertStore;
use tlsn::connection::{ConnectionInfo, HandshakeData, ServerName, TranscriptLength};
use tlsn::prover::ProverOutput;
use tlsn::transcript::ContentType;
use tlsn::verifier::VerifierOutput;
use tlsn::Session;

/// Результат MPC-TLS сессии
pub struct SessionResult {
    /// URL источника
    pub source_url: String,
    /// DNS-имя сервера
    pub server_name: String,
    /// UNIX timestamp (секунды)
    pub timestamp: u64,
    /// Тело HTTP-ответа (расшифрованное)
    pub response_data: String,
    /// Сериализованная attestation (bincode -> base64)
    pub attestation_b64: String,
    /// Публичный ключ нотариуса (secp256k1 compressed, base64)
    pub notary_pubkey_b64: String,
}

/// Запускает полную MPC-TLS сессию
///
/// 1. Создаёт in-process duplex канал для Prover <-> Verifier
/// 2. Запускает Verifier (Notary) в фоновом task
/// 3. Prover подключается к целевому серверу через MPC-TLS
/// 4. Выполняет HTTP-запрос
/// 5. Генерирует proof и получает attestation через oneshot каналы
pub async fn run(
    signing_key: Arc<SigningKey>,
    url: &str,
    method: &str,
    _headers: Option<HashMap<String, String>>,
) -> Result<SessionResult> {
    // Парсим URL
    let parsed_url = url::Url::parse(url).context("Неверный URL")?;
    let host = parsed_url
        .host_str()
        .context("URL без хоста")?
        .to_string();
    let port = parsed_url.port().unwrap_or(443);
    let path = if parsed_url.query().is_some() {
        format!("{}?{}", parsed_url.path(), parsed_url.query().unwrap())
    } else {
        parsed_url.path().to_string()
    };

    info!("MPC-TLS сессия: {} ({}:{}{})", url, host, port, path);

    // 1. Создаём duplex канал (Prover <-> Verifier)
    let (prover_io, verifier_io) = tokio::io::duplex(1 << 16); // 64KB buffer

    // Каналы для attestation (вне MPC-сессии)
    let (req_tx, req_rx) = oneshot::channel::<AttestationRequest>();
    let (att_tx, att_rx) = oneshot::channel::<Attestation>();

    // 2. Запускаем Verifier (Notary) в фоне
    let signing_key_clone = signing_key.clone();
    let verifier_task = tokio::spawn(async move {
        if let Err(e) = run_verifier(verifier_io, signing_key_clone, req_rx, att_tx).await {
            error!("Verifier ошибка: {e:#}");
        }
    });

    // 3. Создаём MPC-TLS Session на стороне Prover
    let session = Session::new(prover_io.compat());
    let (driver, mut handle) = session.split();

    // Запускаем Session driver в фоне
    let driver_task = tokio::spawn(driver);

    // 4. Конфигурируем Prover
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)
        .context("Ошибка создания Prover")?
        .commit(
            TlsCommitConfig::builder()
                .protocol(
                    MpcTlsConfig::builder()
                        .max_sent_data(4096)
                        .max_recv_data(65536)
                        .build()?,
                )
                .build()?,
        )
        .await
        .context("Ошибка commit Prover")?;

    // 5. Подключаемся к целевому серверу
    let target_socket = tokio::net::TcpStream::connect(format!("{host}:{port}"))
        .await
        .context(format!("Не удалось подключиться к {host}:{port}"))?;

    let tls_config = TlsClientConfig::builder()
        .server_name(ServerName::Dns(
            host.clone()
                .try_into()
                .context("Неверное DNS-имя сервера")?,
        ))
        .build()?;

    // connect() — async в новом API
    let (tls_connection, prover_fut) = prover
        .connect(tls_config, target_socket.compat())
        .await
        .context("Ошибка MPC-TLS connect")?;

    let tls_connection = TokioIo::new(tls_connection.compat());

    // Запускаем MPC-TLS протокол в фоне
    let prover_task = tokio::spawn(prover_fut);

    // 6. HTTP-запрос через MPC-TLS соединение
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    let request = Request::builder()
        .method(method)
        .uri(&path)
        .header("Host", &host)
        .header("Accept", "application/json")
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())?;

    let response = request_sender
        .send_request(request)
        .await
        .context("HTTP-запрос через MPC-TLS не удался")?;

    let status = response.status();
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .context("Чтение тела ответа")?
        .to_bytes();
    let response_data = String::from_utf8_lossy(&body_bytes).to_string();

    if status != StatusCode::OK {
        warn!(
            "HTTP ответ {status}: {}",
            &response_data[..200.min(response_data.len())]
        );
    }

    info!(
        "HTTP ответ получен: {} ({} байт)",
        status,
        response_data.len()
    );

    // 7. Завершаем MPC-TLS и генерируем proof
    let mut prover = prover_task
        .await?
        .context("Prover MPC-TLS ошибка")?;

    // Раскрываем весь транскрипт (для MVP — full disclosure)
    let transcript = prover.transcript();
    let mut prove_config = tlsn::config::prove::ProveConfig::builder(transcript);
    prove_config.server_identity();

    // Раскрываем все отправленные и полученные данные
    let sent_len = transcript.sent().len();
    let recv_len = transcript.received().len();
    if sent_len > 0 {
        prove_config.reveal_sent(&(0..sent_len))?;
    }
    if recv_len > 0 {
        prove_config.reveal_recv(&(0..recv_len))?;
    }

    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&prove_config.build()?).await?;

    // Получаем данные для attestation request
    let transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    // 8. Строим AttestationRequest и отправляем нотариусу через канал
    let request_config = RequestConfig::builder().build()?;
    let mut att_builder = AttestationRequest::builder(&request_config);
    att_builder
        .server_name(ServerName::Dns(
            host.clone()
                .try_into()
                .context("Неверное DNS-имя для attestation")?,
        ))
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .expect("server cert chain is present")
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .expect("server signature is present")
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);

    let (att_request, _secrets) = att_builder.build(&CryptoProvider::default())?;

    // Отправляем attestation request нотариусу
    req_tx
        .send(att_request)
        .map_err(|_| anyhow::anyhow!("Verifier не принимает attestation request"))?;

    // Получаем подписанную attestation
    let attestation = att_rx
        .await
        .context("Verifier не вернул attestation")?;

    // Закрываем сессию
    handle.close();
    let _ = driver_task.await;
    let _ = verifier_task.await;

    // Сериализуем attestation
    let attestation_bytes = bincode::serialize(&attestation)?;
    let attestation_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &attestation_bytes);

    // Публичный ключ нотариуса
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.to_sec1_bytes();
    let notary_pubkey_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pubkey_bytes);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Ok(SessionResult {
        source_url: url.to_string(),
        server_name: host,
        timestamp,
        response_data,
        attestation_b64,
        notary_pubkey_b64,
    })
}

/// Запускает Verifier (Notary) сторону MPC-TLS
async fn run_verifier<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    io: T,
    signing_key: Arc<SigningKey>,
    req_rx: oneshot::Receiver<AttestationRequest>,
    att_tx: oneshot::Sender<Attestation>,
) -> Result<()> {
    info!("Verifier: запуск");

    let session = Session::new(io.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    // Конфигурация Verifier с Mozilla root certificates
    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore::mozilla())
        .build()?;

    let verifier = handle
        .new_verifier(verifier_config)?
        .commit()
        .await
        .context("Verifier commit")?;

    // Принимаем конфигурацию Prover и запускаем MPC-TLS
    let verifier = verifier.accept().await?.run().await?;

    // Верифицируем proof от Prover
    let (
        VerifierOutput {
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.verify().await?.accept().await?;

    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;

    info!("Verifier: proof принят");

    // Вычисляем длины транскрипта (только ApplicationData)
    let sent_len = tls_transcript
        .sent()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    let recv_len = tls_transcript
        .recv()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    // Получаем attestation request от Prover через канал
    let request = req_rx
        .await
        .context("Prover не отправил attestation request")?;

    // Создаём CryptoProvider с нашим signing key
    let signer = Box::new(Secp256k1Signer::new(&signing_key.to_bytes())?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    // Строим attestation
    let mut att_config_builder = AttestationConfig::builder();
    att_config_builder
        .supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    let att_config = att_config_builder.build()?;

    let mut builder = Attestation::builder(&att_config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: (*tls_transcript.version()),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(tls_transcript.server_ephemeral_key().clone())
        .transcript_commitments(transcript_commitments);

    let attestation = builder.build(&provider)?;

    // Отправляем attestation Prover-у через канал
    att_tx
        .send(attestation)
        .map_err(|_| anyhow::anyhow!("Prover не принимает attestation"))?;

    info!("Verifier: attestation отправлена");

    handle.close();
    let _ = driver_task.await;

    Ok(())
}
