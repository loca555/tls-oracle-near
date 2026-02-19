//! Генерация Groth16 ZK proof через snarkjs (Node.js subprocess)
//!
//! Подготавливает input.json из SessionResult,
//! вызывает `node zk/generate_proof.js input.json`,
//! парсит stdout → ZkProofResult.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::info;

use crate::mpc_session::SessionResult;

/// Результат ZK proof generation
#[derive(Debug, Serialize, Deserialize)]
pub struct ZkProofResult {
    /// Groth16 proof point A [x, y]
    pub proof_a: [String; 2],
    /// Groth16 proof point B [[x1, x2], [y1, y2]]
    pub proof_b: [[String; 2]; 2],
    /// Groth16 proof point C [x, y]
    pub proof_c: [String; 2],
    /// Public signals: [dataCommitment, serverNameHash, timestamp, notaryPubkeyHash]
    pub public_signals: [String; 4],
}

/// Промежуточная структура для десериализации snarkjs output
#[derive(Deserialize)]
struct SnarkjsOutput {
    proof: SnarkjsProof,
    #[serde(rename = "publicSignals")]
    public_signals: Vec<String>,
}

#[derive(Deserialize)]
struct SnarkjsProof {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
}

/// Генерирует Groth16 proof для MPC-TLS attestation
///
/// 1. Формирует attestation data для input_generator
/// 2. Вызывает Node.js: zk/generate_proof.js
/// 3. Парсит proof + public signals
pub async fn generate_proof(session: &SessionResult) -> Result<ZkProofResult> {
    // Определяем директорию zk/ относительно исполняемого файла
    let zk_dir = get_zk_dir()?;

    // Формируем данные для input_generator
    let attestation_data = serde_json::json!({
        "responseData": session.response_data,
        "serverName": session.server_name,
        "timestamp": session.timestamp,
        "notaryPubkey": session.notary_pubkey_b64,
    });

    // Записываем во временный файл
    let temp_dir = std::env::temp_dir();
    let input_path = temp_dir.join(format!("zk_input_{}.json", std::process::id()));
    std::fs::write(&input_path, serde_json::to_string(&attestation_data)?)
        .context("Запись zk input")?;

    info!("ZK proof: input записан в {:?}", input_path);

    // Вызываем Node.js generate_proof.js
    let generate_script = zk_dir.join("generate_proof.js");
    let output = tokio::process::Command::new("node")
        .arg(&generate_script)
        .arg(&input_path)
        .output()
        .await
        .context("Запуск node zk/generate_proof.js")?;

    // Удаляем temp файл
    let _ = std::fs::remove_file(&input_path);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("snarkjs ошибка: {stderr}");
    }

    let stdout = String::from_utf8(output.stdout)
        .context("snarkjs вывод не UTF-8")?;

    // Парсим JSON output
    let snarkjs: SnarkjsOutput =
        serde_json::from_str(&stdout).context("Парсинг snarkjs output")?;

    // Конвертируем в наш формат
    if snarkjs.proof.pi_a.len() < 2
        || snarkjs.proof.pi_b.len() < 2
        || snarkjs.proof.pi_c.len() < 2
        || snarkjs.public_signals.len() != 4
    {
        anyhow::bail!("Неверный формат snarkjs proof");
    }

    Ok(ZkProofResult {
        proof_a: [
            snarkjs.proof.pi_a[0].clone(),
            snarkjs.proof.pi_a[1].clone(),
        ],
        proof_b: [
            [
                snarkjs.proof.pi_b[0][0].clone(),
                snarkjs.proof.pi_b[0][1].clone(),
            ],
            [
                snarkjs.proof.pi_b[1][0].clone(),
                snarkjs.proof.pi_b[1][1].clone(),
            ],
        ],
        proof_c: [
            snarkjs.proof.pi_c[0].clone(),
            snarkjs.proof.pi_c[1].clone(),
        ],
        public_signals: [
            snarkjs.public_signals[0].clone(),
            snarkjs.public_signals[1].clone(),
            snarkjs.public_signals[2].clone(),
            snarkjs.public_signals[3].clone(),
        ],
    })
}

/// Находит директорию zk/ относительно текущего рабочего каталога или executable
fn get_zk_dir() -> Result<PathBuf> {
    // Сначала проверяем ZK_DIR env variable
    if let Ok(dir) = std::env::var("ZK_DIR") {
        let path = PathBuf::from(dir);
        if path.exists() {
            return Ok(path);
        }
    }

    // Затем относительно cwd
    let cwd_zk = std::env::current_dir()?.join("zk");
    if cwd_zk.exists() {
        return Ok(cwd_zk);
    }

    // Относительно executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let exe_zk = parent.join("zk");
            if exe_zk.exists() {
                return Ok(exe_zk);
            }
        }
    }

    anyhow::bail!("Директория zk/ не найдена. Установите ZK_DIR или запустите из директории prover/")
}
