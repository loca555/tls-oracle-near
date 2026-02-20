use near_sdk::borsh::BorshSerialize;
use near_sdk::store::{IterableMap, LookupMap, LookupSet};
use near_sdk::{env, near, require, AccountId, BorshStorageKey, PanicOnDefault};

mod bn254_types;
mod groth16;
mod vk_data;

use bn254_types::{G1Point, G2Point, Scalar};

// ── Ключи хранилища ─────────────────────────────────────────

#[derive(BorshSerialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
enum StorageKey {
    TrustedNotaries,
    Attestations,
    AttestationsBySource,
    UsedCommitments,
    // v2: новые префиксы для миграции (старые данные с Borsh v1 не десериализуются)
    TrustedNotariesV2,
    AttestationsV2,
    AttestationsBySourceV2,
    UsedCommitmentsV2,
}

// ── Модели данных ────────────────────────────────────────────

/// Аттестация — ZK-верифицированные данные с веб-сайта
#[near(serializers = [borsh, json])]
#[derive(Clone)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    pub id: u64,
    pub source_url: String,
    pub server_name: String,
    pub timestamp: u64,
    pub response_data: String,
    /// Poseidon commitment данных (public signal)
    pub data_commitment: String,
    /// Poseidon hash server_name (public signal)
    pub server_name_hash: String,
    /// Poseidon hash notary pubkey (public signal)
    pub notary_pubkey_hash: String,
    pub submitter: AccountId,
    pub block_height: u64,
    /// Подпись нотариуса верифицирована on-chain через ecrecover
    #[serde(default)]
    pub sig_verified: bool,
}

/// Информация о доверенном нотариусе
#[near(serializers = [borsh, json])]
#[derive(Clone)]
#[serde(rename_all = "camelCase")]
pub struct NotaryInfo {
    /// Poseidon hash secp256k1 pubkey
    pub pubkey_hash: String,
    /// Raw uncompressed secp256k1 pubkey x||y (hex, 128 chars = 64 bytes)
    /// Нужен для ecrecover верификации подписи
    pub raw_pubkey: Option<String>,
    pub name: String,
    pub url: String,
    pub added_by: AccountId,
    pub added_at: u64,
}

// ── Константы ─────────────────────────────────────────────────

/// Максимальный возраст аттестации: 10 минут (в секундах)
const MAX_ATTESTATION_AGE_SECS: u64 = 600;
/// Допуск на будущее время: 1 минута (в секундах)
const FUTURE_TOLERANCE_SECS: u64 = 60;

// ── Вспомогательные функции ──────────────────────────────────

/// Hex string → bytes
fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap())
        .collect()
}

/// Формирует message hash для верификации подписи нотариуса.
/// Формат: SHA-256(source_url || 0x00 || server_name || 0x00 || timestamp_be8 || 0x00 || response_data)
fn build_sign_message(
    source_url: &str,
    server_name: &str,
    timestamp: u64,
    response_data: &str,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(source_url.as_bytes());
    data.push(0x00);
    data.extend_from_slice(server_name.as_bytes());
    data.push(0x00);
    data.extend_from_slice(&timestamp.to_be_bytes());
    data.push(0x00);
    data.extend_from_slice(response_data.as_bytes());
    env::sha256(&data)
}

// ── Контракт ─────────────────────────────────────────────────

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct TlsOracle {
    owner: AccountId,
    /// Ключ: Poseidon hash notary pubkey (decimal string)
    trusted_notaries: IterableMap<String, NotaryInfo>,
    attestations: IterableMap<u64, Attestation>,
    attestations_by_source: LookupMap<String, Vec<u64>>,
    /// Poseidon data commitments для защиты от replay-атак
    used_commitments: LookupSet<String>,
    attestation_count: u64,
}

// ── Реализация ───────────────────────────────────────────────

#[near]
impl TlsOracle {
    #[init]
    pub fn new(owner: AccountId) -> Self {
        Self {
            owner,
            trusted_notaries: IterableMap::new(StorageKey::TrustedNotaries),
            attestations: IterableMap::new(StorageKey::Attestations),
            attestations_by_source: LookupMap::new(StorageKey::AttestationsBySource),
            used_commitments: LookupSet::new(StorageKey::UsedCommitments),
            attestation_count: 0,
        }
    }

    /// Миграция: сброс состояния при изменении Borsh схемы (testnet only)
    /// Использует V2 storage keys чтобы не конфликтовать со старыми данными
    #[private]
    #[init(ignore_state)]
    pub fn migrate(owner: AccountId) -> Self {
        Self {
            owner,
            trusted_notaries: IterableMap::new(StorageKey::TrustedNotariesV2),
            attestations: IterableMap::new(StorageKey::AttestationsV2),
            attestations_by_source: LookupMap::new(StorageKey::AttestationsBySourceV2),
            used_commitments: LookupSet::new(StorageKey::UsedCommitmentsV2),
            attestation_count: 0,
        }
    }

    // ── Управление нотариусами (admin) ───────────────────────

    /// Добавить нотариуса по Poseidon hash его secp256k1 pubkey
    /// raw_pubkey — uncompressed x||y (hex, 128 chars) для ecrecover
    pub fn add_notary(
        &mut self,
        pubkey_hash: String,
        name: String,
        url: String,
        raw_pubkey: Option<String>,
    ) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Только owner может добавлять нотариусов"
        );

        if let Some(ref pk) = raw_pubkey {
            require!(
                pk.len() == 128,
                "raw_pubkey: 128 hex chars (64 bytes x||y)"
            );
            require!(
                pk.chars().all(|c| c.is_ascii_hexdigit()),
                "raw_pubkey: невалидный hex"
            );
        }

        // Если нотариус уже есть — обновляем (позволяет добавить raw_pubkey)
        if self.trusted_notaries.contains_key(&pubkey_hash) {
            let mut info = self.trusted_notaries.get(&pubkey_hash).unwrap().clone();
            if raw_pubkey.is_some() {
                info.raw_pubkey = raw_pubkey;
            }
            info.name = name;
            info.url = url;
            self.trusted_notaries.insert(pubkey_hash.clone(), info);
            env::log_str(&format!("Нотариус обновлён: {}", pubkey_hash));
            return;
        }

        let info = NotaryInfo {
            pubkey_hash: pubkey_hash.clone(),
            raw_pubkey,
            name,
            url,
            added_by: env::predecessor_account_id(),
            added_at: env::block_height(),
        };
        self.trusted_notaries.insert(pubkey_hash.clone(), info);
        env::log_str(&format!("Нотариус добавлен: {}", pubkey_hash));
    }

    pub fn remove_notary(&mut self, pubkey_hash: String) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Только owner может удалять нотариусов"
        );
        require!(
            self.trusted_notaries.remove(&pubkey_hash).is_some(),
            "Нотариус не найден"
        );
        env::log_str(&format!("Нотариус удалён: {}", pubkey_hash));
    }

    pub fn set_owner(&mut self, new_owner: AccountId) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Только owner"
        );
        self.owner = new_owner;
    }

    // ── Отправка аттестации с ZK-доказательством + подпись ────

    /// Submit аттестации с Groth16 ZK proof + подпись нотариуса
    ///
    /// Верификация:
    /// 1. Groth16 ZK proof (data integrity через Poseidon commitments)
    /// 2. secp256k1 ECDSA подпись нотариуса (ecrecover)
    #[payable]
    pub fn submit_attestation(
        &mut self,
        source_url: String,
        server_name: String,
        timestamp: u64,
        response_data: String,
        // Groth16 proof
        proof_a: [String; 2],
        proof_b: [[String; 2]; 2],
        proof_c: [String; 2],
        public_signals: [String; 4],
        // Подпись нотариуса (secp256k1 ECDSA)
        notary_signature: String,
        notary_sig_v: u8,
    ) -> u64 {
        require!(response_data.len() <= 4096, "response_data макс 4KB");
        require!(source_url.len() <= 2048, "source_url макс 2KB");

        // Проверка timestamp
        let block_ts_secs = env::block_timestamp() / 1_000_000_000;
        require!(
            timestamp <= block_ts_secs + FUTURE_TOLERANCE_SECS,
            "Timestamp аттестации в будущем"
        );
        require!(
            timestamp + MAX_ATTESTATION_AGE_SECS >= block_ts_secs,
            "Аттестация устарела (макс 10 минут)"
        );

        // Проверяем что timestamp в public_signals совпадает
        require!(
            public_signals[2] == timestamp.to_string(),
            "Timestamp в public_signals не совпадает"
        );

        // Проверяем что нотариус доверенный (по Poseidon hash pubkey)
        let notary_pubkey_hash = &public_signals[3];
        let notary_info = self
            .trusted_notaries
            .get(notary_pubkey_hash)
            .expect("Нотариус не в списке доверенных")
            .clone();

        // Replay-защита по data commitment
        let data_commitment = &public_signals[0];
        require!(
            !self.used_commitments.contains(data_commitment),
            "Эта аттестация уже была отправлена (replay)"
        );

        // ── Верификация подписи нотариуса (ecrecover) ────────
        let raw_pk = notary_info
            .raw_pubkey
            .as_ref()
            .expect("raw_pubkey не установлен — обновите нотариуса через add_notary");

        require!(
            notary_signature.len() == 128,
            "notary_signature: 128 hex chars (64 bytes r||s)"
        );
        require!(notary_sig_v <= 1, "notary_sig_v: 0 или 1");

        // Воспроизводим message hash (SHA-256)
        let message_hash = build_sign_message(&source_url, &server_name, timestamp, &response_data);

        // Декодируем подпись
        let sig_bytes = hex_to_bytes(&notary_signature);

        // ecrecover: восстанавливаем pubkey из подписи
        let recovered = env::ecrecover(&message_hash, &sig_bytes, notary_sig_v, true)
            .expect("ecrecover: невалидная подпись");

        // Сравниваем с зарегистрированным pubkey нотариуса
        let expected_pubkey = hex_to_bytes(raw_pk);
        require!(
            recovered.as_slice() == expected_pubkey.as_slice(),
            "Подпись нотариуса не совпадает с зарегистрированным ключом"
        );

        env::log_str("Подпись нотариуса верифицирована (ecrecover)");

        // ── Groth16 ZK верификация ──────────────────────────

        // Парсим Groth16 proof
        let proof = groth16::Proof {
            a: G1Point::from_decimal(&proof_a[0], &proof_a[1]),
            b: G2Point {
                x_im: bn254_types::decimal_to_le_bytes(&proof_b[0][1]),
                x_re: bn254_types::decimal_to_le_bytes(&proof_b[0][0]),
                y_im: bn254_types::decimal_to_le_bytes(&proof_b[1][1]),
                y_re: bn254_types::decimal_to_le_bytes(&proof_b[1][0]),
            },
            c: G1Point::from_decimal(&proof_c[0], &proof_c[1]),
        };

        // Парсим public signals → Scalar
        let pub_inputs: Vec<Scalar> = public_signals
            .iter()
            .map(|s| Scalar::from_decimal(s))
            .collect();

        // ZK верификация: Groth16 через alt_bn128
        let vk = vk_data::get_vk();
        require!(
            groth16::verify(&vk, &proof, &pub_inputs),
            "ZK proof невалиден"
        );

        // Сохраняем commitment как использованный
        self.used_commitments.insert(data_commitment.clone());

        // Сохраняем аттестацию
        let id = self.attestation_count;
        self.attestation_count += 1;

        let attestation = Attestation {
            id,
            source_url,
            server_name: server_name.clone(),
            timestamp,
            response_data,
            data_commitment: public_signals[0].clone(),
            server_name_hash: public_signals[1].clone(),
            notary_pubkey_hash: public_signals[3].clone(),
            submitter: env::predecessor_account_id(),
            block_height: env::block_height(),
            sig_verified: true,
        };

        self.attestations.insert(id, attestation);

        // Индекс по домену
        let mut ids = self
            .attestations_by_source
            .get(&server_name)
            .cloned()
            .unwrap_or_default();
        ids.push(id);
        self.attestations_by_source.insert(server_name.clone(), ids);

        env::log_str(&format!(
            "Аттестация #{} сохранена: {} ({}) [sig+zk verified]",
            id, server_name, env::predecessor_account_id()
        ));

        id
    }

    // ── View методы ──────────────────────────────────────────

    pub fn get_attestation(&self, id: u64) -> Option<Attestation> {
        self.attestations.get(&id).cloned()
    }

    pub fn get_attestations(
        &self,
        from_index: Option<u64>,
        limit: Option<u64>,
    ) -> Vec<Attestation> {
        let total = self.attestation_count;
        if total == 0 {
            return vec![];
        }

        let limit = limit.unwrap_or(20).min(100);
        let from = from_index.unwrap_or(total.saturating_sub(1));

        let mut result: Vec<Attestation> = Vec::new();
        let mut i = from;
        loop {
            if let Some(a) = self.attestations.get(&i) {
                result.push(a.clone());
            }
            if result.len() as u64 >= limit || i == 0 {
                break;
            }
            i -= 1;
        }
        result
    }

    pub fn get_attestations_by_source(
        &self,
        server_name: String,
        limit: Option<u64>,
    ) -> Vec<Attestation> {
        let ids = self
            .attestations_by_source
            .get(&server_name)
            .cloned()
            .unwrap_or_default();
        let limit = limit.unwrap_or(20).min(100) as usize;

        ids.iter()
            .rev()
            .take(limit)
            .filter_map(|id| self.attestations.get(id).cloned())
            .collect()
    }

    pub fn get_notaries(&self) -> Vec<NotaryInfo> {
        self.trusted_notaries.values().cloned().collect()
    }

    pub fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "attestationCount": self.attestation_count,
            "notaryCount": self.trusted_notaries.len(),
            "owner": self.owner,
        })
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }
}
