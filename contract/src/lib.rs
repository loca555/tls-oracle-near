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
}

/// Информация о доверенном нотариусе
#[near(serializers = [borsh, json])]
#[derive(Clone)]
#[serde(rename_all = "camelCase")]
pub struct NotaryInfo {
    /// Poseidon hash secp256k1 pubkey
    pub pubkey_hash: String,
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

    // ── Управление нотариусами (admin) ───────────────────────

    /// Добавить нотариуса по Poseidon hash его secp256k1 pubkey
    pub fn add_notary(&mut self, pubkey_hash: String, name: String, url: String) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Только owner может добавлять нотариусов"
        );
        require!(
            !self.trusted_notaries.contains_key(&pubkey_hash),
            "Нотариус уже добавлен"
        );

        let info = NotaryInfo {
            pubkey_hash: pubkey_hash.clone(),
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

    // ── Отправка аттестации с ZK-доказательством ─────────────

    /// Submit аттестации с Groth16 ZK proof
    ///
    /// proof_a: G1 точка [x, y] (decimal strings)
    /// proof_b: G2 точка [[x1, x2], [y1, y2]] (decimal strings)
    /// proof_c: G1 точка [x, y] (decimal strings)
    /// public_signals: [dataCommitment, serverNameHash, timestamp, notaryPubkeyHash]
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
        require!(
            self.trusted_notaries.contains_key(notary_pubkey_hash),
            "Нотариус не в списке доверенных"
        );

        // Replay-защита по data commitment
        let data_commitment = &public_signals[0];
        require!(
            !self.used_commitments.contains(data_commitment),
            "Эта аттестация уже была отправлена (replay)"
        );

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
            "ZK-аттестация #{} сохранена: {} ({})",
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
