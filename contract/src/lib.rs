use near_sdk::borsh::BorshSerialize;
use near_sdk::json_types::Base64VecU8;
use near_sdk::store::{IterableMap, LookupMap, LookupSet};
use near_sdk::{env, near, require, AccountId, BorshStorageKey, PanicOnDefault};

// ── Ключи хранилища ─────────────────────────────────────────

#[derive(BorshSerialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
enum StorageKey {
    TrustedNotaries,
    Attestations,
    AttestationsBySource,
    UsedHashes,
}

// ── Модели данных ────────────────────────────────────────────

/// Аттестация — криптографически подтверждённые данные с веб-сайта
#[near(serializers = [borsh, json])]
#[derive(Clone)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    pub id: u64,
    pub source_url: String,
    pub server_name: String,
    pub timestamp: u64,
    pub response_data: String,
    pub data_hash: Base64VecU8,
    pub notary_pubkey: Base64VecU8,
    pub signature: Base64VecU8,
    pub submitter: AccountId,
    pub block_height: u64,
}

/// Информация о доверенном нотариусе
#[near(serializers = [borsh, json])]
#[derive(Clone)]
#[serde(rename_all = "camelCase")]
pub struct NotaryInfo {
    pub pubkey: Base64VecU8,
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
    trusted_notaries: IterableMap<String, NotaryInfo>,
    attestations: IterableMap<u64, Attestation>,
    attestations_by_source: LookupMap<String, Vec<u64>>,
    /// Использованные хеши для защиты от replay-атак
    used_hashes: LookupSet<Vec<u8>>,
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
            used_hashes: LookupSet::new(StorageKey::UsedHashes),
            attestation_count: 0,
        }
    }

    // ── Управление нотариусами (admin) ───────────────────────

    pub fn add_notary(&mut self, pubkey: Base64VecU8, name: String, url: String) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Только owner может добавлять нотариусов"
        );
        require!(pubkey.0.len() == 32, "Ed25519 pubkey должен быть 32 байта");

        let key = hex::encode(&pubkey.0);
        require!(
            !self.trusted_notaries.contains_key(&key),
            "Нотариус уже добавлен"
        );

        let info = NotaryInfo {
            pubkey: pubkey.clone(),
            name,
            url,
            added_by: env::predecessor_account_id(),
            added_at: env::block_height(),
        };
        self.trusted_notaries.insert(key, info);
        env::log_str(&format!("Нотариус добавлен: {}", hex::encode(&pubkey.0)));
    }

    pub fn remove_notary(&mut self, pubkey: Base64VecU8) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Только owner может удалять нотариусов"
        );
        let key = hex::encode(&pubkey.0);
        require!(
            self.trusted_notaries.remove(&key).is_some(),
            "Нотариус не найден"
        );
        env::log_str(&format!("Нотариус удалён: {}", key));
    }

    pub fn set_owner(&mut self, new_owner: AccountId) {
        require!(
            env::predecessor_account_id() == self.owner,
            "Только owner"
        );
        self.owner = new_owner;
    }

    // ── Отправка аттестации ──────────────────────────────────

    #[payable]
    pub fn submit_attestation(
        &mut self,
        source_url: String,
        server_name: String,
        timestamp: u64,
        response_data: String,
        notary_pubkey: Base64VecU8,
        signature: Base64VecU8,
    ) -> u64 {
        let notary_key = hex::encode(&notary_pubkey.0);
        require!(
            self.trusted_notaries.contains_key(&notary_key),
            "Нотариус не в списке доверенных"
        );

        require!(notary_pubkey.0.len() == 32, "Ed25519 pubkey: 32 байта");
        require!(signature.0.len() == 64, "Ed25519 signature: 64 байта");
        require!(response_data.len() <= 4096, "response_data макс 4KB");
        require!(source_url.len() <= 2048, "source_url макс 2KB");

        // Проверка timestamp: не старше MAX_ATTESTATION_AGE_SECS, не в будущем
        let block_ts_secs = env::block_timestamp() / 1_000_000_000;
        require!(
            timestamp <= block_ts_secs + FUTURE_TOLERANCE_SECS,
            "Timestamp аттестации в будущем"
        );
        require!(
            timestamp + MAX_ATTESTATION_AGE_SECS >= block_ts_secs,
            "Аттестация устарела (макс 10 минут)"
        );

        // Формируем подписанное сообщение (такой же формат у Notary)
        let message = format!(
            "{}|{}|{}|{}",
            source_url, server_name, timestamp, response_data
        );
        let message_hash = env::sha256(message.as_bytes());

        // Replay-защита: проверяем что этот хеш ещё не использовался
        require!(
            !self.used_hashes.contains(&message_hash),
            "Эта аттестация уже была отправлена (replay)"
        );

        // Ed25519 верификация — конвертируем Vec<u8> в fixed-size arrays
        let sig_arr: [u8; 64] = signature.0.as_slice().try_into()
            .expect("signature: 64 байта");
        let pk_arr: [u8; 32] = notary_pubkey.0.as_slice().try_into()
            .expect("pubkey: 32 байта");

        let valid = env::ed25519_verify(&sig_arr, &message_hash, &pk_arr);
        require!(valid, "Неверная Ed25519 подпись нотариуса");

        // Сохраняем хеш как использованный
        self.used_hashes.insert(message_hash.clone());

        // Сохраняем
        let id = self.attestation_count;
        self.attestation_count += 1;

        let attestation = Attestation {
            id,
            source_url,
            server_name: server_name.clone(),
            timestamp,
            response_data,
            data_hash: Base64VecU8(message_hash),
            notary_pubkey,
            signature,
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
            "Аттестация #{} сохранена: {} ({})",
            id, server_name, env::predecessor_account_id()
        ));

        id
    }

    // ── View методы ──────────────────────────────────────────

    pub fn get_attestation(&self, id: u64) -> Option<Attestation> {
        self.attestations.get(&id).cloned()
    }

    pub fn get_attestations(&self, from_index: Option<u64>, limit: Option<u64>) -> Vec<Attestation> {
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

// ── Hex encoding (минимальный, без внешнего крейта) ──────────

mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }
}
