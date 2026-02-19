/**
 * NEAR сервис — только view-методы (чтение из контракта)
 *
 * Серверный submit удалён: пользователь отправляет транзакции из своего кошелька.
 */

import { connect, keyStores } from "near-api-js";
import config from "../config.js";

let viewAccount = null;

// ── Инициализация read-only аккаунта ──────────────────────────

async function initViewAccount() {
  if (viewAccount) return viewAccount;

  const keyStore = new keyStores.InMemoryKeyStore();
  const near = await connect({
    networkId: config.near.network,
    keyStore,
    nodeUrl: config.near.nodeUrl,
  });

  viewAccount = await near.account("dontcare");
  return viewAccount;
}

// ── View методы (бесплатные) ──────────────────────────────────

export async function viewContract(methodName, args = {}) {
  if (!config.near.contractId) {
    console.warn(`[near] Контракт не установлен, пропускаю ${methodName}`);
    return null;
  }
  try {
    const account = await initViewAccount();
    return account.viewFunction({
      contractId: config.near.contractId,
      methodName,
      args,
    });
  } catch (err) {
    console.error(`[near] Ошибка вызова ${methodName}:`, err.message);
    return null;
  }
}

export async function getAttestations(params = {}) {
  return (await viewContract("get_attestations", params)) || [];
}

export async function getAttestation(id) {
  return viewContract("get_attestation", { id });
}

export async function getAttestationsBySource(serverName, limit = 20) {
  return (
    (await viewContract("get_attestations_by_source", {
      server_name: serverName,
      limit,
    })) || []
  );
}

export async function getNotaries() {
  return (await viewContract("get_notaries")) || [];
}

export async function getStats() {
  return (
    (await viewContract("get_stats")) || {
      attestationCount: 0,
      notaryCount: 0,
    }
  );
}
