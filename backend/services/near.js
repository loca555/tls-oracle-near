/**
 * NEAR сервис — подключение к блокчейну
 *
 * Два режима:
 * - viewAccount: бесплатные чтения (без ключей)
 * - oracleAccount: подписание транзакций (submit_attestation)
 */

import { connect, keyStores, KeyPair } from "near-api-js";
import config from "../config.js";

let viewAccount = null;
let oracleAccount = null;

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

// ── Инициализация аккаунта оракула ────────────────────────────

async function initOracleAccount() {
  if (oracleAccount) return oracleAccount;

  if (!config.oracle.accountId || !config.oracle.privateKey) {
    throw new Error("ORACLE_ACCOUNT_ID и ORACLE_PRIVATE_KEY не установлены");
  }

  const keyStore = new keyStores.InMemoryKeyStore();
  const keyPair = KeyPair.fromString(config.oracle.privateKey);
  await keyStore.setKey(config.near.network, config.oracle.accountId, keyPair);

  const near = await connect({
    networkId: config.near.network,
    keyStore,
    nodeUrl: config.near.nodeUrl,
  });

  oracleAccount = await near.account(config.oracle.accountId);
  console.log(`[near] Oracle подключён: ${config.oracle.accountId}`);
  return oracleAccount;
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
  return (await viewContract("get_attestations_by_source", {
    server_name: serverName,
    limit,
  })) || [];
}

export async function getNotaries() {
  return (await viewContract("get_notaries")) || [];
}

export async function getStats() {
  return (await viewContract("get_stats")) || {
    attestationCount: 0,
    notaryCount: 0,
  };
}

// ── Отправка аттестации в контракт ────────────────────────────

export async function submitAttestation(attestation) {
  const account = await initOracleAccount();

  const result = await account.functionCall({
    contractId: config.near.contractId,
    methodName: "submit_attestation",
    args: {
      source_url: attestation.sourceUrl,
      server_name: attestation.serverName,
      timestamp: attestation.timestamp,
      response_data: attestation.responseData,
      notary_pubkey: attestation.notaryPubkey,
      signature: attestation.signature,
    },
    gas: "100000000000000", // 100 TGas
    attachedDeposit: "50000000000000000000000", // 0.05 NEAR (storage)
  });

  const txHash = result.transaction?.hash || result.transaction_outcome?.id;
  console.log(`[near] Аттестация отправлена. TX: ${txHash}`);
  return txHash;
}
