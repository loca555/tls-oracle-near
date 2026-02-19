/**
 * Клиент Prover Service — запрашивает TLS-аттестации
 */

import config from "../config.js";

/**
 * Запросить MPC-TLS аттестацию + ZK proof через Prover
 * @param {object} params - { url, method?, headers? }
 * @returns {object} - { sourceUrl, serverName, timestamp, responseData, proofA, proofB, proofC, publicSignals }
 */
export async function requestProof(params) {
  const resp = await fetch(`${config.prover.url}/prove`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Prover ошибка (${resp.status}): ${text}`);
  }

  return resp.json();
}

/**
 * Запросить ESPN аттестацию — MPC-TLS + ZK proof с извлечением scores
 * @param {object} params - { espnEventId, sport, league }
 * @returns {object} - { sourceUrl, serverName, timestamp, responseData, proofA, proofB, proofC, publicSignals }
 */
export async function requestEspnProof(params) {
  const resp = await fetch(`${config.prover.url}/prove-espn`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Prover ESPN ошибка (${resp.status}): ${text}`);
  }

  return resp.json();
}

/**
 * Получить информацию о нотариусе
 */
export async function getNotaryInfo() {
  const resp = await fetch(`${config.prover.url}/notary-info`);
  if (!resp.ok) throw new Error(`Prover недоступен: ${resp.status}`);
  return resp.json();
}

/**
 * Проверить доступность Prover Service
 */
export async function checkHealth() {
  try {
    const resp = await fetch(`${config.prover.url}/health`, { signal: AbortSignal.timeout(3000) });
    return resp.ok;
  } catch {
    return false;
  }
}
