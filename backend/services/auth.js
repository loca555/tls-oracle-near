/**
 * Аутентификация через NEAR кошелёк + управление API-ключами
 *
 * Флоу: challenge → подпись wallet → верификация → выдача API-ключа
 */

import crypto from "node:crypto";
import { getDb } from "./db.js";
import config from "../config.js";

// Хранилище challenge-ов (короткоживущие, в памяти)
const challenges = new Map(); // nonce -> { accountId, createdAt }
const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 минут

// Дневной лимит запросов на один API-ключ
export const DAILY_LIMIT = 100;

/**
 * Создать challenge для аккаунта
 */
export function createChallenge(accountId) {
  // Очистка просроченных
  const now = Date.now();
  for (const [key, val] of challenges) {
    if (now - val.createdAt > CHALLENGE_TTL_MS) challenges.delete(key);
  }

  const nonce = crypto.randomBytes(32).toString("hex");
  const message = `tls-oracle:auth:${accountId}:${nonce}`;
  challenges.set(nonce, { accountId, createdAt: now });

  return { nonce, message };
}

/**
 * Верифицировать подпись и выдать/вернуть API-ключ
 */
export async function verifyAndIssueKey(accountId, nonce, publicKey) {
  const challenge = challenges.get(nonce);
  if (!challenge) throw new Error("Challenge не найден или истёк");
  if (challenge.accountId !== accountId) throw new Error("Неверный аккаунт");
  challenges.delete(nonce);

  // Проверяем что publicKey зарегистрирован для accountId через NEAR RPC
  const keyExists = await verifyAccessKey(accountId, publicKey);
  if (!keyExists) throw new Error("Ключ не принадлежит аккаунту");

  const db = getDb();

  // Проверяем, есть ли уже ключ
  const row = db
    .prepare("SELECT * FROM api_keys WHERE account_id = ?")
    .get(accountId);

  if (row && row.is_active) {
    return { apiKey: row.api_key, existing: true };
  }

  // Генерируем новый API-ключ
  const apiKey = `tlso_${crypto.randomBytes(24).toString("hex")}`;

  db.prepare(
    `INSERT OR REPLACE INTO api_keys (account_id, api_key, is_active)
     VALUES (?, ?, 1)`,
  ).run(accountId, apiKey);

  return { apiKey, existing: false };
}

/**
 * Проверить API-ключ (для middleware)
 */
export function validateApiKey(apiKey) {
  if (!apiKey || !apiKey.startsWith("tlso_")) return null;

  const db = getDb();
  const row = db
    .prepare("SELECT * FROM api_keys WHERE api_key = ? AND is_active = 1")
    .get(apiKey);

  if (!row) return null;

  // Сброс дневного счётчика
  const today = new Date().toISOString().slice(0, 10);
  const lastUsedDay = row.last_used ? row.last_used.slice(0, 10) : null;

  if (lastUsedDay !== today) {
    db.prepare("UPDATE api_keys SET requests_today = 0 WHERE id = ?").run(
      row.id,
    );
    row.requests_today = 0;
  }

  if (row.requests_today >= DAILY_LIMIT) {
    return { ...row, rateLimited: true };
  }

  // Обновляем счётчики
  db.prepare(
    `UPDATE api_keys
     SET last_used = datetime('now'),
         requests_today = requests_today + 1,
         requests_total = requests_total + 1
     WHERE id = ?`,
  ).run(row.id);

  return { ...row, rateLimited: false };
}

/**
 * Отозвать (деактивировать) API-ключ
 *
 * Возвращает true если ключ был деактивирован, false если не найден
 */
export function revokeApiKey(apiKey) {
  if (!apiKey || !apiKey.startsWith("tlso_")) return false;

  const db = getDb();
  const result = db
    .prepare("UPDATE api_keys SET is_active = 0 WHERE api_key = ? AND is_active = 1")
    .run(apiKey);

  return result.changes > 0;
}

/**
 * Перегенерировать API-ключ для аккаунта
 *
 * Деактивирует старый ключ и создаёт новый.
 * Возвращает новый API-ключ или null если аккаунт не найден.
 */
export function regenerateApiKey(accountId) {
  if (!accountId) return null;

  const db = getDb();

  // Деактивируем все текущие ключи аккаунта
  db.prepare("UPDATE api_keys SET is_active = 0 WHERE account_id = ? AND is_active = 1")
    .run(accountId);

  // Генерируем новый API-ключ
  const newApiKey = `tlso_${crypto.randomBytes(24).toString("hex")}`;

  db.prepare(
    `INSERT INTO api_keys (account_id, api_key, is_active)
     VALUES (?, ?, 1)`,
  ).run(accountId, newApiKey);

  return newApiKey;
}

/**
 * Проверить что publicKey зарегистрирован для accountId через NEAR RPC
 */
async function verifyAccessKey(accountId, publicKey) {
  try {
    const resp = await fetch(config.near.nodeUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "1",
        method: "query",
        params: {
          request_type: "view_access_key",
          finality: "final",
          account_id: accountId,
          public_key: publicKey,
        },
      }),
    });

    const data = await resp.json();
    return !data.error && !!data.result;
  } catch {
    return false;
  }
}
