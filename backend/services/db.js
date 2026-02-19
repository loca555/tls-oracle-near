/**
 * SQLite — хранение API-ключей и аудит запросов
 */

import Database from "better-sqlite3";

let db = null;

export function initDb() {
  if (db) return db;
  db = new Database("tls-oracle.db");
  db.pragma("journal_mode = WAL");

  db.exec(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      account_id TEXT NOT NULL UNIQUE,
      api_key TEXT NOT NULL UNIQUE,
      created_at TEXT DEFAULT (datetime('now')),
      last_used TEXT,
      requests_today INTEGER DEFAULT 0,
      requests_total INTEGER DEFAULT 0,
      is_active INTEGER DEFAULT 1
    );

    CREATE INDEX IF NOT EXISTS idx_api_key ON api_keys(api_key);
    CREATE INDEX IF NOT EXISTS idx_account ON api_keys(account_id);
  `);

  return db;
}

export function getDb() {
  return db || initDb();
}
