/**
 * REST API маршруты TLS Oracle
 */

import { Router } from "express";
import * as near from "../services/near.js";
import * as proverClient from "../services/prover-client.js";
import config from "../config.js";

const router = Router();

// ── Пресеты источников данных ────────────────────────────────

const TEMPLATES = [
  {
    id: "btc-price",
    name: "Bitcoin Price (CoinGecko)",
    url: "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd",
    category: "crypto",
  },
  {
    id: "eth-price",
    name: "Ethereum Price (CoinGecko)",
    url: "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd",
    category: "crypto",
  },
  {
    id: "near-price",
    name: "NEAR Price (CoinGecko)",
    url: "https://api.coingecko.com/api/v3/simple/price?ids=near&vs_currencies=usd",
    category: "crypto",
  },
  {
    id: "httpbin-test",
    name: "Test (httpbin JSON)",
    url: "https://httpbin.org/json",
    category: "test",
  },
];

// ── Эндпоинты ────────────────────────────────────────────────

// Пресеты URL
router.get("/templates", (_req, res) => {
  res.json(TEMPLATES);
});

// Запросить аттестацию
router.post("/prove", async (req, res) => {
  try {
    const { url, method, headers } = req.body;
    if (!url) return res.status(400).json({ error: "URL обязателен" });

    const attestation = await proverClient.requestProof({ url, method, headers });
    res.json(attestation);
  } catch (err) {
    console.error("[api] /prove ошибка:", err.message);
    res.status(502).json({ error: err.message });
  }
});

// Отправить аттестацию в NEAR контракт
router.post("/submit", async (req, res) => {
  try {
    const txHash = await near.submitAttestation(req.body);
    res.json({ txHash });
  } catch (err) {
    console.error("[api] /submit ошибка:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Prove + Submit в одном запросе
router.post("/prove-and-submit", async (req, res) => {
  try {
    const { url, method, headers } = req.body;
    if (!url) return res.status(400).json({ error: "URL обязателен" });

    // 1. Получаем аттестацию
    const attestation = await proverClient.requestProof({ url, method, headers });

    // 2. Отправляем в контракт
    const txHash = await near.submitAttestation(attestation);

    res.json({ attestation, txHash });
  } catch (err) {
    console.error("[api] /prove-and-submit ошибка:", err.message);
    res.status(502).json({ error: err.message });
  }
});

// Список аттестаций
router.get("/attestations", async (req, res) => {
  const fromIndex = req.query.from ? parseInt(req.query.from) : undefined;
  const limit = req.query.limit ? parseInt(req.query.limit) : 20;
  const data = await near.getAttestations({ from_index: fromIndex, limit });
  res.json(data);
});

// Аттестация по ID
router.get("/attestations/:id", async (req, res) => {
  const data = await near.getAttestation(parseInt(req.params.id));
  if (!data) return res.status(404).json({ error: "Не найдено" });
  res.json(data);
});

// Аттестации по домену
router.get("/attestations/source/:serverName", async (req, res) => {
  const limit = req.query.limit ? parseInt(req.query.limit) : 20;
  const data = await near.getAttestationsBySource(req.params.serverName, limit);
  res.json(data);
});

// Нотариусы
router.get("/notaries", async (_req, res) => {
  const data = await near.getNotaries();
  res.json(data);
});

// Статистика
router.get("/stats", async (_req, res) => {
  const data = await near.getStats();
  res.json(data);
});

// NEAR конфиг для фронтенда
router.get("/near-config", (_req, res) => {
  res.json({
    networkId: config.near.network,
    nodeUrl: config.near.nodeUrl,
    contractId: config.near.contractId,
  });
});

// Здоровье сервисов
router.get("/health", async (_req, res) => {
  const proverOk = await proverClient.checkHealth();
  res.json({
    backend: true,
    prover: proverOk,
    contract: !!config.near.contractId,
  });
});

export default router;
