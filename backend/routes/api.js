/**
 * REST API маршруты TLS Oracle
 *
 * POST /prove — защищён API-ключом (X-API-Key).
 * Submit удалён — пользователь отправляет транзакции из своего кошелька.
 */

import { Router } from "express";
import * as near from "../services/near.js";
import * as proverClient from "../services/prover-client.js";
import config from "../config.js";
import { requireAuth } from "../middleware/auth.js";

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
  {
    id: "espn-scores",
    name: "ESPN Game Scores",
    url: "https://site.api.espn.com/apis/site/v2/sports/{sport}/{league}/summary?event={event_id}",
    category: "sports",
    description: "MPC-TLS proof of live ESPN game scores (compact extraction)",
  },
];

// ── Эндпоинты ────────────────────────────────────────────────

// Пресеты URL (публичный)
router.get("/templates", (_req, res) => {
  res.json(TEMPLATES);
});

// Запросить аттестацию (защищённый — требует API-ключ)
router.post("/prove", requireAuth, async (req, res) => {
  try {
    const { url, method, headers } = req.body;
    if (!url) return res.status(400).json({ error: "URL обязателен" });

    // Валидация URL
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return res.status(400).json({ error: "Неверный формат URL" });
    }

    if (parsed.protocol !== "https:") {
      return res.status(400).json({ error: "Разрешён только HTTPS" });
    }

    if (url.length > 2048) {
      return res
        .status(400)
        .json({ error: "URL слишком длинный (макс 2048)" });
    }

    const m = (method || "GET").toUpperCase();
    if (!["GET", "POST"].includes(m)) {
      return res
        .status(400)
        .json({ error: "Метод должен быть GET или POST" });
    }

    const attestation = await proverClient.requestProof({
      url,
      method: m,
      headers,
    });
    res.json(attestation);
  } catch (err) {
    console.error("[api] /prove ошибка:", err.message);
    res.status(502).json({ error: err.message });
  }
});

// Запросить ESPN аттестацию (защищённый — требует API-ключ)
router.post("/prove-espn", requireAuth, async (req, res) => {
  try {
    const { espnEventId, sport, league } = req.body;
    if (!espnEventId || !sport || !league) {
      return res
        .status(400)
        .json({ error: "espnEventId, sport и league обязательны" });
    }

    const attestation = await proverClient.requestEspnProof({
      espnEventId,
      sport,
      league,
    });
    res.json(attestation);
  } catch (err) {
    console.error("[api] /prove-espn ошибка:", err.message);
    res.status(502).json({ error: err.message });
  }
});

// Список аттестаций (публичный)
router.get("/attestations", async (req, res) => {
  const fromIndex = req.query.from ? parseInt(req.query.from) : undefined;
  const limit = req.query.limit ? parseInt(req.query.limit) : 20;
  const data = await near.getAttestations({ from_index: fromIndex, limit });
  res.json(data);
});

// Аттестация по ID (публичный)
router.get("/attestations/:id", async (req, res) => {
  const data = await near.getAttestation(parseInt(req.params.id));
  if (!data) return res.status(404).json({ error: "Не найдено" });
  res.json(data);
});

// Аттестации по домену (публичный)
router.get("/attestations/source/:serverName", async (req, res) => {
  const limit = req.query.limit ? parseInt(req.query.limit) : 20;
  const data = await near.getAttestationsBySource(req.params.serverName, limit);
  res.json(data);
});

// Нотариусы (публичный)
router.get("/notaries", async (_req, res) => {
  const data = await near.getNotaries();
  res.json(data);
});

// Статистика (публичный)
router.get("/stats", async (_req, res) => {
  const data = await near.getStats();
  res.json(data);
});

// NEAR конфиг для фронтенда (публичный)
router.get("/near-config", (_req, res) => {
  res.json({
    networkId: config.near.network,
    nodeUrl: config.near.nodeUrl,
    contractId: config.near.contractId,
  });
});

// Здоровье сервисов (публичный)
router.get("/health", async (_req, res) => {
  const proverOk = await proverClient.checkHealth();
  res.json({
    backend: true,
    prover: proverOk,
    contract: !!config.near.contractId,
  });
});

export default router;
