/**
 * Маршруты аутентификации — регистрация через NEAR кошелёк
 *
 * Флоу:
 * 1. POST /api/auth/challenge {accountId} → {nonce, message}
 * 2. Wallet подписывает message
 * 3. POST /api/auth/verify {accountId, nonce, publicKey} → {apiKey}
 */

import { Router } from "express";
import { createChallenge, verifyAndIssueKey, revokeApiKey, regenerateApiKey } from "../services/auth.js";
import { requireAuth } from "../middleware/auth.js";

const router = Router();

// Шаг 1: Получить challenge для подписи
router.post("/challenge", (req, res) => {
  const { accountId } = req.body;
  if (!accountId)
    return res.status(400).json({ error: "accountId обязателен" });

  // Базовая валидация NEAR accountId
  if (accountId.length > 64 || !/^[a-z0-9._-]+$/.test(accountId)) {
    return res.status(400).json({ error: "Неверный формат accountId" });
  }

  const challenge = createChallenge(accountId);
  res.json(challenge);
});

// Шаг 2: Подтвердить владение аккаунтом и получить API-ключ
router.post("/verify", async (req, res) => {
  try {
    const { accountId, nonce, publicKey } = req.body;
    if (!accountId || !nonce || !publicKey) {
      return res.status(400).json({
        error: "Обязательные поля: accountId, nonce, publicKey",
      });
    }

    const result = await verifyAndIssueKey(accountId, nonce, publicKey);
    res.json(result);
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

// Шаг 3 (опционально): Удалить (деактивировать) текущий API-ключ
router.delete("/key", requireAuth, (req, res) => {
  try {
    const apiKey = req.headers["x-api-key"];
    const revoked = revokeApiKey(apiKey);

    if (!revoked) {
      return res.status(404).json({ error: "API-ключ не найден или уже деактивирован" });
    }

    res.json({ success: true, message: "API-ключ деактивирован" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Шаг 4 (опционально): Перегенерировать API-ключ (деактивировать старый, создать новый)
router.post("/regenerate", requireAuth, (req, res) => {
  try {
    const { accountId } = req.auth;

    if (!accountId || accountId === "service") {
      return res.status(400).json({ error: "Перегенерация недоступна для сервисных ключей" });
    }

    const newApiKey = regenerateApiKey(accountId);

    if (!newApiKey) {
      return res.status(500).json({ error: "Не удалось создать новый ключ" });
    }

    res.json({ apiKey: newApiKey });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
