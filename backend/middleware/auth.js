/**
 * Middleware аутентификации — проверка API-ключа
 *
 * Ключ передаётся в заголовке: X-API-Key: tlso_...
 */

import { validateApiKey, DAILY_LIMIT } from "../services/auth.js";

export function requireAuth(req, res, next) {
  const apiKey = req.headers["x-api-key"];

  if (!apiKey) {
    return res
      .status(401)
      .json({ error: "API-ключ обязателен. Заголовок: X-API-Key" });
  }

  const keyInfo = validateApiKey(apiKey);

  if (!keyInfo) {
    return res.status(401).json({ error: "Неверный или деактивированный API-ключ" });
  }

  if (keyInfo.rateLimited) {
    return res.status(429).json({
      error: "Превышен дневной лимит запросов",
      limit: DAILY_LIMIT,
      resetAt: "00:00 UTC",
    });
  }

  // Данные пользователя для обработчиков
  req.auth = {
    accountId: keyInfo.account_id,
    apiKeyId: keyInfo.id,
  };

  next();
}
