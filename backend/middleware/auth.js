/**
 * Middleware аутентификации — проверка API-ключа
 *
 * Ключ передаётся в заголовке: X-API-Key: tlso_...
 */

import { validateApiKey, DAILY_LIMIT } from "../services/auth.js";
import config from "../config.js";

export function requireAuth(req, res, next) {
  const apiKey = req.headers["x-api-key"];

  if (!apiKey) {
    return res
      .status(401)
      .json({ error: "API key required. Header: X-API-Key" });
  }

  // Сервисный ключ — для service-to-service (NearCast relayer и т.д.)
  if (config.serviceApiKey && apiKey === config.serviceApiKey) {
    req.auth = { accountId: "service", apiKeyId: 0 };
    return next();
  }

  const keyInfo = validateApiKey(apiKey);

  if (!keyInfo) {
    return res.status(401).json({ error: "Invalid or deactivated API key" });
  }

  if (keyInfo.rateLimited) {
    return res.status(429).json({
      error: "Daily request limit exceeded",
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
