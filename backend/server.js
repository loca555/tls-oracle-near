/**
 * TLS Oracle — Express API сервер
 *
 * Безопасность: CORS, rate limiting, JSON limit, API-ключи
 */

import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import config from "./config.js";
import apiRoutes from "./routes/api.js";
import authRoutes from "./routes/auth.js";
import { initDb } from "./services/db.js";

// Инициализация БД
initDb();

const app = express();

// CORS — только фронтенд
app.use(
  cors({
    origin: config.frontendUrl || false,
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "X-API-Key"],
  }),
);

// Ограничение размера JSON
app.use(express.json({ limit: "16kb" }));

// Глобальный rate limit: 60 запросов/мин на IP
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Слишком много запросов. Подождите." },
  }),
);

// API маршруты
app.use("/api/auth", authRoutes);
app.use("/api/", apiRoutes);

// Статика фронтенда (production)
if (process.env.NODE_ENV === "production") {
  const { default: path } = await import("path");
  const frontendPath = path.resolve("frontend/dist");
  app.use(express.static(frontendPath));
  app.get("*", (_req, res, next) => {
    if (_req.path.startsWith("/api/")) return next();
    res.sendFile(path.join(frontendPath, "index.html"));
  });
}

// Старт
const port = config.port;
app.listen(port, () => {
  console.log(
    `[server] TLS Oracle API запущен на http://localhost:${port}`,
  );
  console.log(
    `[server] NEAR: ${config.near.network}, контракт: ${config.near.contractId || "(не установлен)"}`,
  );
  console.log(
    `[server] Prover: ${config.prover?.url || "(не установлен)"}`,
  );
});
