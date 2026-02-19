/**
 * TLS Oracle — Express API сервер
 */

import express from "express";
import cors from "cors";
import config from "./config.js";
import apiRoutes from "./routes/api.js";

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// API маршруты
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
  console.log(`[server] TLS Oracle API запущен на http://localhost:${port}`);
  console.log(`[server] NEAR: ${config.near.network}, контракт: ${config.near.contractId || "(не установлен)"}`);
  console.log(`[server] Prover: ${config.prover?.url || "(не установлен)"}`);
});
