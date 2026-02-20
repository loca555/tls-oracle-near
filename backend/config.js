/**
 * Конфигурация TLS Oracle
 */

import dotenv from "dotenv";
dotenv.config();

export default {
  port: process.env.PORT || 4001,
  frontendUrl: process.env.FRONTEND_URL ||
    (process.env.NODE_ENV === "production" ? "" : "http://localhost:3001"),

  near: {
    network: process.env.NEAR_NETWORK || "testnet",
    nodeUrl:
      process.env.NEAR_NODE_URL ||
      (process.env.NEAR_NETWORK === "mainnet"
        ? "https://free.rpc.fastnear.com"
        : "https://test.rpc.fastnear.com"),
    contractId: process.env.TLS_ORACLE_CONTRACT || "tls-oracle-v2.nearcast-oracle.testnet",
  },

  prover: {
    url: process.env.PROVER_URL || "http://34.44.244.184:7048",
  },

  // Сервисный API-ключ для service-to-service вызовов (без SQLite)
  serviceApiKey: process.env.SERVICE_API_KEY || "",
};
