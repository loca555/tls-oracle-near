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
    contractId: process.env.TLS_ORACLE_CONTRACT || "",
  },

  oracle: {
    accountId: process.env.ORACLE_ACCOUNT_ID || "",
    privateKey: process.env.ORACLE_PRIVATE_KEY || "",
  },

  prover: {
    url: process.env.PROVER_URL || "http://127.0.0.1:7048",
  },
};
