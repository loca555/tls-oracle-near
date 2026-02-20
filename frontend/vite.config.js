import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  define: {
    // near-api-js обращается к global (Node.js) — в браузере это globalThis
    global: "globalThis",
  },
  server: {
    port: 3001,
    proxy: {
      "/api/": {
        target: "http://localhost:4001",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
  },
});
