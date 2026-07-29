import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// Backend runs on :7421 in dev. Tauri wraps this Vite server in production.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 1420,
    strictPort: true,
    proxy: {
      "/api": "http://127.0.0.1:7421",
      "/health": "http://127.0.0.1:7421",
      "/ws": {
        target: "ws://127.0.0.1:7421",
        ws: true,
      },
    },
  },
  build: {
    target: "es2022",
    sourcemap: true,
  },
  clearScreen: false,
});
