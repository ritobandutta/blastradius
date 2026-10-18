import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev the UI talks to the API through /api (proxied to the FastAPI port, prefix stripped).
// In the Docker image FastAPI serves the built UI itself, so the UI calls the API directly.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.API_URL || "http://localhost:8010",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ""),
      },
    },
  },
});
