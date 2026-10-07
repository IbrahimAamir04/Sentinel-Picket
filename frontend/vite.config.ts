import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "VITE_");
  // The browser talks to the SPA origin only; /api is forwarded to Django. Session and CSRF cookies stay same-origin.
  const proxy = { "/api": { target: env.VITE_PROXY_TARGET || "http://localhost:8000" } };
  return {
    plugins: [react(), tailwindcss()],
    // A compile-time constant, so the bundler removes the unused data source (demo data never ships in API builds).
    define: { __DATA_MODE__: JSON.stringify(env.VITE_DATA_MODE === "demo" ? "demo" : "api") },
    server: { port: 5173, proxy },
    preview: { port: 4173, proxy },
  };
});
