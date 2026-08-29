import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  server: {
    // Development convenience: proxy API calls to a locally running agent.
    proxy: {
      "/api": {
        target: "http://127.0.0.1:7171",
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
  },
});
