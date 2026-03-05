import { defineConfig } from "vite";

export default defineConfig({
  build: {
    target: "es2020",
  },
  optimizeDeps: {
    exclude: ["@openforge-sh/liboqs"],
  },
  test: {
    globals: true,
    environment: "node",
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      include: ["src/crypto/**/*.ts"],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80,
      },
    },
  },
} as Parameters<typeof defineConfig>[0]);
