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
    // node pour les tests crypto (WASM), jsdom pour les tests services (IndexedDB + Firebase)
    environment: "node",
    environmentMatchGlobs: [
      ["src/services/__tests__/**", "jsdom"],
    ],
    // Setup : fake-indexeddb + mocks Firebase (auth + firestore)
    setupFiles: ["src/services/__tests__/setup.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      include: ["src/crypto/**/*.ts", "src/services/**/*.ts"],
      thresholds: {
        lines     : 80,
        functions : 80,
        branches  : 80,
        statements: 80,
      },
    },
  },
} as Parameters<typeof defineConfig>[0]);
