import { defineConfig } from "vite";

export default defineConfig({
  build: {
    target: "es2020",
  },
  optimizeDeps: {
    exclude: ["@openforge-sh/liboqs"],
  },
  test: {
    // Les environnements et setupFiles sont définis dans vitest.workspace.ts.
    // Ce bloc gère uniquement la config globale (coverage, reporter).
    globals: true,
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      include  : ["src/crypto/**/*.ts", "src/services/**/*.ts"],
      exclude  : ["src/**/__tests__/**"],
      thresholds: {
        lines     : 80,
        functions : 80,
        branches  : 80,
        statements: 80,
      },
    },
  },
} as Parameters<typeof defineConfig>[0]);
