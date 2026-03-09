import { defineConfig } from "vite";
import topLevelAwait  from "vite-plugin-top-level-await";
import loggerPlugin   from "./vite-plugin-logger";

export default defineConfig({
  plugins: [
    topLevelAwait(),
    loggerPlugin(),
  ],
  build: {
    target: "es2022",
    rollupOptions: {
      // argon2-browser ne peut pas être bundlé par Rollup (WASM non-standard + imports Node)
      // On l'exclut du bundle — il est chargé via <script> CDN dans index.html
      external: ["argon2-browser"],
      output: {
        globals: {
          "argon2-browser": "argon2",
        },
      },
    },
  },
  optimizeDeps: {
    exclude: ["@openforge-sh/liboqs", "argon2-browser"],
  },
  test: {
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
