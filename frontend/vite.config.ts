import { defineConfig } from "vite";
import topLevelAwait  from "vite-plugin-top-level-await";
import loggerPlugin   from "./vite-plugin-logger";
import { resolve }    from "path";
import fs             from "fs";

/**
 * Plugin maison : copie les fichiers dist/*.min.js de @openforge-sh/liboqs
 * dans public/dist/ avant le build et en dev.
 *
 * Pourquoi : liboqs utilise import.meta.url + import() dynamique pour charger
 * ses implémentations WASM/JS (ml-kem-768.min.js, ml-dsa-65.min.js…).
 * Ces chemins sont résolus à la racine du domaine (/dist/…).
 * En production Firebase les fichiers doivent donc être dans dist/ du déployé,
 * ce que Vite garantit en les passant par public/.
 */
function copyLiboqsPlugin() {
  return {
    name: "copy-liboqs-dist",
    buildStart() {
      const src = resolve(
        __dirname,
        "node_modules/@openforge-sh/liboqs/dist"
      );
      const dst = resolve(__dirname, "public/dist");

      if (!fs.existsSync(dst)) fs.mkdirSync(dst, { recursive: true });

      const files = fs.readdirSync(src).filter(f => f.endsWith(".min.js"));
      for (const file of files) {
        fs.copyFileSync(resolve(src, file), resolve(dst, file));
      }
      console.log(`[liboqs] Copied ${files.length} files → public/dist/`);
    },
  };
}

export default defineConfig({
  plugins: [
    topLevelAwait(),
    loggerPlugin(),
    copyLiboqsPlugin(),
  ],
  build: {
    target: "es2022",
    rollupOptions: {
      // argon2-browser ne peut pas être bundlé par Rollup (WASM non-standard + imports Node)
      // Chargé via <script> CDN dans index.html
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
