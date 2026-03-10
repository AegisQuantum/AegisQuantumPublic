import { defineConfig } from "vite";
import topLevelAwait  from "vite-plugin-top-level-await";
import loggerPlugin   from "./vite-plugin-logger";
import { resolve }    from "path";
import fs             from "fs";
import path           from "path";

/**
 * Plugin : copie les fichiers dist/*.min.js de @openforge-sh/liboqs
 * dans public/dist/ avant chaque build/dev.
 * En prod, Vite copie public/dist/ → dist/dist/ automatiquement.
 */
function copyLiboqsPlugin() {
  const copyFiles = () => {
    const src = resolve(__dirname, "node_modules/@openforge-sh/liboqs/dist");
    const dst = resolve(__dirname, "public/dist");
    if (!fs.existsSync(dst)) fs.mkdirSync(dst, { recursive: true });
    const files = fs.readdirSync(src).filter((f: string) => f.endsWith(".min.js"));
    for (const file of files) {
      fs.copyFileSync(resolve(src, file), resolve(dst, file));
    }
    console.log(`[liboqs] Copied ${files.length} files → public/dist/`);
  };

  return {
    name: "copy-liboqs-dist",
    buildStart: copyFiles,
    configureServer() { copyFiles(); },
  };
}

/**
 * Plugin dev uniquement : intercepte /dist/*.min.js EN PREMIER
 * avant que le middleware Vite ne puisse rejeter la requête.
 *
 * Vite refuse de servir public/*.js via import() dynamique en dev.
 * On contourne en servant nous-mêmes le fichier depuis node_modules
 * via un middleware inséré en tête de pile (configureServer retourne
 * une fonction → celle-ci est appelée AVANT les middlewares Vite internes).
 */
function liboqsDevPlugin() {
  return {
    name: "liboqs-dev",
    apply: "serve" as const,

    configureServer(server: any) {
      // Retourner une fonction = middleware inséré AVANT les middlewares Vite
      return () => {
        server.middlewares.use((req: any, res: any, next: any) => {
          const url: string = req.url?.split("?")[0] ?? "";
          const m = url.match(/^\/dist\/([\w-]+\.min\.js)$/);
          if (!m) return next();

          const filepath = path.resolve(
            __dirname,
            "node_modules/@openforge-sh/liboqs/dist",
            m[1]
          );

          if (!fs.existsSync(filepath)) return next();

          res.setHeader("Content-Type", "application/javascript; charset=utf-8");
          res.setHeader("Cache-Control", "no-cache");
          fs.createReadStream(filepath).pipe(res);
        });
      };
    },
  };
}

export default defineConfig({
  plugins: [
    topLevelAwait(),
    liboqsDevPlugin(),
    copyLiboqsPlugin(),
    loggerPlugin(),
  ],
  build: {
    target: "es2022",
    rollupOptions: {
      external: ["argon2-browser"],
      output: {
        globals: { "argon2-browser": "argon2" },
      },
    },
  },
  optimizeDeps: {
    exclude: ["@openforge-sh/liboqs", "argon2-browser"],
  },
  server: {
    hmr: { overlay: false },
  },
  test: {
    globals: true,
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      include: ["src/crypto/**/*.ts", "src/services/**/*.ts"],
      exclude: ["src/**/__tests__/**"],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80,
      },
    },
  },
});
