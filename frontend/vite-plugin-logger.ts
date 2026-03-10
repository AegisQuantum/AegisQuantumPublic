/**
 * vite-plugin-logger.ts
 *
 * Plugin Vite dev-only qui expose un endpoint POST /api/log.
 * Le frontend envoie ses logs ici → écrits dans admin/logs/app.log
 *
 * Actif UNIQUEMENT en mode dev (npm run dev).
 * En production le endpoint n'existe pas — les appels échouent silencieusement.
 */

import type { Plugin } from "vite";
import { appendFileSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const LOG_DIR   = join(__dirname, "../../admin/logs");
const LOG_FILE  = join(LOG_DIR, "app.log");

function ensureLogDir() {
  try { mkdirSync(LOG_DIR, { recursive: true }); } catch {}
}

function writeLine(line: string) {
  try {
    ensureLogDir();
    appendFileSync(LOG_FILE, line + "\n", "utf8");
  } catch (e) {
    console.error("[vite-plugin-logger] write failed:", e);
  }
}

export default function loggerPlugin(): Plugin {
  return {
    name: "aq-logger",
    apply: "serve",   // dev only

    configureServer(server) {
      server.middlewares.use("/api/log", (req, res) => {
        if (req.method !== "POST") {
          res.writeHead(405);
          res.end();
          return;
        }

        let body = "";
        req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
        req.on("end", () => {
          try {
            const { level, message, timestamp } = JSON.parse(body) as {
              level: string;
              message: string;
              timestamp: string;
            };
            const line = `[${timestamp}] [${level.toUpperCase().padEnd(5)}] ${message}`;
            writeLine(line);
          } catch {
            writeLine(`[PARSE ERROR] ${body}`);
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end('{"ok":true}');
        });
      });

      // Log de démarrage
      writeLine(`\n${"=".repeat(60)}`);
      writeLine(`[${new Date().toISOString()}] [START] Vite dev server started`);
      writeLine(`${"=".repeat(60)}`);
      console.log(`[AQ Logger] Logs → ${LOG_FILE}`);
    },
  };
}
