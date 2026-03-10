/**
 * logger.ts — Envoie les logs vers admin/logs/app.log via le plugin Vite dev
 *
 * En dev  : POST /api/log → vite-plugin-logger.ts → admin/logs/app.log
 * En prod : les appels échouent silencieusement (pas de endpoint)
 *
 * Intercepte : console.log / console.error / console.warn + erreurs non gérées
 */

const ENDPOINT = "/api/log";
const ENABLED  = import.meta.env.DEV;  // actif uniquement en dev

function send(level: "log" | "error" | "warn", args: unknown[]): void {
  if (!ENABLED) return;

  const message = args.map((a) => {
    if (typeof a === "string") return a;
    try { return JSON.stringify(a); } catch { return String(a); }
  }).join(" ");

  const payload = JSON.stringify({
    level,
    message,
    timestamp: new Date().toISOString(),
  });

  // fire-and-forget — ne jamais bloquer l'app pour les logs
  fetch(ENDPOINT, {
    method : "POST",
    headers: { "Content-Type": "application/json" },
    body   : payload,
  }).catch(() => { /* silencieux en prod */ });
}

// ── Intercepter console ───────────────────────────────────────────────────

const _origLog   = console.log.bind(console);
const _origError = console.error.bind(console);
const _origWarn  = console.warn.bind(console);

console.log = (...args: unknown[]) => {
  _origLog(...args);
  send("log", args);
};
console.error = (...args: unknown[]) => {
  _origError(...args);
  send("error", args);
};
console.warn = (...args: unknown[]) => {
  _origWarn(...args);
  send("warn", args);
};

// ── Erreurs non gérées ────────────────────────────────────────────────────

window.addEventListener("error", (e) => {
  send("error", [`[uncaught] ${e.message} — ${e.filename}:${e.lineno}`]);
});

window.addEventListener("unhandledrejection", (e) => {
  const msg = e.reason instanceof Error ? e.reason.message : String(e.reason);
  send("error", [`[unhandled promise] ${msg}`]);
});

export {};
