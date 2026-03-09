/**
 * hkdf.test.ts — Unit, Security & Performance tests for HKDF-SHA256
 *
 * ══════════════════════════════════════════════════════════════════
 * Coverage :
 *  ── Functional ──────────────────────────────────────────────────
 *  - hkdfDerive()     : produit une clé de la bonne longueur
 *  - hkdfDerivePair() : produit deux clés distinctes
 *  - HKDF_INFO        : les info strings sont bien définies
 *
 *  ── Correctness ─────────────────────────────────────────────────
 *  - Déterminisme : même (secret, info) → même clé
 *  - Longueur personnalisée : 16, 32, 64 bytes
 *  - Deux info différentes → deux clés différentes (isolation de domaine)
 *  - Deux secrets différents → deux clés différentes
 *
 *  ── Security / Pentest ──────────────────────────────────────────
 *  - [PENTEST] 1 bit flippé dans le secret → clé totalement différente
 *  - [PENTEST] Secret tout-zéros → clé non-triviale (HKDF ne dégénère pas)
 *  - [PENTEST] Info vide → clé produite (RFC 5869 l'autorise)
 *  - [PENTEST] hkdfDerivePair : rootKey ≠ chainKey (pas de collision entre les deux)
 *  - Input validation : secret vide, secret non-Base64
 *
 *  ── KPIs ────────────────────────────────────────────────────────
 *  - hkdfDerive     < 2 ms
 *  - hkdfDerivePair < 5 ms
 * ══════════════════════════════════════════════════════════════════
 */

import { describe, it, expect } from "vitest";
import { hkdfDerive, hkdfDerivePair, HKDF_INFO } from "../hkdf";
import { toBase64, fromBase64 } from "../kem";

// ── Helpers ────────────────────────────────────────────────────────────────

function randomSecret(bytes = 32): string {
  return toBase64(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function measureMs(fn: () => Promise<unknown>, runs = 10): Promise<number> {
  const s: number[] = [];
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    await fn();
    s.push(performance.now() - t0);
  }
  return s.reduce((a, b) => a + b) / s.length;
}

// ══════════════════════════════════════════════════════════════════════════
// 1. HKDF_INFO constants
// ══════════════════════════════════════════════════════════════════════════

describe("HKDF_INFO", () => {
  it("MESSAGE_KEY est défini et non-vide", () => {
    expect(typeof HKDF_INFO.MESSAGE_KEY).toBe("string");
    expect(HKDF_INFO.MESSAGE_KEY.length).toBeGreaterThan(0);
  });
  it("RATCHET_ROOT est défini et non-vide", () => {
    expect(HKDF_INFO.RATCHET_ROOT.length).toBeGreaterThan(0);
  });
  it("RATCHET_CHAIN est défini et non-vide", () => {
    expect(HKDF_INFO.RATCHET_CHAIN.length).toBeGreaterThan(0);
  });
  it("les trois info strings sont toutes distinctes", () => {
    const infos = [HKDF_INFO.MESSAGE_KEY, HKDF_INFO.RATCHET_ROOT, HKDF_INFO.RATCHET_CHAIN];
    const unique = new Set(infos);
    expect(unique.size).toBe(3);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 2. hkdfDerive — Correctness
// ══════════════════════════════════════════════════════════════════════════

describe("hkdfDerive — correctness", () => {
  it("retourne une string Base64 non-vide", async () => {
    const key = await hkdfDerive(randomSecret(), HKDF_INFO.MESSAGE_KEY);
    expect(typeof key).toBe("string");
    expect(key.length).toBeGreaterThan(0);
  });

  it("retourne 32 bytes par défaut", async () => {
    const key = await hkdfDerive(randomSecret(), HKDF_INFO.MESSAGE_KEY);
    expect(fromBase64(key).length).toBe(32);
  });

  it("retourne 16 bytes si outputLength=16", async () => {
    const key = await hkdfDerive(randomSecret(), HKDF_INFO.MESSAGE_KEY, 16);
    expect(fromBase64(key).length).toBe(16);
  });

  it("retourne 64 bytes si outputLength=64", async () => {
    const key = await hkdfDerive(randomSecret(), HKDF_INFO.MESSAGE_KEY, 64);
    expect(fromBase64(key).length).toBe(64);
  });

  it("est déterministe : même (secret, info) → même clé", async () => {
    const secret = randomSecret();
    const k1 = await hkdfDerive(secret, HKDF_INFO.MESSAGE_KEY);
    const k2 = await hkdfDerive(secret, HKDF_INFO.MESSAGE_KEY);
    expect(k1).toBe(k2);
  });

  it("deux info différentes → deux clés différentes (isolation de domaine)", async () => {
    const secret = randomSecret();
    const kMsg    = await hkdfDerive(secret, HKDF_INFO.MESSAGE_KEY);
    const kRatchet= await hkdfDerive(secret, HKDF_INFO.RATCHET_ROOT);
    expect(kMsg).not.toBe(kRatchet);
  });

  it("deux secrets différents → deux clés différentes", async () => {
    const k1 = await hkdfDerive(randomSecret(), HKDF_INFO.MESSAGE_KEY);
    const k2 = await hkdfDerive(randomSecret(), HKDF_INFO.MESSAGE_KEY);
    expect(k1).not.toBe(k2);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 3. hkdfDerivePair — Correctness
// ══════════════════════════════════════════════════════════════════════════

describe("hkdfDerivePair — correctness", () => {
  it("retourne { rootKey, chainKey } non-vides", async () => {
    const { rootKey, chainKey } = await hkdfDerivePair(randomSecret());
    expect(rootKey.length).toBeGreaterThan(0);
    expect(chainKey.length).toBeGreaterThan(0);
  });

  it("rootKey et chainKey sont différentes", async () => {
    const { rootKey, chainKey } = await hkdfDerivePair(randomSecret());
    expect(rootKey).not.toBe(chainKey);
  });

  it("chacune fait 32 bytes", async () => {
    const { rootKey, chainKey } = await hkdfDerivePair(randomSecret());
    expect(fromBase64(rootKey).length).toBe(32);
    expect(fromBase64(chainKey).length).toBe(32);
  });

  it("est déterministe sur le même secret", async () => {
    const secret = randomSecret();
    const p1 = await hkdfDerivePair(secret);
    const p2 = await hkdfDerivePair(secret);
    expect(p1.rootKey).toBe(p2.rootKey);
    expect(p1.chainKey).toBe(p2.chainKey);
  });

  it("deux secrets différents → deux paires différentes", async () => {
    const p1 = await hkdfDerivePair(randomSecret());
    const p2 = await hkdfDerivePair(randomSecret());
    expect(p1.rootKey).not.toBe(p2.rootKey);
    expect(p1.chainKey).not.toBe(p2.chainKey);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 4. Security / Pentests
// ══════════════════════════════════════════════════════════════════════════

describe("hkdfDerive — [PENTEST] sécurité", () => {
  it("[PENTEST] 1 bit flippé dans le secret → clé totalement différente (avalanche)", async () => {
    const secretBytes = crypto.getRandomValues(new Uint8Array(32));
    const original    = toBase64(secretBytes);
    const flipped     = new Uint8Array(secretBytes);
    flipped[0] ^= 0x01;
    const flippedB64  = toBase64(flipped);

    const k1 = await hkdfDerive(original,   HKDF_INFO.MESSAGE_KEY);
    const k2 = await hkdfDerive(flippedB64, HKDF_INFO.MESSAGE_KEY);
    expect(k1).not.toBe(k2);
  });

  it("[PENTEST] secret tout-zéros → clé non-triviale (HKDF ne dégénère pas sur zéros)", async () => {
    const zeroSecret = toBase64(new Uint8Array(32).fill(0x00));
    const key        = await hkdfDerive(zeroSecret, HKDF_INFO.MESSAGE_KEY);
    const keyBytes   = fromBase64(key);
    // La clé ne doit pas être entièrement nulle
    const allZero = keyBytes.every((b) => b === 0);
    expect(allZero).toBe(false);
  });

  it("[PENTEST] info vide → clé produite sans erreur (RFC 5869 l'autorise)", async () => {
    const key = await hkdfDerive(randomSecret(), "");
    expect(fromBase64(key).length).toBe(32);
  });

  it("[PENTEST] hkdfDerivePair : rootKey ≠ chainKey sur 20 secrets aléatoires", async () => {
    for (let i = 0; i < 20; i++) {
      const { rootKey, chainKey } = await hkdfDerivePair(randomSecret());
      expect(rootKey).not.toBe(chainKey);
    }
  });

  it("[PENTEST] clé message différente pour deux contextes AegisQuantum", async () => {
    const secret = randomSecret();
    const k1 = await hkdfDerive(secret, "AegisQuantum-v1-message-key");
    const k2 = await hkdfDerive(secret, "AegisQuantum-v1-ratchet-root");
    expect(k1).not.toBe(k2);
  });
});

describe("hkdfDerive — Input Validation", () => {
  it("lève une erreur sur un secret Base64 malformé", async () => {
    await expect(hkdfDerive("not!!valid-base64", HKDF_INFO.MESSAGE_KEY)).rejects.toThrow();
  });

  it("lève une erreur sur un secret vide", async () => {
    await expect(hkdfDerive("", HKDF_INFO.MESSAGE_KEY)).rejects.toThrow();
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 5. KPIs
// ══════════════════════════════════════════════════════════════════════════

describe("Performance KPIs — HKDF-SHA256", () => {
  it("[KPI] hkdfDerive < 2 ms", async () => {
    const secret = randomSecret();
    const avg    = await measureMs(() => hkdfDerive(secret, HKDF_INFO.MESSAGE_KEY));
    console.log(`[KPI] hkdfDerive avg: ${avg.toFixed(2)} ms`);
    expect(avg).toBeLessThan(2);
  });

  it("[KPI] hkdfDerivePair < 5 ms", async () => {
    const secret = randomSecret();
    const avg    = await measureMs(() => hkdfDerivePair(secret));
    console.log(`[KPI] hkdfDerivePair avg: ${avg.toFixed(2)} ms`);
    expect(avg).toBeLessThan(5);
  });
});
