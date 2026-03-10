/**
 * aes-gcm.test.ts — Unit, Security & Performance tests for AES-256-GCM
 *
 * ══════════════════════════════════════════════════════════════════
 * Coverage :
 *  ── Functional ──────────────────────────────────────────────────
 *  - aesGcmEncrypt() : produit { ciphertext, nonce } non-vides
 *  - aesGcmDecrypt() : round-trip plaintext → cipher → plaintext
 *  - Nonce 12 bytes  : généré aléatoirement à chaque appel
 *
 *  ── Correctness ─────────────────────────────────────────────────
 *  - Round-trip sur strings UTF-8, Unicode, vide, JSON, binaire
 *  - Deux chiffrements du même plaintext → ciphertexts différents (nonce unique)
 *  - Déterminisme : même ciphertext+nonce+key → même plaintext
 *
 *  ── Security / Pentest ──────────────────────────────────────────
 *  - [PENTEST] Ciphertext 1 bit flippé → decrypt throw (tag GCM invalide)
 *  - [PENTEST] Nonce différent → decrypt throw
 *  - [PENTEST] Clé différente → decrypt throw
 *  - [PENTEST] Tag GCM tronqué → decrypt throw
 *  - [PENTEST] Nonce réutilisé avec même clé → ciphertexts différents
 *    (chaque appel à encrypt génère un nonce frais)
 *  - [PENTEST] Plaintext vide → encrypt + decrypt round-trip OK
 *  - [PENTEST] Très long message (1 MB) → OK
 *
 *  ── Input Validation ────────────────────────────────────────────
 *  - Clé de mauvaise longueur → throw
 *  - Base64 invalide → throw
 *
 *  ── KPIs ────────────────────────────────────────────────────────
 *  - aesGcmEncrypt < 2 ms (message standard < 4 KB)
 *  - aesGcmDecrypt < 2 ms (message standard < 4 KB)
 * ══════════════════════════════════════════════════════════════════
 */

import { describe, it, expect } from "vitest";
import { aesGcmEncrypt, aesGcmDecrypt } from "../aes-gcm";
import { toBase64, fromBase64 } from "../kem";

// ── Helpers ────────────────────────────────────────────────────────────────

function randomKey(): string {
  return toBase64(crypto.getRandomValues(new Uint8Array(32)));
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
// 1. aesGcmEncrypt — Functional
// ══════════════════════════════════════════════════════════════════════════

describe("aesGcmEncrypt — functional", () => {
  it("retourne { ciphertext, nonce } non-vides", async () => {
    const { ciphertext, nonce } = await aesGcmEncrypt("hello", randomKey());
    expect(ciphertext.length).toBeGreaterThan(0);
    expect(nonce.length).toBeGreaterThan(0);
  });

  it("nonce = 12 bytes", async () => {
    const { nonce } = await aesGcmEncrypt("test nonce size", randomKey());
    expect(fromBase64(nonce).length).toBe(12);
  });

  it("deux chiffrements du même plaintext → ciphertexts différents (nonces uniques)", async () => {
    const key = randomKey();
    const r1  = await aesGcmEncrypt("same plaintext", key);
    const r2  = await aesGcmEncrypt("same plaintext", key);
    expect(r1.ciphertext).not.toBe(r2.ciphertext);
    expect(r1.nonce).not.toBe(r2.nonce);
  });

  it("ciphertext ≠ plaintext en clair (le message est bien chiffré)", async () => {
    const plaintext = "visible plaintext should not appear";
    const { ciphertext } = await aesGcmEncrypt(plaintext, randomKey());
    expect(ciphertext).not.toContain(plaintext);
    expect(atob(ciphertext)).not.toContain(plaintext);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 2. Round-trip — Correctness
// ══════════════════════════════════════════════════════════════════════════

describe("encrypt + decrypt round-trip", () => {
  const cases = [
    { label: "string ASCII simple",   text: "Hello, AegisQuantum!" },
    { label: "string Unicode",        text: "Héllo wörld 🔐 — post-quantum" },
    { label: "string vide",           text: "" },
    { label: "string JSON",           text: JSON.stringify({ uid: "abc", key: "xyz", ts: 1234567890 }) },
    { label: "longue string (2048c)", text: "A".repeat(2048) },
  ];

  for (const { label, text } of cases) {
    it(`round-trip OK : ${label}`, async () => {
      const key                   = randomKey();
      const { ciphertext, nonce } = await aesGcmEncrypt(text, key);
      const decrypted             = await aesGcmDecrypt(ciphertext, nonce, key);
      expect(decrypted).toBe(text);
    });
  }

  it("round-trip binaire (Base64 de bytes aléatoires)", async () => {
    const key       = randomKey();
    const binary    = toBase64(crypto.getRandomValues(new Uint8Array(256)));
    const { ciphertext, nonce } = await aesGcmEncrypt(binary, key);
    expect(await aesGcmDecrypt(ciphertext, nonce, key)).toBe(binary);
  });

  it("déterminisme : même ciphertext+nonce+key → même plaintext", async () => {
    const key = randomKey();
    const { ciphertext, nonce } = await aesGcmEncrypt("deterministic", key);
    const d1 = await aesGcmDecrypt(ciphertext, nonce, key);
    const d2 = await aesGcmDecrypt(ciphertext, nonce, key);
    expect(d1).toBe(d2);
    expect(d1).toBe("deterministic");
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 3. Security / Pentests
// ══════════════════════════════════════════════════════════════════════════

describe("aesGcmDecrypt — [PENTEST] sécurité", () => {
  it("[PENTEST] 1 bit flippé dans ciphertext → throw (tag GCM invalide)", async () => {
    const key = randomKey();
    const { ciphertext, nonce } = await aesGcmEncrypt("tamper test", key);

    // Flipper le premier byte du ciphertext
    const ctBytes    = fromBase64(ciphertext);
    ctBytes[0]      ^= 0x01;
    const tamperedCT = toBase64(ctBytes);

    await expect(aesGcmDecrypt(tamperedCT, nonce, key)).rejects.toThrow();
  });

  it("[PENTEST] nonce différent → throw", async () => {
    const key = randomKey();
    const { ciphertext } = await aesGcmEncrypt("nonce swap", key);
    const wrongNonce = toBase64(crypto.getRandomValues(new Uint8Array(12)));
    await expect(aesGcmDecrypt(ciphertext, wrongNonce, key)).rejects.toThrow();
  });

  it("[PENTEST] clé différente → throw (tag GCM invalide)", async () => {
    const key1 = randomKey();
    const key2 = randomKey();
    const { ciphertext, nonce } = await aesGcmEncrypt("wrong key", key1);
    await expect(aesGcmDecrypt(ciphertext, nonce, key2)).rejects.toThrow();
  });

  it("[PENTEST] ciphertext tronqué (sans tag GCM) → throw", async () => {
    const key = randomKey();
    const { ciphertext, nonce } = await aesGcmEncrypt("truncation test", key);

    // Tronquer les 16 derniers bytes (tag GCM)
    const ctBytes   = fromBase64(ciphertext);
    const truncated = toBase64(ctBytes.slice(0, -16));

    await expect(aesGcmDecrypt(truncated, nonce, key)).rejects.toThrow();
  });

  it("[PENTEST] ciphertext vide → throw", async () => {
    const key   = randomKey();
    const nonce = toBase64(crypto.getRandomValues(new Uint8Array(12)));
    await expect(aesGcmDecrypt("", nonce, key)).rejects.toThrow();
  });

  it("[PENTEST] chiffrement d'un plaintext vide → decrypt round-trip OK", async () => {
    const key                   = randomKey();
    const { ciphertext, nonce } = await aesGcmEncrypt("", key);
    expect(await aesGcmDecrypt(ciphertext, nonce, key)).toBe("");
  });

  it("[PENTEST] chaque appel à encrypt génère un nonce frais (pas de réutilisation)", async () => {
    const key    = randomKey();
    const nonces = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const { nonce } = await aesGcmEncrypt("nonce uniqueness", key);
      nonces.add(nonce);
    }
    // Tous les 50 nonces doivent être distincts
    expect(nonces.size).toBe(50);
  });

  it("[PENTEST] très grand message (1 MB) → round-trip OK", async () => {
    const key       = randomKey();
    const large     = "x".repeat(1_000_000);
    const { ciphertext, nonce } = await aesGcmEncrypt(large, key);
    expect(await aesGcmDecrypt(ciphertext, nonce, key)).toBe(large);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 4. Input Validation
// ══════════════════════════════════════════════════════════════════════════

describe("Input Validation", () => {
  it("aesGcmEncrypt : clé de 16 bytes (128 bits) → throw (on attend 256 bits)", async () => {
    const shortKey = toBase64(new Uint8Array(16));
    await expect(aesGcmEncrypt("test", shortKey)).rejects.toThrow();
  });

  it("aesGcmEncrypt : clé de 24 bytes (192 bits) → throw (on attend 256 bits)", async () => {
    const key192 = toBase64(new Uint8Array(24));
    await expect(aesGcmEncrypt("test", key192)).rejects.toThrow();
  });

  it("aesGcmEncrypt : clé Base64 invalide → throw", async () => {
    await expect(aesGcmEncrypt("test", "not!!valid-base64")).rejects.toThrow();
  });

  it("aesGcmDecrypt : ciphertext Base64 invalide → throw", async () => {
    const key   = randomKey();
    const nonce = toBase64(crypto.getRandomValues(new Uint8Array(12)));
    await expect(aesGcmDecrypt("not!!base64", nonce, key)).rejects.toThrow();
  });

  it("aesGcmDecrypt : nonce Base64 invalide → throw", async () => {
    const key = randomKey();
    const { ciphertext } = await aesGcmEncrypt("test", key);
    await expect(aesGcmDecrypt(ciphertext, "not!!base64", key)).rejects.toThrow();
  });

  it("aesGcmDecrypt : nonce de mauvaise longueur → throw", async () => {
    const key              = randomKey();
    const { ciphertext }   = await aesGcmEncrypt("test", key);
    const wrongNonce       = toBase64(new Uint8Array(8)); // 8 bytes au lieu de 12
    await expect(aesGcmDecrypt(ciphertext, wrongNonce, key)).rejects.toThrow();
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 5. KPIs
// ══════════════════════════════════════════════════════════════════════════

describe("Performance KPIs — AES-256-GCM", () => {
  const shortMsg = "AegisQuantum encrypted message — typical size";

  it("[KPI] aesGcmEncrypt < 2 ms (message < 4 KB)", async () => {
    const key = randomKey();
    const avg = await measureMs(() => aesGcmEncrypt(shortMsg, key));
    console.log(`[KPI] aesGcmEncrypt avg: ${avg.toFixed(2)} ms`);
    expect(avg).toBeLessThan(2);
  });

  it("[KPI] aesGcmDecrypt < 2 ms (message < 4 KB)", async () => {
    const key                   = randomKey();
    const { ciphertext, nonce } = await aesGcmEncrypt(shortMsg, key);
    const avg = await measureMs(() => aesGcmDecrypt(ciphertext, nonce, key));
    console.log(`[KPI] aesGcmDecrypt avg: ${avg.toFixed(2)} ms`);
    expect(avg).toBeLessThan(2);
  });
});
