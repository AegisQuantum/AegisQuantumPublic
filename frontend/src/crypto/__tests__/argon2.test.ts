/**
 * argon2.test.ts — Unit, Security & Performance tests for Argon2id
 *
 * ══════════════════════════════════════════════════════════════════
 * Coverage :
 *  ── Functional ──────────────────────────────────────────────────
 *  - argon2Derive() sans salt → génère un salt aléatoire + retourne la clé
 *  - argon2Derive() avec salt → réutilise le salt, retourne la même clé
 *  - Taille clé = 32 bytes (Base64)
 *  - Taille salt = 16 bytes (Base64)
 *
 *  ── Correctness ─────────────────────────────────────────────────
 *  - Déterminisme : même (password, salt) → même clé
 *  - Deux mots de passe différents → deux clés différentes
 *  - Deux salts différents + même password → deux clés différentes
 *  - Salt aléatoire à chaque inscription (pas de collision)
 *
 *  ── Security / Pentest ──────────────────────────────────────────
 *  - [PENTEST] Clé ≠ password en clair (HKDF n'est pas identity)
 *  - [PENTEST] Clé non-triviale (pas tout-zéros) même pour password = "a"
 *  - [PENTEST] Password similaires → clés totalement différentes (avalanche)
 *  - [PENTEST] Salt tout-zéros → clé produite (edge case RFC)
 *  - [PENTEST] Mot de passe vide → clé produite (Argon2 l'accepte)
 *  - [PENTEST] Très long mot de passe → pas de crash, clé correcte
 *
 *  ── KPIs ────────────────────────────────────────────────────────
 *  - argon2Derive < 5000 ms (Argon2id est intentionnellement lent)
 *  - Le salt retourné est différent à chaque appel sans salt
 * ══════════════════════════════════════════════════════════════════
 *
 * ⚠️  Argon2id avec m=65536 (64 MB) prend ~500 ms par dérivation.
 *     Ces tests ont donc un timeout plus long que les autres modules.
 */

import { describe, it, expect } from "vitest";
import { argon2Derive } from "../argon2";
import { fromBase64 } from "../kem";

// ── Helpers ────────────────────────────────────────────────────────────────


// ══════════════════════════════════════════════════════════════════════════
// 1. Functional
// ══════════════════════════════════════════════════════════════════════════

describe("argon2Derive — functional", () => {
  it("retourne { key, salt } non-vides sans salt en entrée", async () => {
    const { key, salt } = await argon2Derive("password123");
    expect(key.length).toBeGreaterThan(0);
    expect(salt.length).toBeGreaterThan(0);
  });

  it("clé = 32 bytes (256 bits)", async () => {
    const { key } = await argon2Derive("test-key-length");
    expect(fromBase64(key).length).toBe(32);
  });

  it("salt généré automatiquement = 16 bytes", async () => {
    const { salt } = await argon2Derive("test-salt-length");
    expect(fromBase64(salt).length).toBe(16);
  });

  it("salt retourné en entrée doit matcher le salt passé", async () => {
    const { salt: generatedSalt } = await argon2Derive("first-call");
    const { salt: returnedSalt } = await argon2Derive("second-call", generatedSalt);
    expect(returnedSalt).toBe(generatedSalt);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 2. Correctness — Déterminisme
// ══════════════════════════════════════════════════════════════════════════

describe("argon2Derive — correctness", () => {
  it("déterministe : même (password, salt) → même clé", async () => {
    const { key: k1, salt } = await argon2Derive("my-password");
    const { key: k2 }       = await argon2Derive("my-password", salt);
    expect(k1).toBe(k2);
  });

  it("deux mots de passe différents + même salt → deux clés différentes", async () => {
    const { key: k1, salt } = await argon2Derive("password-A");
    const { key: k2 }       = await argon2Derive("password-B", salt);
    expect(k1).not.toBe(k2);
  });

  it("même password + deux salts différents → deux clés différentes", async () => {
    const { key: k1, salt: s1 } = await argon2Derive("same-password");
    const { key: k2, salt: s2 } = await argon2Derive("same-password");
    expect(s1).not.toBe(s2);
    expect(k1).not.toBe(k2);
  });

  it("salt aléatoire à chaque inscription — pas de collision sur 5 appels", async () => {
    const salts = new Set<string>();
    for (let i = 0; i < 5; i++) {
      const { salt } = await argon2Derive(`user-${i}`);
      salts.add(salt);
    }
    expect(salts.size).toBe(5);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 3. Security / Pentests
// ══════════════════════════════════════════════════════════════════════════

describe("argon2Derive — [PENTEST] sécurité", () => {
  it("[PENTEST] clé ≠ password en clair (pas d'identity function)", async () => {
    const pw      = "my-plaintext-password";
    const { key } = await argon2Derive(pw);
    expect(key).not.toContain(pw);
    expect(atob(key)).not.toContain(pw);
  });

  it("[PENTEST] clé non-triviale pour password = 'a' (pas tout-zéros)", async () => {
    const { key }  = await argon2Derive("a");
    const keyBytes = fromBase64(key);
    expect(keyBytes.every((b) => b === 0)).toBe(false);
  });

  it("[PENTEST] passwords similaires → clés très différentes (effet avalanche)", async () => {
    const { key: k1, salt } = await argon2Derive("Password123!");
    const { key: k2 }       = await argon2Derive("Password123 ", salt);
    expect(k1).not.toBe(k2);
    const b1 = fromBase64(k1);
    const b2 = fromBase64(k2);
    const diffCount = b1.filter((b, i) => b !== b2[i]).length;
    expect(diffCount).toBeGreaterThan(10);
  });

  it("[PENTEST] salt tout-zéros (16 bytes) → clé produite sans erreur", async () => {
    const { toBase64 } = await import("../kem");
    const zeroSalt = toBase64(new Uint8Array(16).fill(0x00));
    const { key }  = await argon2Derive("test-zero-salt", zeroSalt);
    expect(fromBase64(key).length).toBe(32);
  });

  it("[PENTEST] mot de passe vide → clé produite (Argon2 l'accepte)", async () => {
    const { key } = await argon2Derive("");
    expect(fromBase64(key).length).toBe(32);
  });

  it("[PENTEST] très long mot de passe (1000 chars) → pas de crash, clé correcte", async () => {
    const longPw  = "x".repeat(1000);
    const { key } = await argon2Derive(longPw);
    expect(fromBase64(key).length).toBe(32);
  });

  it("[PENTEST] clé différente du salt (pas de fuite du salt dans la clé)", async () => {
    const { key, salt } = await argon2Derive("salt-leak-check");
    expect(key).not.toBe(salt);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 4. KPIs
// ══════════════════════════════════════════════════════════════════════════

describe("Performance KPIs — Argon2id", () => {
  it("[KPI] argon2Derive < 5000 ms en production (mock PBKDF2 rapide en tests)", async () => {
    const t0 = performance.now();
    await argon2Derive("kpi-benchmark-password");
    const ms = performance.now() - t0;
    console.log(`[KPI] argon2Derive (mock PBKDF2 en test): ${ms.toFixed(0)} ms`);
    // Mock PBKDF2 en tests → rapide. Seuil 5000 ms valide pour le vrai Argon2id en browser.
    expect(ms).toBeLessThan(5000);
  });
});
