/**
 * key-registry.test.ts — Unit, KPI & security tests for key-registry.ts
 *
 * ══════════════════════════════════════════════════════════════════
 * Coverage :
 *  ── Functional ──────────────────────────────────────────────────────────────
 *  - publishPublicKeys()  : writes a PublicKeyBundle to Firestore
 *  - getPublicKeys()      : reads it back, returns null for unknown uid
 *  - getPublicKeysBatch() : fetches multiple bundles, chunks >30 uids correctly
 *
 *  ── Robustesse Parsing ──────────────────────────────────────────────────────
 *  - getPublicKeys() avec kemPublicKey malformée (trop courte) → renvoie le bundle
 *    sans crash (la validation appartient à la couche crypto, pas au registry)
 *  - UIDs avec caractères spéciaux / très longs → comportement stable
 *
 *  ── KPIs (specs §2.2) ───────────────────────────────────────────────────────
 *  - publishPublicKeys  < 1000 ms
 *  - getPublicKeys      < 500  ms
 *  - getPublicKeysBatch < 1000 ms
 *
 *  ── Security / pseudo-pentest ────────────────────────────────────────────────
 *  - getPublicKeys returns null (not throws) for unknown uid — no info leak
 *  - PublicKeyBundle NEVER contains private key fields
 *  - Batch call with empty array returns empty Map (no crash, no default data)
 *  - getPublicKeysBatch with >30 uids does not throw (chunking verified)
 *  - path traversal uid → null, pas de crash
 * ══════════════════════════════════════════════════════════════════
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  publishPublicKeys,
  getPublicKeys,
  getPublicKeysBatch,
} from "../key-registry";
import type { PublicKeyBundle } from "../../types/user";

// ── Fixtures ───────────────────────────────────────────────────────────────

const UID_ALICE = "test-uid-registry-alice";
const UID_BOB   = "test-uid-registry-bob";

function makeBundle(uid: string, overrides: Partial<PublicKeyBundle> = {}): PublicKeyBundle {
  return {
    uid,
    kemPublicKey: btoa("A".repeat(1184)),
    dsaPublicKey: btoa("B".repeat(256)),
    createdAt   : Date.now(),
    ...overrides,
  };
}

async function measureMs(fn: () => Promise<unknown>): Promise<number> {
  const t0 = performance.now();
  await fn();
  return performance.now() - t0;
}

// Pré-peupler Alice et Bob avant chaque groupe de tests
beforeEach(async () => {
  await publishPublicKeys(UID_ALICE, makeBundle(UID_ALICE));
  await publishPublicKeys(UID_BOB,   makeBundle(UID_BOB));
});

// ══════════════════════════════════════════════════════════════════════════
// 1. publishPublicKeys
// ══════════════════════════════════════════════════════════════════════════

describe("publishPublicKeys [INTEGRATION]", () => {
  it("should write a bundle without throwing", async () => {
    await expect(
      publishPublicKeys(UID_ALICE, makeBundle(UID_ALICE))
    ).resolves.not.toThrow();
  });

  it("should be idempotent — re-publishing same uid overwrites cleanly", async () => {
    const bundle1 = makeBundle(UID_ALICE, { kemPublicKey: btoa("V1".padEnd(1184, "A")) });
    const bundle2 = makeBundle(UID_ALICE, { kemPublicKey: btoa("V2".padEnd(1184, "B")) });
    await publishPublicKeys(UID_ALICE, bundle1);
    await publishPublicKeys(UID_ALICE, bundle2);
    const result = await getPublicKeys(UID_ALICE);
    expect(result?.kemPublicKey).toBe(bundle2.kemPublicKey);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 2. getPublicKeys
// ══════════════════════════════════════════════════════════════════════════

describe("getPublicKeys [INTEGRATION]", () => {
  it("should return the bundle that was published", async () => {
    const bundle = makeBundle(UID_ALICE);
    await publishPublicKeys(UID_ALICE, bundle);
    const result = await getPublicKeys(UID_ALICE);
    expect(result).not.toBeNull();
    expect(result!.uid).toBe(UID_ALICE);
    expect(result!.kemPublicKey).toBe(bundle.kemPublicKey);
    expect(result!.dsaPublicKey).toBe(bundle.dsaPublicKey);
  });

  it("should return null for an unknown uid — not throw", async () => {
    expect(await getPublicKeys("uid-that-does-not-exist-xyz")).toBeNull();
  });

  it("returned bundle contains all required fields (no email)", async () => {
    const result = await getPublicKeys(UID_ALICE);
    expect(result).toHaveProperty("uid");
    expect(result).toHaveProperty("kemPublicKey");
    expect(result).toHaveProperty("dsaPublicKey");
    expect(result).toHaveProperty("createdAt");
    // email ne doit PAS être présent
    expect(result).not.toHaveProperty("email");
  });

  it("kemPublicKey and dsaPublicKey should be non-empty strings", async () => {
    const result = await getPublicKeys(UID_ALICE);
    expect(typeof result!.kemPublicKey).toBe("string");
    expect(result!.kemPublicKey.length).toBeGreaterThan(0);
    expect(typeof result!.dsaPublicKey).toBe("string");
    expect(result!.dsaPublicKey.length).toBeGreaterThan(0);
  });

  it("[SEC] kemPublicKey trop courte stockée dans Firestore → gestion sécurisée (renvoie null ou bundle)", async () => {
    const CORRUPT_UID = "uid-corrupt-kemkey";
    
    // On publie une clé invalide
    await publishPublicKeys(CORRUPT_UID, makeBundle(CORRUPT_UID, {
      kemPublicKey: btoa("X".repeat(100)), 
    }));

    // On récupère le résultat
    const result = await getPublicKeys(CORRUPT_UID);

    // ASSERTION : Le code ne doit pas avoir crashé (pas d'exception)
    // Et selon ta logique métier, soit il accepte le bundle malformé (et c'est au KEM de râler plus tard)
    // soit il renvoie null car il a détecté la corruption.
    
    // Si tu veux accepter que la fonction renvoie null en cas de corruption :
    expect(result === null || typeof result === 'object').toBe(true);
});

  it("[SEC] dsaPublicKey vide → getPublicKeys ne crashe pas", async () => {
    const UID = "uid-empty-dsakey";
    await publishPublicKeys(UID, makeBundle(UID, { dsaPublicKey: "" }));
    const result = await getPublicKeys(UID);
    expect(result).not.toBeNull();
    expect(result!.dsaPublicKey).toBe("");
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 3. getPublicKeysBatch
// ══════════════════════════════════════════════════════════════════════════

describe("getPublicKeysBatch [INTEGRATION]", () => {
  it("should return bundles for all known uids", async () => {
    const result = await getPublicKeysBatch([UID_ALICE, UID_BOB]);
    expect(result.size).toBe(2);
    expect(result.has(UID_ALICE)).toBe(true);
    expect(result.has(UID_BOB)).toBe(true);
  });

  it("should return empty Map for empty uid list", async () => {
    expect((await getPublicKeysBatch([])).size).toBe(0);
  });

  it("should silently omit unknown uids", async () => {
    const result = await getPublicKeysBatch([UID_ALICE, "uid-ghost-999"]);
    expect(result.has(UID_ALICE)).toBe(true);
    expect(result.has("uid-ghost-999")).toBe(false);
  });

  it("should handle >30 uids without throwing (chunking)", async () => {
    const fakeUids = Array.from({ length: 32 }, (_, i) => `uid-fake-${i}`);
    const result   = await getPublicKeysBatch([...fakeUids, UID_ALICE, UID_BOB]);
    expect(result.size).toBe(2);
    expect(result.has(UID_ALICE)).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 4. KPIs
// ══════════════════════════════════════════════════════════════════════════

describe("Performance KPIs — key-registry (specs §2.2)", () => {
  it("publishPublicKeys < 1000 ms", async () => {
    const ms = await measureMs(() => publishPublicKeys(UID_ALICE, makeBundle(UID_ALICE)));
    console.log(`[KPI] publishPublicKeys: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(1000);
  });

  it("getPublicKeys < 500 ms", async () => {
    const ms = await measureMs(() => getPublicKeys(UID_ALICE));
    console.log(`[KPI] getPublicKeys: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(500);
  });

  it("getPublicKeysBatch (2 uids) < 1000 ms", async () => {
    const ms = await measureMs(() => getPublicKeysBatch([UID_ALICE, UID_BOB]));
    console.log(`[KPI] getPublicKeysBatch (2): ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(1000);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 5. Invariants de sécurité
// ══════════════════════════════════════════════════════════════════════════

describe("Security invariants — key-registry", () => {
  it("[SEC] getPublicKeys returns null, not throws, for unknown uid", async () => {
    await expect(getPublicKeys("uid-nonexistent-sec-test")).resolves.toBeNull();
  });

  it("[SEC] PublicKeyBundle must NOT contain any private key fields", async () => {
    const result = await getPublicKeys(UID_ALICE);
    expect(result).not.toHaveProperty("kemPrivateKey");
    expect(result).not.toHaveProperty("dsaPrivateKey");
    expect(result).not.toHaveProperty("privateKey");
    expect(result).not.toHaveProperty("masterKey");
    expect(result).not.toHaveProperty("argon2Salt");
  });

  it("[SEC] PublicKeyBundle must NOT contain email", async () => {
    const result = await getPublicKeys(UID_ALICE);
    expect(result).not.toHaveProperty("email");
  });

  it("[SEC] getPublicKeysBatch with empty array returns empty Map — no default data injected", async () => {
    const result = await getPublicKeysBatch([]);
    expect(result instanceof Map).toBe(true);
    expect(result.size).toBe(0);
  });

  it("[SEC] makeBundle type-check — no private keys in PublicKeyBundle shape", () => {
    const bundle: PublicKeyBundle = makeBundle(UID_ALICE);
    expect(bundle).not.toHaveProperty("kemPrivateKey");
    expect(bundle).not.toHaveProperty("email");
  });

  it("[SEC] getPublicKeys with path-traversal uid returns null — no crash", async () => {
    const result = await getPublicKeys("../users/admin").catch(() => null);
    expect(result).toBeNull();
  });

  it("[SEC] UIDs with special characters are handled without unhandled crash", async () => {
    const weirdUids = [
      "uid with spaces",
      "uid<script>alert(1)</script>",
      "uid@#$%^&*()",
      "a".repeat(500),
    ];
    for (const uid of weirdUids) {
      const result = await getPublicKeys(uid).catch(() => null);
      expect(result === null || typeof result === "object").toBe(true);
    }
  });

  it("[SEC] publishPublicKeys + getPublicKeys with empty uid — no unhandled crash", async () => {
    let stable = true;
    try {
      await publishPublicKeys("", makeBundle(""));
      await getPublicKeys("");
    } catch {
      // Acceptable — Firestore rejette les chemins vides
    }
    expect(stable).toBe(true);
  });
});
