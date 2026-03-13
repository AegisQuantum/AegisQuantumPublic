/**
 * key-store.test.ts — Unit, KPI & security tests for key-store.ts
 *
 * ══════════════════════════════════════════════════════════════════
 * Coverage :
 *  ── Functional ──────────────────────────────────────────────────────────────
 *  - storePrivateKeys()   : stores keys in IDB + loads into memory
 *  - unlockPrivateKeys()  : reads back from IDB into memory
 *  - getKemPrivateKey()   : returns correct value from memory
 *  - getDsaPrivateKey()   : returns correct value from memory
 *  - clearPrivateKeys()   : wipes in-memory store
 *  - deleteVault()        : removes IDB entry permanently
 *  - saveRatchetState()   : persists ratchet JSON to IDB
 *  - loadRatchetState()   : reads ratchet JSON back, null on first call
 *
 *  ── Nouveaux — Cycle de vie et Auth ─────────────────────────────────────────
 *  - [SESSION EXPIRY] Après clearPrivateKeys (simulant onAuthChange → null),
 *    les clés privées sont bien purgées de la RAM
 *  - [IDB FAILURE]   Si IDB renvoie undefined (vault corrompu/absent),
 *    unlockPrivateKeys throw proprement — pas de clé undefined chargée
 *  - [PERSISTENCE]   Le vault survit à clearPrivateKeys et se recharge via unlock
 *
 *  ── KPIs (specs §2.2) ───────────────────────────────────────────────────────
 *  - storePrivateKeys  < 50 ms
 *  - unlockPrivateKeys < 50 ms
 *  - getKemPrivateKey  < 1 ms  (synchronous memory read)
 *  - getDsaPrivateKey  < 1 ms  (synchronous memory read)
 *
 *  ── Security / pseudo-pentest ────────────────────────────────────────────────
 *  - getKemPrivateKey throws immediately if vault not loaded (no silent fail)
 *  - getDsaPrivateKey throws immediately if vault not loaded
 *  - clearPrivateKeys makes both getters throw (memory fully purged)
 *  - unlockPrivateKeys throws on missing vault (no fallback / no default keys)
 *  - keys from different UIDs are strictly isolated (no cross-uid leakage)
 *  - overwriting vault for same uid does not expose old keys after clearPrivateKeys
 *  - ratchet states are isolated per (uid, conversationId) — no cross-conv leakage
 *  - empty string uid is rejected gracefully
 * ══════════════════════════════════════════════════════════════════
 */

import { describe, it, expect, afterEach } from "vitest";
import {
  storePrivateKeys,
  unlockPrivateKeys,
  getKemPrivateKey,
  getDsaPrivateKey,
  clearPrivateKeys,
  deleteVault,
  saveRatchetState,
  loadRatchetState,
  type PrivateKeyBundle,
} from "../key-store";

// ── Helpers ────────────────────────────────────────────────────────────────

function makeBundle(overrides: Partial<PrivateKeyBundle> = {}): PrivateKeyBundle {
  return {
    kemPrivateKey: "kem-private-key-base64-alice",
    dsaPrivateKey: "dsa-private-key-base64-alice",
    masterKey    : "master-key-base64-32bytes=====",
    argon2Salt   : "argon2-salt-base64-16bytes===",
    ...overrides,
  };
}

async function measureMs(fn: () => Promise<unknown>): Promise<number> {
  const t0 = performance.now();
  await fn();
  return performance.now() - t0;
}

const UID_ALICE = "uid-alice-test-001";
const UID_BOB   = "uid-bob-test-002";

afterEach(async () => {
  clearPrivateKeys();
  await deleteVault(UID_ALICE).catch(() => {});
  await deleteVault(UID_BOB).catch(() => {});
});

// ══════════════════════════════════════════════════════════════════════════
// 1. storePrivateKeys
// ══════════════════════════════════════════════════════════════════════════

describe("storePrivateKeys", () => {
  it("should load kemPrivateKey into memory immediately after storing", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    expect(getKemPrivateKey(UID_ALICE)).toBe("kem-private-key-base64-alice");
  });

  it("should load dsaPrivateKey into memory immediately after storing", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    expect(getDsaPrivateKey(UID_ALICE)).toBe("dsa-private-key-base64-alice");
  });

  it("should persist to IDB (unlockPrivateKeys reads it back)", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    clearPrivateKeys();
    await unlockPrivateKeys(UID_ALICE, "master-key-base64-32bytes=====");
    expect(getKemPrivateKey(UID_ALICE)).toBe("kem-private-key-base64-alice");
  });

  it("should accept arbitrary Base64 strings for all key fields", async () => {
    const bundle = makeBundle({
      kemPrivateKey: btoa("A".repeat(2400)),
      dsaPrivateKey: btoa("B".repeat(512)),
    });
    await storePrivateKeys(UID_ALICE, bundle);
    expect(getKemPrivateKey(UID_ALICE)).toBe(btoa("A".repeat(2400)));
    expect(getDsaPrivateKey(UID_ALICE)).toBe(btoa("B".repeat(512)));
  });

  it("should overwrite memory if called twice for the same uid", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle({ kemPrivateKey: "old-key" }));
    await storePrivateKeys(UID_ALICE, makeBundle({ kemPrivateKey: "new-key" }));
    expect(getKemPrivateKey(UID_ALICE)).toBe("new-key");
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 2. unlockPrivateKeys
// ══════════════════════════════════════════════════════════════════════════

describe("unlockPrivateKeys", () => {
  it("should throw if no vault exists for the given uid", async () => {
    await expect(unlockPrivateKeys("uid-nonexistent", "any-key")).rejects.toThrow();
  });

  it("should restore kem + dsa keys after clearPrivateKeys", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    clearPrivateKeys();
    await unlockPrivateKeys(UID_ALICE, "master-key-base64-32bytes=====");
    expect(getKemPrivateKey(UID_ALICE)).toBe("kem-private-key-base64-alice");
    expect(getDsaPrivateKey(UID_ALICE)).toBe("dsa-private-key-base64-alice");
  });

  it("should not affect keys of another uid in memory", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle({ kemPrivateKey: "alice-kem" }));
    await storePrivateKeys(UID_BOB,   makeBundle({ kemPrivateKey: "bob-kem" }));
    clearPrivateKeys();
    await unlockPrivateKeys(UID_ALICE, "master-key-base64-32bytes=====");
    expect(() => getKemPrivateKey(UID_BOB)).toThrow();
  });

  // ── [IDB FAILURE] Vault corrompu / absent ────────────────────────────────
  it("[SEC] unlockPrivateKeys throw proprement si le vault IDB est absent — pas de clé undefined", async () => {
    // Vérifie que si IDB ne contient rien pour cet uid, on obtient une erreur
    // claire et pas une clé `undefined` silencieusement chargée en mémoire
    await expect(unlockPrivateKeys("uid-no-vault-ever", "some-key")).rejects.toThrow(
      /no vault|not found/i
    );
    // Après un échec d'unlock, getKemPrivateKey doit toujours throw
    expect(() => getKemPrivateKey("uid-no-vault-ever")).toThrow();
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 3. getKemPrivateKey / getDsaPrivateKey
// ══════════════════════════════════════════════════════════════════════════

describe("getKemPrivateKey / getDsaPrivateKey", () => {
  it("getKemPrivateKey returns exact stored value", async () => {
    const key = "exact-kem-key-value-xyz";
    await storePrivateKeys(UID_ALICE, makeBundle({ kemPrivateKey: key }));
    expect(getKemPrivateKey(UID_ALICE)).toBe(key);
  });

  it("getDsaPrivateKey returns exact stored value", async () => {
    const key = "exact-dsa-key-value-abc";
    await storePrivateKeys(UID_ALICE, makeBundle({ dsaPrivateKey: key }));
    expect(getDsaPrivateKey(UID_ALICE)).toBe(key);
  });

  it("getKemPrivateKey is synchronous (no async overhead)", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    let returned: string | null = null;
    expect(() => { returned = getKemPrivateKey(UID_ALICE); }).not.toThrow();
    expect(returned).not.toBeNull();
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 4. clearPrivateKeys — Session Expiry
// ══════════════════════════════════════════════════════════════════════════

describe("clearPrivateKeys", () => {
  it("should make getKemPrivateKey throw after clearing", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    clearPrivateKeys();
    expect(() => getKemPrivateKey(UID_ALICE)).toThrow();
  });

  it("should make getDsaPrivateKey throw after clearing", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    clearPrivateKeys();
    expect(() => getDsaPrivateKey(UID_ALICE)).toThrow();
  });

  it("should clear all uids at once", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    await storePrivateKeys(UID_BOB, makeBundle());
    clearPrivateKeys();
    expect(() => getKemPrivateKey(UID_ALICE)).toThrow();
    expect(() => getKemPrivateKey(UID_BOB)).toThrow();
  });

  it("should NOT delete IDB vault (unlockPrivateKeys still works after clear)", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    clearPrivateKeys();
    await expect(unlockPrivateKeys(UID_ALICE, "master-key-base64-32bytes=====")).resolves.not.toThrow();
  });

  // ── [SESSION EXPIRY] Simuler onAuthChange → null ─────────────────────────
  it("[SESSION] clearPrivateKeys simule l'expiration de session Firebase — RAM purgée immédiatement", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle({ kemPrivateKey: "session-key" }));

    // Vérification préalable — la clé est accessible avant la déconnexion
    expect(getKemPrivateKey(UID_ALICE)).toBe("session-key");

    // Simuler onAuthStateChanged(null) → appel à clearPrivateKeys()
    clearPrivateKeys();

    // La clé doit être immédiatement inaccessible — pas de fuite post-session
    expect(() => getKemPrivateKey(UID_ALICE)).toThrow();
    expect(() => getDsaPrivateKey(UID_ALICE)).toThrow();
  });

  it("[SESSION] vault IDB persiste après clearPrivateKeys — reconnexion possible", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle({ kemPrivateKey: "reconnect-key" }));
    clearPrivateKeys(); // déconnexion

    // Simuler une reconnexion — unlock depuis IDB doit fonctionner
    await unlockPrivateKeys(UID_ALICE, "master-key-base64-32bytes=====");
    expect(getKemPrivateKey(UID_ALICE)).toBe("reconnect-key");
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 5. deleteVault
// ══════════════════════════════════════════════════════════════════════════

describe("deleteVault", () => {
  it("should remove IDB entry so unlockPrivateKeys throws afterwards", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    clearPrivateKeys();
    await deleteVault(UID_ALICE);
    await expect(unlockPrivateKeys(UID_ALICE, "any")).rejects.toThrow();
  });

  it("should not throw when called on a non-existent vault", async () => {
    await expect(deleteVault("uid-ghost-user")).resolves.not.toThrow();
  });

  it("should not affect vault of another uid", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    await storePrivateKeys(UID_BOB,   makeBundle({ kemPrivateKey: "bob-kem" }));
    clearPrivateKeys();
    await deleteVault(UID_ALICE);
    await unlockPrivateKeys(UID_BOB, "master-key-base64-32bytes=====");
    expect(getKemPrivateKey(UID_BOB)).toBe("bob-kem");
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 6. saveRatchetState / loadRatchetState
// ══════════════════════════════════════════════════════════════════════════

describe("saveRatchetState / loadRatchetState", () => {
  it("loadRatchetState returns null when no state has been saved", async () => {
    expect(await loadRatchetState(UID_ALICE, "conv-001")).toBeNull();
  });

  it("should persist and retrieve ratchet state round-trip", async () => {
    const state = JSON.stringify({ rootKey: "abc", sendCount: 3 });
    await saveRatchetState(UID_ALICE, "conv-001", state);
    expect(await loadRatchetState(UID_ALICE, "conv-001")).toBe(state);
  });

  it("should overwrite state on successive saves (latest wins)", async () => {
    await saveRatchetState(UID_ALICE, "conv-001", JSON.stringify({ sendCount: 1 }));
    await saveRatchetState(UID_ALICE, "conv-001", JSON.stringify({ sendCount: 5 }));
    const loaded = await loadRatchetState(UID_ALICE, "conv-001");
    expect(JSON.parse(loaded!).sendCount).toBe(5);
  });

  it("ratchet states are isolated per conversationId", async () => {
    await saveRatchetState(UID_ALICE, "conv-001", JSON.stringify({ rootKey: "key-conv1" }));
    await saveRatchetState(UID_ALICE, "conv-002", JSON.stringify({ rootKey: "key-conv2" }));
    expect(JSON.parse((await loadRatchetState(UID_ALICE, "conv-001"))!).rootKey).toBe("key-conv1");
    expect(JSON.parse((await loadRatchetState(UID_ALICE, "conv-002"))!).rootKey).toBe("key-conv2");
  });

  it("ratchet states are isolated per uid", async () => {
    await saveRatchetState(UID_ALICE, "conv-001", JSON.stringify({ rootKey: "alice-state" }));
    await saveRatchetState(UID_BOB,   "conv-001", JSON.stringify({ rootKey: "bob-state" }));
    expect(JSON.parse((await loadRatchetState(UID_ALICE, "conv-001"))!).rootKey).toBe("alice-state");
    expect(JSON.parse((await loadRatchetState(UID_BOB,   "conv-001"))!).rootKey).toBe("bob-state");
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 7. KPIs de Performance
// ══════════════════════════════════════════════════════════════════════════

describe("Performance KPIs — key-store (specs §2.2)", () => {
  it("storePrivateKeys should complete in < 50 ms", async () => {
    const ms = await measureMs(() => storePrivateKeys(UID_ALICE, makeBundle()));
    console.log(`[KPI] storePrivateKeys: ${ms.toFixed(2)} ms`);
    expect(ms).toBeLessThan(50);
  });

  it("unlockPrivateKeys should complete in < 50 ms", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    clearPrivateKeys();
    const ms = await measureMs(() => unlockPrivateKeys(UID_ALICE, "master-key-base64-32bytes====="));
    console.log(`[KPI] unlockPrivateKeys: ${ms.toFixed(2)} ms`);
    expect(ms).toBeLessThan(50);
  });

  it("getKemPrivateKey (memory read) should complete in < 1 ms", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    const t0 = performance.now();
    getKemPrivateKey(UID_ALICE);
    const ms = performance.now() - t0;
    console.log(`[KPI] getKemPrivateKey: ${ms.toFixed(3)} ms`);
    expect(ms).toBeLessThan(1);
  });

  it("getDsaPrivateKey (memory read) should complete in < 1 ms", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    const t0 = performance.now();
    getDsaPrivateKey(UID_ALICE);
    const ms = performance.now() - t0;
    console.log(`[KPI] getDsaPrivateKey: ${ms.toFixed(3)} ms`);
    expect(ms).toBeLessThan(1);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 8. Invariants de Sécurité
// ══════════════════════════════════════════════════════════════════════════

describe("Security invariants — key-store", () => {
  it("[SEC] getKemPrivateKey throws if vault was never loaded — no silent null/undefined return", () => {
    expect(() => getKemPrivateKey("uid-never-seen")).toThrow(/not loaded|signed in/i);
  });

  it("[SEC] getDsaPrivateKey throws if vault was never loaded — no silent null/undefined return", () => {
    expect(() => getDsaPrivateKey("uid-never-seen")).toThrow(/not loaded|signed in/i);
  });

  it("[SEC] getKemPrivateKey error message contains the uid for diagnostics, not key material", () => {
    const uid = "uid-diagnostic-test";
    try {
      getKemPrivateKey(uid);
      expect.fail("Should have thrown");
    } catch (e: unknown) {
      const msg = (e as Error).message;
      expect(msg).toContain(uid);
      expect(msg.length).toBeLessThan(200);
    }
  });

  it("[SEC] uid isolation — Alice's keys are not accessible under Bob's uid", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle({ kemPrivateKey: "alice-secret-kem" }));
    expect(() => getKemPrivateKey(UID_BOB)).toThrow();
  });

  it("[SEC] uid isolation — Bob cannot read Alice's ratchet state via his uid", async () => {
    await saveRatchetState(UID_ALICE, "conv-shared", JSON.stringify({ secret: "alice-only" }));
    expect(await loadRatchetState(UID_BOB, "conv-shared")).toBeNull();
  });

  it("[SEC] after clearPrivateKeys, no key is retrievable even if uid is known", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    clearPrivateKeys();
    expect(() => getKemPrivateKey(UID_ALICE)).toThrow();
    expect(() => getDsaPrivateKey(UID_ALICE)).toThrow();
  });

  it("[SEC] overwriting vault then clearing does not expose old keys", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle({ kemPrivateKey: "old-leaked-key" }));
    await storePrivateKeys(UID_ALICE, makeBundle({ kemPrivateKey: "new-key" }));
    clearPrivateKeys();
    expect(() => getKemPrivateKey(UID_ALICE)).toThrow();
  });

  it("[SEC] unlockPrivateKeys with wrong uid throws — no cross-user vault access", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    clearPrivateKeys();
    await expect(unlockPrivateKeys(UID_BOB, "master")).rejects.toThrow();
  });

  it("[SEC] deleteVault is irreversible — unlockPrivateKeys throws after deletion", async () => {
    await storePrivateKeys(UID_ALICE, makeBundle());
    await deleteVault(UID_ALICE);
    await expect(unlockPrivateKeys(UID_ALICE, "master")).rejects.toThrow();
  });

  it("[SEC] empty string uid does not silently collide with other entries", async () => {
    await storePrivateKeys("", makeBundle({ kemPrivateKey: "empty-uid-key" }));
    expect(() => getKemPrivateKey(UID_ALICE)).toThrow();
    await deleteVault("");
  });
});
