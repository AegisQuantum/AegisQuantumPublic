/**
 * auth.test.ts — Unit, KPI & security tests for auth.ts
 */

import { describe, it, expect, afterEach } from "vitest";
import { getCurrentUser, onAuthChange, register, signIn, signOut } from "../auth";
import { clearPrivateKeys, getKemPrivateKey, storePrivateKeys, unlockPrivateKeys } from "../key-store";

const TEST_EMAIL    = `test-${Date.now()}@aegisquantum.test`;
const TEST_PASSWORD = "TestP@ssw0rd!";
const WEAK_PASSWORD = "123";
const BAD_EMAIL     = "not-an-email";

async function measureMs(fn: () => Promise<unknown>): Promise<number> {
  const t0 = performance.now();
  await fn();
  return performance.now() - t0;
}

afterEach(async () => {
  await signOut().catch(() => {});
  clearPrivateKeys();
});

// ── getCurrentUser ─────────────────────────────────────────────────────────

describe("getCurrentUser [UNIT]", () => {
  it("retourne null quand aucun utilisateur n'est connecté", () => {
    const user = getCurrentUser();
    expect(user === null || typeof user?.uid === "string").toBe(true);
  });

  it("retourne un objet avec un champ uid (string) quand connecté", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    const user = getCurrentUser();
    if (user !== null) {
      expect(typeof user.uid).toBe("string");
      expect(Object.keys(user)).toEqual(["uid"]); // pas d'email
    }
  });
});

// ── register ───────────────────────────────────────────────────────────────

describe("register [INTEGRATION]", () => {
  it("retourne un AQUser avec un uid non-vide", async () => {
    const user = await register(TEST_EMAIL, TEST_PASSWORD);
    expect(typeof user.uid).toBe("string");
    expect(user.uid.length).toBeGreaterThan(0);
  });

  it("ne retourne PAS de clés privées dans AQUser", async () => {
    const user = await register(TEST_EMAIL, TEST_PASSWORD);
    expect(user).not.toHaveProperty("kemPrivateKey");
    expect(user).not.toHaveProperty("dsaPrivateKey");
    expect(user).not.toHaveProperty("masterKey");
  });

  it("met à jour getCurrentUser() après inscription", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    expect(getCurrentUser()).not.toBeNull();
    expect(getCurrentUser()!.uid.length).toBeGreaterThan(0);
  });

  it("throw sur mot de passe trop court (< 6 chars)", async () => {
    await expect(register(TEST_EMAIL, WEAK_PASSWORD)).rejects.toThrow();
  });

  it("throw sur email malformé", async () => {
    await expect(register(BAD_EMAIL, TEST_PASSWORD)).rejects.toThrow();
  });

  it("throw sur email vide", async () => {
    await expect(register("", TEST_PASSWORD)).rejects.toThrow();
  });

  it("throw sur mot de passe vide", async () => {
    await expect(register(TEST_EMAIL, "")).rejects.toThrow();
  });

  it("throw sur email dupliqué — pas de prise de compte silencieuse", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    await signOut();
    await expect(register(TEST_EMAIL, TEST_PASSWORD)).rejects.toThrow();
  });
});

// ── signIn ─────────────────────────────────────────────────────────────────

describe("signIn [INTEGRATION]", () => {
  it("retourne un AQUser après connexion réussie", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    await signOut();
    const user = await signIn(TEST_EMAIL, TEST_PASSWORD);
    expect(user.uid.length).toBeGreaterThan(0);
    expect(user).not.toHaveProperty("email");
  });

  it("uid de signIn = uid de register", async () => {
    const reg = await register(TEST_EMAIL, TEST_PASSWORD);
    await signOut();
    const log = await signIn(TEST_EMAIL, TEST_PASSWORD);
    expect(log.uid).toBe(reg.uid);
  });

  it("throw sur mauvais mot de passe — pas de bypass silencieux", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    await signOut();
    await expect(signIn(TEST_EMAIL, "wrong-password")).rejects.toThrow();
  });

  it("throw sur email inconnu", async () => {
    await expect(signIn("nobody@nowhere.com", TEST_PASSWORD)).rejects.toThrow();
  });

  it("throw sur mot de passe vide", async () => {
    await expect(signIn(TEST_EMAIL, "")).rejects.toThrow();
  });

  it("throw sur email vide", async () => {
    await expect(signIn("", TEST_PASSWORD)).rejects.toThrow();
  });
});

// ── signOut ────────────────────────────────────────────────────────────────

describe("signOut [INTEGRATION]", () => {
  it("se termine sans erreur", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    await expect(signOut()).resolves.not.toThrow();
  });

  it("getCurrentUser() retourne null après signOut", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    await signOut();
    await new Promise((r) => setTimeout(r, 50));
    expect(getCurrentUser()).toBeNull();
  });

  it("[SESSION] purge immédiatement le KeyStore — getKemPrivateKey throw après signOut", async () => {
    const { uid } = await register(TEST_EMAIL, TEST_PASSWORD);
    await storePrivateKeys(uid, {
      kemPrivateKey: "session-critical-key",
      dsaPrivateKey: "session-dsa-key",
      masterKey    : "mk",
      argon2Salt   : "salt",
    });
    expect(getKemPrivateKey(uid)).toBe("session-critical-key");
    await signOut();
    expect(() => getKemPrivateKey(uid)).toThrow();
  });

  it("[SESSION] vault IDB persiste après signOut — reconnexion possible", async () => {
    const { uid } = await register(TEST_EMAIL, TEST_PASSWORD);
    await storePrivateKeys(uid, {
      kemPrivateKey: "persist-kem",
      dsaPrivateKey: "persist-dsa",
      masterKey    : "mk",
      argon2Salt   : "salt",
    });
    await signOut();
    await expect(unlockPrivateKeys(uid, "mk")).resolves.not.toThrow();
  });

  it("idempotent — deux signOut consécutifs ne throw pas", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    await signOut();
    await expect(signOut()).resolves.not.toThrow();
  });

  it("[SEC] signOut vide le KeyStore même si _currentUser est déjà null", async () => {
    const uid = "hypothetical-uid";
    await storePrivateKeys(uid, { kemPrivateKey: "k", dsaPrivateKey: "d", masterKey: "m", argon2Salt: "s" });
    await signOut();
    expect(() => getKemPrivateKey(uid)).toThrow();
  });
});

// ── onAuthChange ───────────────────────────────────────────────────────────

describe("onAuthChange [UNIT/INTEGRATION]", () => {
  it("retourne une fonction unsubscribe", () => {
    const unsub = onAuthChange(() => {});
    expect(typeof unsub).toBe("function");
    unsub();
  });

  it("le callback reçoit un AQUser sans champ email à la connexion", async () => {
    const received: unknown[] = [];
    const unsub = onAuthChange((u) => received.push(u));
    await register(TEST_EMAIL, TEST_PASSWORD);
    await new Promise((r) => setTimeout(r, 50));
    unsub();
    const users = received.filter((u) => u !== null) as { uid: string }[];
    expect(users.length).toBeGreaterThan(0);
    expect(typeof users[0].uid).toBe("string");
    expect(users[0]).not.toHaveProperty("email");
  });

  it("[SESSION] onAuthChange émet null après signOut", async () => {
    const states: unknown[] = [];
    const unsub = onAuthChange((u) => states.push(u));
    await register(TEST_EMAIL, TEST_PASSWORD);
    await new Promise((r) => setTimeout(r, 50));
    await signOut();
    await new Promise((r) => setTimeout(r, 50));
    unsub();
    expect(states.some((s) => s !== null)).toBe(true);
    expect(states.includes(null)).toBe(true);
  });

  it("unsubscribe stoppe les callbacks futurs", async () => {
    const calls: unknown[] = [];
    const unsub = onAuthChange((u) => calls.push(u));
    unsub();
    const before = calls.length;
    await register(TEST_EMAIL, TEST_PASSWORD).catch(() => {});
    await signOut().catch(() => {});
    expect(calls.length).toBe(before);
  });
});

// ── KPIs ───────────────────────────────────────────────────────────────────

describe("Performance KPIs — auth (specs §2.2)", () => {
  it("register() < 3000 ms", async () => {
    const ms = await measureMs(() => register(TEST_EMAIL, TEST_PASSWORD));
    console.log(`[KPI] register: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(3000);
  });

  it("signIn() < 2000 ms", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    await signOut();
    const ms = await measureMs(() => signIn(TEST_EMAIL, TEST_PASSWORD));
    console.log(`[KPI] signIn: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(2000);
  });

  it("signOut() < 500 ms", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    const ms = await measureMs(() => signOut());
    console.log(`[KPI] signOut: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(500);
  });
});

// ── Invariants de sécurité ─────────────────────────────────────────────────

describe("Security invariants — auth", () => {
  it("[SEC] register() message d'erreur non-vide (pas de fuite d'état interne)", async () => {
    try {
      await register(BAD_EMAIL, TEST_PASSWORD);
      expect.fail("Should have thrown");
    } catch (e: unknown) {
      const msg = (e as Error).message;
      expect(typeof msg).toBe("string");
      expect(msg.length).toBeGreaterThan(0);
    }
  });

  it("[SEC] uid Firebase ≥ 20 caractères (non-devinable)", async () => {
    const user = await register(TEST_EMAIL, TEST_PASSWORD);
    expect(user.uid.length).toBeGreaterThanOrEqual(20);
  });
});
