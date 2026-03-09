/**
 * auth.test.ts — Unit, KPI & security tests for auth.ts
 *
 * L'utilisateur s'authentifie avec USERNAME + PASSWORD uniquement.
 * Aucun email n'est attendu dans AQUser ni dans aucun retour de service.
 */

import { describe, it, expect, afterEach } from "vitest";
import { getCurrentUser, onAuthChange, register, signIn, signOut, validateUsername } from "../auth";
import { clearPrivateKeys, getKemPrivateKey, storePrivateKeys, unlockPrivateKeys } from "../key-store";

const USERNAME       = `testuser_${Date.now()}`;
const PASSWORD       = "TestP@ssw0rd!";
const WEAK_PASSWORD  = "123";
const SHORT_USERNAME = "ab";
const LONG_USERNAME  = "a".repeat(25);

async function measureMs(fn: () => Promise<unknown>): Promise<number> {
  const t0 = performance.now();
  await fn();
  return performance.now() - t0;
}

afterEach(async () => {
  await signOut().catch(() => {});
  clearPrivateKeys();
});

// ── validateUsername ───────────────────────────────────────────────────────

describe("validateUsername [UNIT]", () => {
  it("returns null for valid usernames", () => {
    expect(validateUsername("alice")).toBeNull();
    expect(validateUsername("bob_42")).toBeNull();
    expect(validateUsername("user.name")).toBeNull();
    expect(validateUsername("a-b-c")).toBeNull();
  });
  it("rejects username shorter than 3 chars", () => {
    expect(validateUsername(SHORT_USERNAME)).toMatch(/3 character/i);
  });
  it("rejects username longer than 24 chars", () => {
    expect(validateUsername(LONG_USERNAME)).toMatch(/24 character/i);
  });
  it("rejects username with spaces or special chars", () => {
    expect(validateUsername("user name")).not.toBeNull();
    expect(validateUsername("user@name")).not.toBeNull();
  });
});

// ── getCurrentUser ─────────────────────────────────────────────────────────

describe("getCurrentUser [UNIT]", () => {
  it("returns null or AQUser with only uid field", async () => {
    const user = getCurrentUser();
    if (user !== null) {
      expect(Object.keys(user)).toEqual(["uid"]);
    } else {
      expect(user).toBeNull();
    }
  });
});

// ── register ───────────────────────────────────────────────────────────────

describe("register [INTEGRATION]", () => {
  it("returns AQUser with non-empty uid", async () => {
    const user = await register(USERNAME, PASSWORD);
    expect(typeof user.uid).toBe("string");
    expect(user.uid.length).toBeGreaterThan(0);
  });

  it("AQUser must NOT contain email", async () => {
    const user = await register(USERNAME, PASSWORD);
    expect(user).not.toHaveProperty("email");
    expect(Object.keys(user)).toEqual(["uid"]);
  });

  it("AQUser must NOT contain private keys", async () => {
    const user = await register(USERNAME, PASSWORD);
    expect(user).not.toHaveProperty("kemPrivateKey");
    expect(user).not.toHaveProperty("dsaPrivateKey");
    expect(user).not.toHaveProperty("masterKey");
  });

  it("getCurrentUser() is set after register", async () => {
    await register(USERNAME, PASSWORD);
    const current = getCurrentUser();
    expect(current).not.toBeNull();
    expect(typeof current!.uid).toBe("string");
  });

  it("throws on weak password (< 6 chars)", async () => {
    await expect(register(USERNAME, WEAK_PASSWORD)).rejects.toThrow();
  });

  it("throws on duplicate username", async () => {
    await register(USERNAME, PASSWORD);
    await signOut();
    await expect(register(USERNAME, PASSWORD)).rejects.toThrow();
  });

  it("throws on empty password", async () => {
    await expect(register(USERNAME, "")).rejects.toThrow();
  });

  it("throws on empty username", async () => {
    await expect(register("", PASSWORD)).rejects.toThrow();
  });
});

// ── signIn ─────────────────────────────────────────────────────────────────

describe("signIn [INTEGRATION]", () => {
  it("returns AQUser after successful login", async () => {
    await register(USERNAME, PASSWORD);
    await signOut();
    const user = await signIn(USERNAME, PASSWORD);
    expect(user.uid.length).toBeGreaterThan(0);
    expect(user).not.toHaveProperty("email");
    expect(Object.keys(user)).toEqual(["uid"]);
  });

  it("uid from signIn matches uid from register", async () => {
    const reg = await register(USERNAME, PASSWORD);
    await signOut();
    const log = await signIn(USERNAME, PASSWORD);
    expect(log.uid).toBe(reg.uid);
  });

  it("throws on wrong password", async () => {
    await register(USERNAME, PASSWORD);
    await signOut();
    await expect(signIn(USERNAME, "wrong-password")).rejects.toThrow();
  });

  it("throws on unknown username", async () => {
    await expect(signIn("nobody_that_exists", PASSWORD)).rejects.toThrow();
  });

  it("throws on empty password", async () => {
    await expect(signIn(USERNAME, "")).rejects.toThrow();
  });

  it("throws on empty username", async () => {
    await expect(signIn("", PASSWORD)).rejects.toThrow();
  });
});

// ── signOut ────────────────────────────────────────────────────────────────

describe("signOut [INTEGRATION]", () => {
  it("completes without throwing", async () => {
    await register(USERNAME, PASSWORD);
    await expect(signOut()).resolves.not.toThrow();
  });

  it("getCurrentUser() returns null after signOut", async () => {
    await register(USERNAME, PASSWORD);
    await signOut();
    await new Promise((r) => setTimeout(r, 50));
    expect(getCurrentUser()).toBeNull();
  });

  it("[SESSION] purges RAM immediately — getKemPrivateKey throws after signOut", async () => {
    const { uid } = await register(USERNAME, PASSWORD);
    await storePrivateKeys(uid, {
      kemPrivateKey: "critical-kem-key",
      dsaPrivateKey: "critical-dsa-key",
      masterKey    : "mk",
      argon2Salt   : "salt",
    });
    expect(getKemPrivateKey(uid)).toBe("critical-kem-key");
    await signOut();
    expect(() => getKemPrivateKey(uid)).toThrow();
  });

  it("[SESSION] IndexedDB vault persists after signOut — reconnection possible", async () => {
    const { uid } = await register(USERNAME, PASSWORD);
    await storePrivateKeys(uid, {
      kemPrivateKey: "persist-kem",
      dsaPrivateKey: "persist-dsa",
      masterKey    : "mk",
      argon2Salt   : "salt",
    });
    await signOut();
    await expect(unlockPrivateKeys(uid, "mk")).resolves.not.toThrow();
  });

  it("is idempotent — double signOut does not throw", async () => {
    await register(USERNAME, PASSWORD);
    await signOut();
    await expect(signOut()).resolves.not.toThrow();
  });

  it("[SEC] signOut clears KeyStore even if _currentUser is already null", async () => {
    const uid = "hypothetical-uid";
    await storePrivateKeys(uid, { kemPrivateKey: "k", dsaPrivateKey: "d", masterKey: "m", argon2Salt: "s" });
    await signOut();
    expect(() => getKemPrivateKey(uid)).toThrow();
  });
});

// ── onAuthChange ───────────────────────────────────────────────────────────

describe("onAuthChange [UNIT/INTEGRATION]", () => {
  it("returns an unsubscribe function", () => {
    const unsub = onAuthChange(() => {});
    expect(typeof unsub).toBe("function");
    unsub();
  });

  it("callback receives AQUser with only uid (no email) on sign-in", async () => {
    const received: unknown[] = [];
    const unsub = onAuthChange((u) => received.push(u));
    await register(USERNAME, PASSWORD);
    await new Promise((r) => setTimeout(r, 50));
    unsub();
    const users = received.filter((u) => u !== null) as { uid: string }[];
    expect(users.length).toBeGreaterThan(0);
    expect(typeof users[0].uid).toBe("string");
    expect(users[0]).not.toHaveProperty("email");
  });

  it("[SESSION] emits null after signOut", async () => {
    const states: unknown[] = [];
    const unsub = onAuthChange((u) => states.push(u));
    await register(USERNAME, PASSWORD);
    await new Promise((r) => setTimeout(r, 50));
    await signOut();
    await new Promise((r) => setTimeout(r, 50));
    unsub();
    expect(states.some((s) => s !== null)).toBe(true);
    expect(states.some((s) => s === null)).toBe(true);
  });

  it("unsubscribe stops future callbacks", async () => {
    const calls: unknown[] = [];
    const unsub = onAuthChange((u) => calls.push(u));
    unsub();
    const before = calls.length;
    await register(USERNAME, PASSWORD).catch(() => {});
    await signOut().catch(() => {});
    expect(calls.length).toBe(before);
  });
});

// ── KPIs ───────────────────────────────────────────────────────────────────

describe("Performance KPIs — auth (specs §2.2)", () => {
  it("register() < 3000 ms", async () => {
    const ms = await measureMs(() => register(USERNAME, PASSWORD));
    console.log(`[KPI] register: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(3000);
  });

  it("signIn() < 2000 ms", async () => {
    await register(USERNAME, PASSWORD);
    await signOut();
    const ms = await measureMs(() => signIn(USERNAME, PASSWORD));
    console.log(`[KPI] signIn: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(2000);
  });

  it("signOut() < 500 ms", async () => {
    await register(USERNAME, PASSWORD);
    const ms = await measureMs(() => signOut());
    console.log(`[KPI] signOut: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(500);
  });
});

// ── Invariants de sécurité ─────────────────────────────────────────────────

describe("Security invariants — auth", () => {
  it("[SEC] error messages are non-empty strings (no internal state leak)", async () => {
    try {
      await register("ab", PASSWORD); // trop court → validateUsername
      expect.fail("Should have thrown");
    } catch (e: unknown) {
      const msg = (e instanceof Error) ? e.message : String(e);
      expect(typeof msg).toBe("string");
      expect(msg.length).toBeGreaterThan(0);
    }
  });

  it("[SEC] uid length ≥ 20 chars (non-guessable)", async () => {
    const user = await register(USERNAME, PASSWORD);
    expect(user.uid.length).toBeGreaterThanOrEqual(20);
  });

  it("[SEC] AQUser returned by register has exactly one field: uid", async () => {
    const user = await register(USERNAME, PASSWORD);
    expect(Object.keys(user)).toEqual(["uid"]);
  });

  it("[SEC] AQUser returned by signIn has exactly one field: uid", async () => {
    await register(USERNAME, PASSWORD);
    await signOut();
    const user = await signIn(USERNAME, PASSWORD);
    expect(Object.keys(user)).toEqual(["uid"]);
  });
});
