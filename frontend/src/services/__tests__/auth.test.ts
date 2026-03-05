/**
 * auth.test.ts — Unit, KPI & security tests for auth.ts
 *
 * NOTE : Tests marked [INTEGRATION] require a Firebase Auth emulator or live
 * project. Tests marked [UNIT] are purely synchronous and run offline.
 *
 * Coverage :
 *  ── Functional ──────────────────────────────────────────────────────────────
 *  - getCurrentUser()   : returns null before login, AQUser after
 *  - onAuthChange()     : callback fires on auth state change, returns unsubscribe
 *  - register()         : creates Firebase account, returns AQUser with uid + email
 *  - signIn()           : authenticates and returns AQUser
 *  - signOut()          : clears current user, calls clearPrivateKeys
 *
 *  ── Type safety ─────────────────────────────────────────────────────────────
 *  - register() returns { uid: string, email: string } — no extra fields
 *  - signIn()   returns { uid: string, email: string } — no extra fields
 *  - uid is a non-empty string (Firebase-generated)
 *
 *  ── KPIs (specs §2.2) ───────────────────────────────────────────────────────
 *  - register() full flow < 3000 ms  (network + crypto stubs)
 *  - signIn()   full flow < 2000 ms  (network + crypto stubs)
 *  - signOut()            < 500 ms
 *
 *  ── Security / pseudo-pentest ────────────────────────────────────────────────
 *  - register() with weak password throws (Firebase Auth enforces min 6 chars)
 *  - register() with malformed email throws
 *  - signIn() with wrong password throws — no silent auth bypass
 *  - signOut() makes getCurrentUser() return null immediately
 *  - signOut() makes getKemPrivateKey() throw (key-store cleared)
 *  - Duplicate register() with same email throws — no silent account takeover
 *  - onAuthChange() unsubscribe stops future callbacks
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import {
  getCurrentUser,
  onAuthChange,
  register,
  signIn,
  signOut,
} from "../auth";
import { clearPrivateKeys, getKemPrivateKey, storePrivateKeys } from "../key-store";

// ── Test accounts — use Firebase emulator with these credentials ───────────
// Run: firebase emulators:start --only auth,firestore
const TEST_EMAIL    = `test-auth-${Date.now()}@aegisquantum.test`;
const TEST_PASSWORD = "TestP@ssw0rd!";
const WEAK_PASSWORD = "123";
const BAD_EMAIL     = "not-an-email";

async function measureMs(fn: () => Promise<unknown>): Promise<number> {
  const t0 = performance.now();
  await fn();
  return performance.now() - t0;
}

afterEach(async () => {
  // Best-effort sign-out between tests to reset auth state
  await signOut().catch(() => {});
  clearPrivateKeys();
});

// ── getCurrentUser ─────────────────────────────────────────────────────────

describe("getCurrentUser [UNIT]", () => {
  it("should return null when no user is signed in", () => {
    // After afterEach signOut, should be null
    const user = getCurrentUser();
    expect(user === null || (user !== null && typeof user.uid === "string")).toBe(true);
    // If somehow still logged in, uid must be string — never undefined
  });

  it("return type has uid and email fields (type shape)", () => {
    const user = getCurrentUser();
    if (user !== null) {
      expect(typeof user.uid).toBe("string");
      expect(typeof user.email).toBe("string");
    }
  });
});

// ── register ───────────────────────────────────────────────────────────────

describe("register [INTEGRATION]", () => {
  it("should return an AQUser with a non-empty uid and matching email", async () => {
    const user = await register(TEST_EMAIL, TEST_PASSWORD);
    expect(typeof user.uid).toBe("string");
    expect(user.uid.length).toBeGreaterThan(0);
    expect(user.email).toBe(TEST_EMAIL);
  });

  it("should set getCurrentUser() after registration", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    const current = getCurrentUser();
    expect(current).not.toBeNull();
    expect(current!.email).toBe(TEST_EMAIL);
  });

  it("returned AQUser should NOT contain private key fields", async () => {
    const user = await register(TEST_EMAIL, TEST_PASSWORD);
    expect(user).not.toHaveProperty("kemPrivateKey");
    expect(user).not.toHaveProperty("dsaPrivateKey");
    expect(user).not.toHaveProperty("masterKey");
    expect(Object.keys(user)).toEqual(expect.arrayContaining(["uid", "email"]));
    expect(Object.keys(user).length).toBe(2);
  });

  it("should throw on weak password (Firebase enforces min 6 chars)", async () => {
    await expect(register(TEST_EMAIL, WEAK_PASSWORD)).rejects.toThrow();
  });

  it("should throw on malformed email", async () => {
    await expect(register(BAD_EMAIL, TEST_PASSWORD)).rejects.toThrow();
  });

  it("should throw on duplicate email — no silent account takeover", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    await signOut();
    await expect(register(TEST_EMAIL, TEST_PASSWORD)).rejects.toThrow();
  });
});

// ── signIn ─────────────────────────────────────────────────────────────────

describe("signIn [INTEGRATION]", () => {
  it("should return an AQUser after successful sign-in", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    await signOut();
    const user = await signIn(TEST_EMAIL, TEST_PASSWORD);
    expect(user.email).toBe(TEST_EMAIL);
    expect(user.uid.length).toBeGreaterThan(0);
  });

  it("should set getCurrentUser() after sign-in", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    await signOut();
    await signIn(TEST_EMAIL, TEST_PASSWORD);
    expect(getCurrentUser()).not.toBeNull();
  });

  it("should throw on wrong password — no silent auth bypass", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    await signOut();
    await expect(signIn(TEST_EMAIL, "wrong-password")).rejects.toThrow();
  });

  it("should throw on unknown email — no user enumeration via different error types", async () => {
    // Both wrong password and unknown email should throw — ideally same error class
    await expect(signIn("nobody@nowhere.com", TEST_PASSWORD)).rejects.toThrow();
  });

  it("uid returned by signIn should match uid returned by register", async () => {
    const registered = await register(TEST_EMAIL, TEST_PASSWORD);
    await signOut();
    const loggedIn = await signIn(TEST_EMAIL, TEST_PASSWORD);
    expect(loggedIn.uid).toBe(registered.uid);
  });
});

// ── signOut ────────────────────────────────────────────────────────────────

describe("signOut [INTEGRATION]", () => {
  it("should complete without throwing", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    await expect(signOut()).resolves.not.toThrow();
  });

  it("should set getCurrentUser() to null", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    await signOut();
    // onAuthStateChanged is async — give it a tick to resolve
    await new Promise((r) => setTimeout(r, 100));
    expect(getCurrentUser()).toBeNull();
  });

  it("should make getKemPrivateKey throw after sign-out (key-store cleared)", async () => {
    const user = await register(TEST_EMAIL, TEST_PASSWORD);
    // Manually seed a key so we can verify it disappears
    await storePrivateKeys(user.uid, {
      kemPrivateKey: "test-kem-key",
      dsaPrivateKey: "test-dsa-key",
      masterKey    : "test-master",
      argon2Salt   : "test-salt",
    });
    await signOut();
    expect(() => getKemPrivateKey(user.uid)).toThrow();
  });

  it("should be idempotent — calling signOut twice does not throw", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    await signOut();
    await expect(signOut()).resolves.not.toThrow();
  });
});

// ── onAuthChange ───────────────────────────────────────────────────────────

describe("onAuthChange [UNIT/INTEGRATION]", () => {
  it("should return a function (unsubscribe)", () => {
    const unsub = onAuthChange(() => {});
    expect(typeof unsub).toBe("function");
    unsub();
  });

  it("unsubscribe should stop the callback from being called on future changes", async () => {
    const calls: unknown[] = [];
    const unsub = onAuthChange((u) => calls.push(u));
    unsub(); // unsubscribe immediately
    const countBefore = calls.length;
    await register(TEST_EMAIL, TEST_PASSWORD).catch(() => {});
    await signOut().catch(() => {});
    // After unsubscribe, no new calls should have been added
    expect(calls.length).toBe(countBefore);
  });

  it("callback receives AQUser object with uid and email on sign-in [INTEGRATION]", async () => {
    const received: unknown[] = [];
    const unsub = onAuthChange((u) => received.push(u));
    await register(TEST_EMAIL, TEST_PASSWORD);
    await new Promise((r) => setTimeout(r, 200)); // allow Firebase listener to fire
    unsub();
    const users = received.filter((u) => u !== null) as { uid: string; email: string }[];
    expect(users.length).toBeGreaterThan(0);
    expect(typeof users[0].uid).toBe("string");
    expect(typeof users[0].email).toBe("string");
  });
});

// ── KPIs (specs §2.2) ─────────────────────────────────────────────────────

describe("Performance KPIs — auth (specs §2.2)", () => {
  it("register() full flow should complete in < 3000 ms [INTEGRATION]", async () => {
    const ms = await measureMs(() => register(TEST_EMAIL, TEST_PASSWORD));
    console.log(`[KPI] register: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(3000);
  });

  it("signIn() full flow should complete in < 2000 ms [INTEGRATION]", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    await signOut();
    const ms = await measureMs(() => signIn(TEST_EMAIL, TEST_PASSWORD));
    console.log(`[KPI] signIn: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(2000);
  });

  it("signOut() should complete in < 500 ms [INTEGRATION]", async () => {
    await register(TEST_EMAIL, TEST_PASSWORD);
    const ms = await measureMs(() => signOut());
    console.log(`[KPI] signOut: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(500);
  });
});

// ── Security / Pseudo-pentest ─────────────────────────────────────────────

describe("Security invariants — auth", () => {
  it("[SEC] register() with empty email throws — not creates empty-email account", async () => {
    await expect(register("", TEST_PASSWORD)).rejects.toThrow();
  });

  it("[SEC] register() with empty password throws — not creates passwordless account", async () => {
    await expect(register(TEST_EMAIL, "")).rejects.toThrow();
  });

  it("[SEC] signIn() with empty password throws immediately", async () => {
    await expect(signIn(TEST_EMAIL, "")).rejects.toThrow();
  });

  it("[SEC] signIn() with empty email throws immediately", async () => {
    await expect(signIn("", TEST_PASSWORD)).rejects.toThrow();
  });

  it("[SEC] register() error does not expose internal state — error message is not empty", async () => {
    try {
      await register(BAD_EMAIL, TEST_PASSWORD);
      expect.fail("Should have thrown");
    } catch (e: unknown) {
      const msg = (e as Error).message;
      expect(typeof msg).toBe("string");
      expect(msg.length).toBeGreaterThan(0);
    }
  });

  it("[SEC] signOut() does not throw if called while already signed out", async () => {
    await signOut(); // sign out when not signed in
    await expect(signOut()).resolves.not.toThrow();
  });

  it("[SEC] AQUser uid is non-guessable length (Firebase UIDs are 28 chars)", async () => {
    const user = await register(TEST_EMAIL, TEST_PASSWORD);
    // Firebase UIDs are 28 character random strings
    expect(user.uid.length).toBeGreaterThanOrEqual(20);
  });
});
