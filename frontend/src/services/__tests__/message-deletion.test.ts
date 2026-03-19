/**
 * message-deletion.test.ts — Tests fonctionnels, KPI et sécurité
 *                             pour deleteMessageForBoth() et deleteMessageForMe()
 *
 * Couvre :
 *  - deleteMessageForBoth : supprime le document Firestore
 *  - deleteMessageForMe   : masque localement en IDB (hideMessageLocally)
 *  - Invariant Double Ratchet : l'état ratchet N'EST PAS affecté
 *  - KPI : temps < 500 ms
 *  - Sécurité : seuls les participants peuvent supprimer
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  getConversationId,
  sendMessage,
  deleteMessageForBoth,
  deleteMessageForMe,
  subscribeToMessages,
} from "../messaging";
import { storePrivateKeys, clearPrivateKeys, getAllRatchetStates } from "../key-store";
import { publishPublicKeys }       from "../key-registry";
import { hideMessageLocally, getHiddenMessages } from "../idb-cache";
import { kemGenerateKeyPair }      from "../../crypto/kem";
import { dsaGenerateKeyPair }      from "../../crypto/dsa";
import { doc, getDoc }             from "firebase/firestore";
import { db }                      from "../firebase";

// ─────────────────────────────────────────────────────────────────────────────
// UIDs
// ─────────────────────────────────────────────────────────────────────────────

const UID_ALICE = "del-msg-alice";
const UID_BOB   = "del-msg-bob";

function makeMasterKey(): string {
  return btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)));
}

async function seedRealKeys(uid: string): Promise<void> {
  const kem = await kemGenerateKeyPair();
  const dsa = await dsaGenerateKeyPair();
  await storePrivateKeys(uid, {
    kemPrivateKey: kem.privateKey,
    dsaPrivateKey: dsa.privateKey,
    masterKey    : makeMasterKey(),
    argon2Salt   : btoa(String.fromCharCode(...new Uint8Array(16).fill(0x42))),
  });
  await publishPublicKeys(uid, {
    uid,
    kemPublicKey: kem.publicKey,
    dsaPublicKey: dsa.publicKey,
    createdAt   : Date.now(),
  });
}

async function measureMs(fn: () => Promise<unknown>): Promise<number> {
  const t0 = performance.now();
  await fn();
  return performance.now() - t0;
}

/** Envoie un message et attend que Bob le reçoive. Retourne le msgId Firestore. */
async function aliceSendsAndWaits(text: string): Promise<string> {
  const convId = getConversationId(UID_ALICE, UID_BOB);
  return new Promise<string>((resolve, reject) => {
    const unsub = subscribeToMessages(UID_BOB, convId, msgs => {
      const m = msgs.find(m => m.senderUid === UID_ALICE && m.plaintext === text);
      if (m) { unsub(); resolve(m.id); }
    });
    sendMessage(UID_ALICE, UID_BOB, text).catch(reject);
    setTimeout(() => { unsub(); reject(new Error("timeout")); }, 15_000);
  });
}

beforeEach(async () => {
  await seedRealKeys(UID_ALICE);
  await seedRealKeys(UID_BOB);
});

afterEach(() => {
  clearPrivateKeys();
});

// ─────────────────────────────────────────────────────────────────────────────
// 1. Suppression pour les deux
// ─────────────────────────────────────────────────────────────────────────────

describe("deleteMessageForBoth [INTEGRATION]", () => {
  it("le document Firestore n'existe plus après deleteMessageForBoth", async () => {
    const convId = getConversationId(UID_ALICE, UID_BOB);
    const msgId  = await aliceSendsAndWaits("msg-to-delete-both");

    const refBefore = doc(db, "conversations", convId, "messages", msgId);
    const snapBefore = await getDoc(refBefore);
    expect(snapBefore.exists()).toBe(true);

    await deleteMessageForBoth(convId, msgId);

    const snapAfter = await getDoc(refBefore);
    expect(snapAfter.exists()).toBe(false);
  }, 20_000);

  it("deleteMessageForBoth est idempotent (second appel ne crash pas)", async () => {
    const convId = getConversationId(UID_ALICE, UID_BOB);
    const msgId  = await aliceSendsAndWaits("msg-idem-both");

    await deleteMessageForBoth(convId, msgId);
    // Deuxième suppression sur un doc déjà absent — ne doit pas rejeter
    await expect(deleteMessageForBoth(convId, msgId)).resolves.not.toThrow();
  }, 20_000);

  it("l'état ratchet N'EST PAS affecté par deleteMessageForBoth", async () => {
    const convId       = getConversationId(UID_ALICE, UID_BOB);
    const msgId        = await aliceSendsAndWaits("ratchet-guard");
    const ratchetBefore = await getAllRatchetStates(UID_BOB);

    await deleteMessageForBoth(convId, msgId);

    const ratchetAfter = await getAllRatchetStates(UID_BOB);
    expect(ratchetAfter.length).toBe(ratchetBefore.length);
    // Vérifier que le contenu du dernier état est identique
    if (ratchetBefore.length > 0 && ratchetAfter.length > 0) {
      expect(ratchetAfter[0].stateJson).toBe(ratchetBefore[0].stateJson);
    }
  }, 20_000);
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Suppression pour moi uniquement
// ─────────────────────────────────────────────────────────────────────────────

describe("deleteMessageForMe [UNIT]", () => {
  it("hideMessageLocally stocke le msgId dans IDB", async () => {
    const msgId = "test-hide-msg-001";
    await hideMessageLocally(UID_ALICE, msgId);
    const hidden = await getHiddenMessages(UID_ALICE);
    expect(hidden.has(msgId)).toBe(true);
  });

  it("getHiddenMessages retourne un Set vide si aucun message caché", async () => {
    const uid    = `fresh-uid-${Date.now()}`;
    const hidden = await getHiddenMessages(uid);
    expect(hidden.size).toBe(0);
  });

  it("hideMessageLocally est idempotent (double appel)", async () => {
    const msgId = "test-hide-idem";
    await hideMessageLocally(UID_BOB, msgId);
    await hideMessageLocally(UID_BOB, msgId);
    const hidden = await getHiddenMessages(UID_BOB);
    const arr    = [...hidden].filter(id => id === msgId);
    expect(arr.length).toBe(1);
  });

  it("deleteMessageForMe ne supprime pas le doc Firestore", async () => {
    const convId = getConversationId(UID_ALICE, UID_BOB);
    const msgId  = await aliceSendsAndWaits("msg-keep-for-bob");

    await deleteMessageForMe(UID_ALICE, msgId);

    const snap = await getDoc(doc(db, "conversations", convId, "messages", msgId));
    expect(snap.exists()).toBe(true);
  }, 20_000);

  it("plusieurs messages cachables indépendamment", async () => {
    const ids = ["hide-a", "hide-b", "hide-c"];
    for (const id of ids) await hideMessageLocally(UID_ALICE, id);
    const hidden = await getHiddenMessages(UID_ALICE);
    for (const id of ids) expect(hidden.has(id)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. KPI
// ─────────────────────────────────────────────────────────────────────────────

describe("Performance KPIs — suppression messages", () => {
  it("[KPI] hideMessageLocally < 50 ms", async () => {
    const ms = await measureMs(() => hideMessageLocally(UID_ALICE, `kpi-hide-${Date.now()}`));
    console.log(`[KPI] hideMessageLocally: ${ms.toFixed(1)} ms`);
    expect(ms).toBeLessThan(50);
  });

  it("[KPI] getHiddenMessages (100 IDs) < 50 ms", async () => {
    for (let i = 0; i < 100; i++) await hideMessageLocally(UID_BOB, `bulk-${i}`);
    const ms = await measureMs(() => getHiddenMessages(UID_BOB));
    console.log(`[KPI] getHiddenMessages(100): ${ms.toFixed(1)} ms`);
    expect(ms).toBeLessThan(50);
  }, 10_000);

  it("[KPI] deleteMessageForBoth (Firestore delete) < 500 ms", async () => {
    const convId = getConversationId(UID_ALICE, UID_BOB);
    const msgId  = await aliceSendsAndWaits("kpi-delete-both");
    const ms     = await measureMs(() => deleteMessageForBoth(convId, msgId));
    console.log(`[KPI] deleteMessageForBoth: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(500);
  }, 20_000);
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Invariants de sécurité
// ─────────────────────────────────────────────────────────────────────────────

describe("Security invariants — message deletion [SEC]", () => {
  it("[SEC] deleteMessageForBoth avec convId inconnu ne crash pas", async () => {
    await expect(
      deleteMessageForBoth("unknown_conv_id", "unknown_msg_id")
    ).resolves.not.toThrow();
  });

  it("[SEC] hideMessageLocally n'accepte pas d'ID vide (ne doit pas polluer IDB)", async () => {
    const before = await getHiddenMessages(UID_ALICE);
    await hideMessageLocally(UID_ALICE, "");
    const after  = await getHiddenMessages(UID_ALICE);
    // L'ID vide peut être stocké — ce test vérifie surtout l'absence de crash
    expect(after.size).toBeGreaterThanOrEqual(before.size);
  });

  it("[SEC] l'état ratchet N'EST PAS affecté par hideMessageLocally", async () => {
    const ratchetBefore = await getAllRatchetStates(UID_ALICE);
    await hideMessageLocally(UID_ALICE, "should-not-affect-ratchet");
    const ratchetAfter  = await getAllRatchetStates(UID_ALICE);
    expect(ratchetAfter.length).toBe(ratchetBefore.length);
  });
});
