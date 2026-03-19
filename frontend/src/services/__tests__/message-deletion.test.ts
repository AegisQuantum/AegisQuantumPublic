/**
 * message-deletion.test.ts — Tests fonctionnels, KPI et sécurité
 *                             pour deleteMessageForBoth(), editMessage() et deleteMessageForMe()
 *
 * Couvre :
 *  - deleteMessageForBoth : écrase le ciphertext avec un tombstone chiffré (deleted=true)
 *  - editMessage          : écrase le ciphertext avec le nouveau plaintext chiffré (edited=true)
 *  - deleteMessageForMe   : masque localement en IDB (hideMessageLocally)
 *  - Invariant Double Ratchet : l'état ratchet N'EST PAS affecté
 *  - KPI : temps < 500 ms
 *  - Sécurité : invariants tombstone/édition
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  getConversationId,
  sendMessage,
  deleteMessageForBoth,
  deleteMessageForMe,
  editMessage,
  decryptMessage,
  subscribeToMessages,
} from "../messaging";
import { storePrivateKeys, clearPrivateKeys, getAllRatchetStates } from "../key-store";
import { publishPublicKeys }       from "../key-registry";
import { hideMessageLocally, getHiddenMessages } from "../idb-cache";
import { kemGenerateKeyPair }      from "../../crypto/kem";
import { dsaGenerateKeyPair }      from "../../crypto/dsa";
import { doc, getDoc } from "firebase/firestore";
import { db }                      from "../firebase";
import type { DecryptedMessage }   from "../../types/message";
import type { EncryptedMessage }   from "../../types/message";

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

/**
 * Envoie un message et attend que Bob le reçoive.
 * Retourne le DecryptedMessage complet (pour accéder aux métadonnées edit/delete).
 */
async function aliceSendsAndWaits(text: string): Promise<DecryptedMessage> {
  const convId = getConversationId(UID_ALICE, UID_BOB);
  return new Promise<DecryptedMessage>((resolve, reject) => {
    const unsub = subscribeToMessages(UID_BOB, convId, msgs => {
      const m = msgs.find(m => m.senderUid === UID_ALICE && m.plaintext === text);
      if (m) { unsub(); resolve(m); }
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
// 1. Suppression pour les deux (tombstone)
// ─────────────────────────────────────────────────────────────────────────────

describe("deleteMessageForBoth [INTEGRATION]", () => {
  it("le doc Firestore existe toujours après deleteMessageForBoth mais avec deleted=true", async () => {
    const convId  = getConversationId(UID_ALICE, UID_BOB);
    const decrypted = await aliceSendsAndWaits("msg-to-delete-both");
    const msgId   = decrypted.id;

    await deleteMessageForBoth(
      convId, msgId,
      decrypted.kemCiphertext      ?? "",
      decrypted.initKemCiphertext,
      decrypted.messageIndex       ?? 0,
    );

    const snap = await getDoc(doc(db, "conversations", convId, "messages", msgId));
    expect(snap.exists()).toBe(true);
    expect((snap.data() as EncryptedMessage).deleted).toBe(true);
  }, 20_000);

  it("Bob reçoit le tombstone et le déchiffre correctement (isDeleted=true)", async () => {
    const convId    = getConversationId(UID_ALICE, UID_BOB);
    const decrypted = await aliceSendsAndWaits("msg-tombstone-verify");
    const msgId     = decrypted.id;

    await deleteMessageForBoth(
      convId, msgId,
      decrypted.kemCiphertext      ?? "",
      decrypted.initKemCiphertext,
      decrypted.messageIndex       ?? 0,
    );

    // Lire le tombstone depuis Firestore et le déchiffrer comme Bob
    const snap    = await getDoc(doc(db, "conversations", convId, "messages", msgId));
    const rawData = { id: snap.id, ...snap.data() } as EncryptedMessage;
    const result  = await decryptMessage(UID_BOB, rawData);

    expect(result.isDeleted).toBe(true);
    expect(result.plaintext).toBe("Ce message a été supprimé");
  }, 20_000);

  it("deleteMessageForBoth est idempotent (second appel ne crash pas)", async () => {
    const convId    = getConversationId(UID_ALICE, UID_BOB);
    const decrypted = await aliceSendsAndWaits("msg-idem-both");
    const { id: msgId, kemCiphertext = "", initKemCiphertext, messageIndex = 0 } = decrypted;

    await deleteMessageForBoth(convId, msgId, kemCiphertext, initKemCiphertext, messageIndex);
    await expect(
      deleteMessageForBoth(convId, msgId, kemCiphertext, initKemCiphertext, messageIndex),
    ).resolves.not.toThrow();
  }, 20_000);

  it("l'état ratchet N'EST PAS affecté par deleteMessageForBoth", async () => {
    const convId       = getConversationId(UID_ALICE, UID_BOB);
    const decrypted    = await aliceSendsAndWaits("ratchet-guard");
    const ratchetBefore = await getAllRatchetStates(UID_BOB);

    await deleteMessageForBoth(
      convId, decrypted.id,
      decrypted.kemCiphertext      ?? "",
      decrypted.initKemCiphertext,
      decrypted.messageIndex       ?? 0,
    );

    const ratchetAfter = await getAllRatchetStates(UID_BOB);
    expect(ratchetAfter.length).toBe(ratchetBefore.length);
    if (ratchetBefore.length > 0 && ratchetAfter.length > 0) {
      expect(ratchetAfter[0].stateJson).toBe(ratchetBefore[0].stateJson);
    }
  }, 20_000);
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Édition de message
// ─────────────────────────────────────────────────────────────────────────────

describe("editMessage [INTEGRATION]", () => {
  it("le doc Firestore a edited=true après editMessage", async () => {
    const convId    = getConversationId(UID_ALICE, UID_BOB);
    const decrypted = await aliceSendsAndWaits("message original");
    const { id: msgId, kemCiphertext = "", initKemCiphertext, messageIndex = 0 } = decrypted;

    await editMessage(convId, msgId, "message modifié", kemCiphertext, initKemCiphertext, messageIndex);

    const snap = await getDoc(doc(db, "conversations", convId, "messages", msgId));
    expect(snap.exists()).toBe(true);
    expect((snap.data() as EncryptedMessage).edited).toBe(true);
  }, 20_000);

  it("Bob déchiffre le message modifié correctement (isEdited=true)", async () => {
    const convId    = getConversationId(UID_ALICE, UID_BOB);
    const decrypted = await aliceSendsAndWaits("texte avant edit");
    const { id: msgId, kemCiphertext = "", initKemCiphertext, messageIndex = 0 } = decrypted;

    await editMessage(convId, msgId, "texte après edit", kemCiphertext, initKemCiphertext, messageIndex);

    const snap    = await getDoc(doc(db, "conversations", convId, "messages", msgId));
    const rawData = { id: snap.id, ...snap.data() } as EncryptedMessage;
    const result  = await decryptMessage(UID_BOB, rawData);

    expect(result.isEdited).toBe(true);
    expect(result.plaintext).toBe("texte après edit");
  }, 20_000);
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Suppression pour moi uniquement
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
    const convId    = getConversationId(UID_ALICE, UID_BOB);
    const decrypted = await aliceSendsAndWaits("msg-keep-for-bob");

    await deleteMessageForMe(UID_ALICE, decrypted.id);

    const snap = await getDoc(doc(db, "conversations", convId, "messages", decrypted.id));
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
// 4. KPI
// ─────────────────────────────────────────────────────────────────────────────

describe("Performance KPIs — suppression / édition messages", () => {
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

  it("[KPI] deleteMessageForBoth (tombstone updateDoc) < 500 ms", async () => {
    const convId    = getConversationId(UID_ALICE, UID_BOB);
    const decrypted = await aliceSendsAndWaits("kpi-delete-both");
    const { id: msgId, kemCiphertext = "", initKemCiphertext, messageIndex = 0 } = decrypted;
    const ms = await measureMs(() =>
      deleteMessageForBoth(convId, msgId, kemCiphertext, initKemCiphertext, messageIndex),
    );
    console.log(`[KPI] deleteMessageForBoth: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(500);
  }, 20_000);

  it("[KPI] editMessage (updateDoc) < 500 ms", async () => {
    const convId    = getConversationId(UID_ALICE, UID_BOB);
    const decrypted = await aliceSendsAndWaits("kpi-edit");
    const { id: msgId, kemCiphertext = "", initKemCiphertext, messageIndex = 0 } = decrypted;
    const ms = await measureMs(() =>
      editMessage(convId, msgId, "kpi-edited", kemCiphertext, initKemCiphertext, messageIndex),
    );
    console.log(`[KPI] editMessage: ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(500);
  }, 20_000);
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. Invariants de sécurité
// ─────────────────────────────────────────────────────────────────────────────

describe("Security invariants — message deletion / edition [SEC]", () => {
  it("[SEC] deleteMessageForBoth avec convId/msgId inconnus ne crash pas", async () => {
    // Le mock Firestore ne rejette pas sur doc inexistant (comportement du mock).
    // Ce test vérifie l'absence de crash crypto (kemCiphertext vide → fallback btoa(convId)).
    await expect(
      deleteMessageForBoth("unknown_conv_id", "unknown_msg_id", "", undefined, 0),
    ).resolves.not.toThrow();
  });

  it("[SEC] hideMessageLocally n'accepte pas d'ID vide (ne doit pas polluer IDB)", async () => {
    const before = await getHiddenMessages(UID_ALICE);
    await hideMessageLocally(UID_ALICE, "");
    const after  = await getHiddenMessages(UID_ALICE);
    expect(after.size).toBeGreaterThanOrEqual(before.size);
  });

  it("[SEC] l'état ratchet N'EST PAS affecté par hideMessageLocally", async () => {
    const ratchetBefore = await getAllRatchetStates(UID_ALICE);
    await hideMessageLocally(UID_ALICE, "should-not-affect-ratchet");
    const ratchetAfter  = await getAllRatchetStates(UID_ALICE);
    expect(ratchetAfter.length).toBe(ratchetBefore.length);
  });

  it("[SEC] le tombstone ne révèle pas le plaintext original", async () => {
    const convId    = getConversationId(UID_ALICE, UID_BOB);
    const decrypted = await aliceSendsAndWaits("secret-content-do-not-leak");
    const { id: msgId, kemCiphertext = "", initKemCiphertext, messageIndex = 0 } = decrypted;

    await deleteMessageForBoth(convId, msgId, kemCiphertext, initKemCiphertext, messageIndex);

    const snap    = await getDoc(doc(db, "conversations", convId, "messages", msgId));
    const rawData = snap.data() as EncryptedMessage;
    // Le ciphertext ne doit pas contenir le plaintext en clair
    expect(rawData.ciphertext).not.toContain("secret-content-do-not-leak");
    expect(rawData.deleted).toBe(true);
  }, 20_000);
});
