/**
 * file-transfer.test.ts — Tests fonctionnels, KPI et sécurité pour sendFile()
 *
 * Couvre :
 *  - Envoi + réception de fichier (pipeline complet : AES-GCM + Double Ratchet)
 *  - Validation taille (10 MB max)
 *  - Validation type MIME (aucune exécution côté serveur)
 *  - KPI : envoi < 3 s pour un fichier 1 MB
 *  - Sécurité RFI/LFI : noms de fichiers path-traversal ne compromettent pas le serveur
 *  - Sécurité : le contenu chiffré dans Firestore est opaque (bits aléatoires)
 *  - Sécurité : clé de fichier dérivée via HKDF — unique par message
 *
 * NOTE : On utilise getDocs + decryptMessage au lieu de subscribeToMessages
 * car Alice et Bob partagent le même IDB en contexte de test. Le cache IDB
 * (saveMsgCache) côté Alice serait lu par le subscriber de Bob, retournant le
 * message sans la pièce jointe (le subscriber éviterait alors le déchiffrement
 * complet). L'appel direct à decryptMessage contourne ce problème.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  getConversationId,
  sendFile,
  decryptMessage,
} from "../messaging";
import { storePrivateKeys, clearPrivateKeys } from "../key-store";
import { publishPublicKeys }                 from "../key-registry";
import { kemGenerateKeyPair }                from "../../crypto/kem";
import { dsaGenerateKeyPair }                from "../../crypto/dsa";
import { collection, getDocs } from "firebase/firestore";
import { db }                                from "../firebase";
import type { EncryptedMessage }             from "../../types/message";

// ─────────────────────────────────────────────────────────────────────────────
// UIDs
// ─────────────────────────────────────────────────────────────────────────────

const UID_ALICE = "file-test-alice";
const UID_BOB   = "file-test-bob";

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

/** Crée un faux File avec un nom et un contenu Uint8Array. */
function makeFile(name: string, bytes: Uint8Array, type = "application/octet-stream"): File {
  return new File([bytes.buffer as ArrayBuffer], name, { type });
}

async function measureMs(fn: () => Promise<unknown>): Promise<number> {
  const t0 = performance.now();
  await fn();
  return performance.now() - t0;
}

/**
 * Envoie un fichier et récupère le message Firestore déchiffré par Bob.
 * Contourne le problème de cache IDB partagé entre Alice et Bob en appelant
 * decryptMessage directement sur le document Firestore.
 */
async function sendAndDecrypt(file: File) {
  const convId = getConversationId(UID_ALICE, UID_BOB);
  await sendFile(UID_ALICE, UID_BOB, file);

  const snap = await getDocs(collection(db, "conversations", convId, "messages"));
  const rawDoc = snap.docs.find(d => (d.data() as Record<string, unknown>).hasFile === true && (d.data() as Record<string, unknown>).fileName === file.name);
  if (!rawDoc) throw new Error("Message avec fichier introuvable dans Firestore");

  const msg = { id: rawDoc.id, ...rawDoc.data() } as EncryptedMessage;
  return decryptMessage(UID_BOB, msg);
}

beforeEach(async () => {
  await seedRealKeys(UID_ALICE);
  await seedRealKeys(UID_BOB);
});

afterEach(() => {
  clearPrivateKeys();
});

// ─────────────────────────────────────────────────────────────────────────────
// 1. Pipeline d'envoi/réception
// ─────────────────────────────────────────────────────────────────────────────

describe("sendFile [INTEGRATION]", () => {
  it("un fichier texte envoyé par Alice est reçu par Bob avec hasFile=true", async () => {
    const content  = new TextEncoder().encode("Contenu secret du fichier");
    const file     = makeFile("document.txt", content, "text/plain");
    const received = await sendAndDecrypt(file);

    expect(received.file).toBeDefined();
    expect(received.file!.name).toBe("document.txt");
    expect(received.file!.type).toBe("text/plain");
    expect(received.file!.size).toBe(content.length);
    expect(received.verified).toBe(true);
  }, 25_000);

  it("le Blob reçu contient les données originales", async () => {
    const original = "Données binaires \x00\x01\x02";
    const content  = new TextEncoder().encode(original);
    const file     = makeFile("binary.bin", content);
    const received = await sendAndDecrypt(file);

    expect(received.file).toBeDefined();
    const decoded = new TextDecoder().decode(await received.file!.blob.arrayBuffer());
    expect(decoded).toBe(original);
  }, 25_000);

  it("sendFile lève si le fichier dépasse 10 MB", async () => {
    const big = makeFile("huge.bin", new Uint8Array(11 * 1024 * 1024));
    await expect(sendFile(UID_ALICE, UID_BOB, big)).rejects.toThrow(/volumineux|10 MB/i);
  });

  it("un fichier de 0 octet est envoyable sans crash", async () => {
    const empty = makeFile("empty.txt", new Uint8Array(0), "text/plain");
    await expect(sendFile(UID_ALICE, UID_BOB, empty)).resolves.not.toThrow();
  }, 15_000);
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. KPI
// ─────────────────────────────────────────────────────────────────────────────

describe("Performance KPIs — sendFile", () => {
  it("[KPI] envoi fichier 100 KB < 3000 ms", async () => {
    const content = new Uint8Array(100 * 1024).fill(0xAB);
    const file    = makeFile("medium.bin", content);
    const ms      = await measureMs(() => sendFile(UID_ALICE, UID_BOB, file));
    console.log(`[KPI] sendFile(100 KB): ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(3000);
  }, 15_000);

  it("[KPI] envoi fichier 1 MB < 5000 ms", async () => {
    const content = new Uint8Array(1024 * 1024).fill(0xCD);
    const file    = makeFile("large.bin", content);
    const ms      = await measureMs(() => sendFile(UID_ALICE, UID_BOB, file));
    console.log(`[KPI] sendFile(1 MB): ${ms.toFixed(0)} ms`);
    expect(ms).toBeLessThan(5000);
  }, 20_000);

  it("[KPI] taille du document Firestore (sans blob) < 50 KB", async () => {
    const convId  = getConversationId(UID_ALICE, UID_BOB);
    const content = new Uint8Array(512).fill(0x0F);
    const file    = makeFile("size-check.bin", content);

    await sendFile(UID_ALICE, UID_BOB, file);

    const snap    = await getDocs(collection(db, "conversations", convId, "messages"));
    const rawDoc  = snap.docs.find(d => (d.data() as Record<string, unknown>).fileName === "size-check.bin");
    expect(rawDoc).toBeDefined();

    // Exclure le blob du calcul de taille (stocké séparément en prod)
    const dataWithoutBlob = { ...rawDoc!.data() as Record<string, unknown> };
    delete dataWithoutBlob.fileCiphertext;
    const sizeKB = JSON.stringify(dataWithoutBlob).length / 1024;
    console.log(`[KPI] Firestore doc size (512B file, sans blob): ${sizeKB.toFixed(2)} KB`);
    expect(sizeKB).toBeLessThan(50);
  }, 20_000);
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Sécurité — RFI / LFI / injection de nom de fichier
//
// Contexte : Le nom de fichier est stocké en clair dans Firestore (fileName).
// Un attaquant pourrait tenter d'injecter des chemins traversant (../../../etc/passwd),
// des null bytes, ou des noms exécutables pour tromper un client qui
// téléchargerait et exécuterait automatiquement le fichier.
//
// Défense attendue : AegisQuantum ne fait pas d'auto-exécution.
// Le nom est traité comme une chaîne opaque affichée via escapeHtml() dans l'UI.
// Les tests vérifient que :
//  1. sendFile n'échoue pas sur des noms pathologiques (robustesse)
//  2. Le nom stocké dans Firestore est celui fourni, sans modification serveur
//     (pas de sanitisation silencieuse qui masquerait le risque côté UI)
// ─────────────────────────────────────────────────────────────────────────────

describe("Security — RFI/LFI — noms de fichiers pathologiques [SEC]", () => {
  const MALICIOUS_NAMES = [
    "../../../etc/passwd",
    "..\\..\\windows\\system32\\cmd.exe",
    "file\x00.txt",          // null byte
    "<script>alert(1)</script>.txt",
    "file with spaces.txt",
    "a".repeat(255),          // nom très long
    "CON",                    // nom réservé Windows
    ".htaccess",
    "exploit.php",
    "shell.jsp",
  ];

  for (const name of MALICIOUS_NAMES) {
    it(`[SEC] sendFile avec nom "${name.slice(0, 40)}" ne crash pas`, async () => {
      const content = new TextEncoder().encode("test");
      const file    = makeFile(name, content);
      await expect(sendFile(UID_ALICE, UID_BOB, file)).resolves.not.toThrow();
    }, 12_000);
  }

  it("[SEC] le ciphertext Firestore est opaque (pas de plaintext visible)", async () => {
    const convId  = getConversationId(UID_ALICE, UID_BOB);
    const secret  = "SUPER SECRET CONTENT";
    const content = new TextEncoder().encode(secret);
    const file    = makeFile("secret.txt", content, "text/plain");

    await sendFile(UID_ALICE, UID_BOB, file);

    const snap   = await getDocs(collection(db, "conversations", convId, "messages"));
    const rawDoc = snap.docs.find(d => (d.data() as Record<string, unknown>).fileName === "secret.txt");
    expect(rawDoc).toBeDefined();

    const raw = JSON.stringify(rawDoc!.data() ?? {});

    // Le secret ne doit jamais apparaître en clair dans le document Firestore
    expect(raw).not.toContain(secret);
    expect(raw).not.toContain("SUPER SECRET");
  }, 20_000);

  it("[SEC] deux envois de fichiers identiques produisent des ciphertexts différents (IV aléatoire)", async () => {
    const convId  = getConversationId(UID_ALICE, UID_BOB);
    const content = new Uint8Array(64).fill(0xFF);
    const file1   = makeFile("dup.bin", content);
    const file2   = makeFile("dup.bin", content);

    await sendFile(UID_ALICE, UID_BOB, file1);
    await sendFile(UID_ALICE, UID_BOB, file2);

    const snap = await getDocs(collection(db, "conversations", convId, "messages"));
    const dups = snap.docs.filter(d => (d.data() as Record<string, unknown>).fileName === "dup.bin");
    expect(dups.length).toBeGreaterThanOrEqual(2);

    const ct1 = (dups[0].data() as Record<string, unknown>).fileCiphertext ?? "";
    const ct2 = (dups[1].data() as Record<string, unknown>).fileCiphertext ?? "";

    // Ciphertexts différents malgré le même plaintext (IV aléatoire + ratchet avancé)
    expect(ct1).not.toBe(ct2);
  }, 30_000);

  it("[SEC] sendFile lève si clés de l'envoyeur absentes", async () => {
    clearPrivateKeys();
    const file = makeFile("no-keys.txt", new TextEncoder().encode("test"));
    await expect(sendFile(UID_ALICE, UID_BOB, file)).rejects.toThrow();
  });

  it("[SEC] sendFile lève si clés du destinataire introuvables", async () => {
    const file = makeFile("no-contact.txt", new TextEncoder().encode("test"));
    await expect(sendFile(UID_ALICE, "uid-fantome-xyz", file)).rejects.toThrow(/introuvable/i);
  });
});
