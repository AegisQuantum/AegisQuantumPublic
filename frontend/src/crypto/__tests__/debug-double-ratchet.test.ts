/**
 * src/crypto/__tests__/debug-double-ratchet.test.ts
 *
 * Script de stress-test et diagnostic ultra-profond du Double Ratchet ML-KEM-768.
 */

import { it } from "vitest";
import { doubleRatchetEncrypt, doubleRatchetDecrypt } from "../double-ratchet";
import { kemGenerateKeyPair } from "../kem";
import { deserializeRatchetState } from "../ratchet-state";
import type { RatchetState } from "../../types/ratchet";

const ALICE_UID = "QYmzVREnPQMRVARuMYHH1WpJ1dl1";
const BOB_UID   = "e22Kivi4NFR6TinNPf7ebOZKli82";
const CONV_ID   = `conv_${ALICE_UID}_${BOB_UID}`;

// ── Types Firebase simulés ───────────────────────────────────────────────────

interface FirestoreMessageDoc {
  id               : string;
  ciphertext       : string;
  nonce            : string;
  kemCiphertext    : string;
  senderEphPub     : string;
  messageIndex     : number;
  initKemCiphertext?: string;
  senderId         : string;
}

interface FirestoreDB {
  messages     : FirestoreMessageDoc[];
  ratchetStates: Record<string, string | null>;
}

// ── Logging ──────────────────────────────────────────────────────────────────

const RESET  = "\x1b[0m";
const GREEN  = "\x1b[32m";
const RED    = "\x1b[31m";
const YELLOW = "\x1b[33m";
const CYAN   = "\x1b[36m";
const BOLD   = "\x1b[1m";
const DIM    = "\x1b[2m";

let stepCounter = 0;

function logStep(title: string) {
  stepCounter++;
  console.log(`\n${BOLD}${CYAN}━━━ [STEP ${stepCounter}] ${title} ━━━${RESET}`);
}
function logOk(msg: string)   { console.log(`  ${GREEN}✔${RESET}  ${msg}`); }
function logErr(msg: string)  { console.log(`  ${RED}✘${RESET}  ${RED}${msg}${RESET}`); }
function logInfo(msg: string) { console.log(`  ${DIM}ℹ${RESET}  ${msg}`); }
function logWarn(msg: string) { console.log(`  ${YELLOW}⚠${RESET}  ${YELLOW}${msg}${RESET}`); }

function logRatchetState(label: string, stateJson: string) {
  try {
    const s: RatchetState = deserializeRatchetState(stateJson);
    console.log(`\n  ${BOLD}[STATE — ${label}]${RESET}`);
    console.log(`    rootKey           : ${s.rootKey.slice(0, 16)}…`);
    console.log(`    sendingChainKey   : ${s.sendingChainKey   ? s.sendingChainKey.slice(0, 16)   + "…" : "(vide)"}`);
    console.log(`    receivingChainKey : ${s.receivingChainKey ? s.receivingChainKey.slice(0, 16) + "…" : "(vide)"}`);
    console.log(`    ourPublicKey      : ${s.ourPublicKey.slice(0, 16)}…`);
    console.log(`    theirPublicKey    : ${s.theirPublicKey.slice(0, 16)}…`);
    console.log(`    sendCount         : ${s.sendCount}`);
    console.log(`    receiveCount      : ${s.receiveCount}`);
  } catch (e) {
    logErr(`Impossible de désérialiser le state : ${e}`);
  }
}

function assert(condition: boolean, message: string): void {
  if (!condition) {
    logErr(`ASSERTION FAILED : ${message}`);
    throw new Error(`ASSERTION FAILED : ${message}`);
  }
  logOk(`ASSERTION OK     : ${message}`);
}

// ── Firebase helpers (stores locaux passés en argument) ──────────────────────

function saveRatchetState(db: FirestoreDB, uid: string, stateJson: string) {
  db.ratchetStates[uid] = stateJson;
  logInfo(`[Firebase] ratchetState mis à jour pour ${uid === ALICE_UID ? "Alice" : "Bob"}`);
}

function loadRatchetState(db: FirestoreDB, uid: string): string | null {
  return db.ratchetStates[uid] ?? null;
}

function saveMessage(db: FirestoreDB, doc: FirestoreMessageDoc) {
  db.messages.push(doc);
  logInfo(`[Firebase] message#${doc.messageIndex} stocké (sender=${doc.senderId === ALICE_UID ? "Alice" : "Bob"})`);
}

function loadMessage(db: FirestoreDB, index: number): FirestoreMessageDoc | undefined {
  return db.messages.find(m => m.messageIndex === index);
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  // Stores locaux — isolés par run, jamais partagés entre instances parallèles
  const db: FirestoreDB = {
    messages     : [],
    ratchetStates: { [ALICE_UID]: null, [BOB_UID]: null },
  };

  stepCounter = 0;

  console.log(`\n${BOLD}${CYAN}╔════════════════════════════════════════════════════════╗`);
  console.log(`║   DEBUG DOUBLE RATCHET — AegisQuantum (ML-KEM-768)    ║`);
  console.log(`╚════════════════════════════════════════════════════════╝${RESET}`);
  console.log(`  Alice  : ${ALICE_UID}`);
  console.log(`  Bob    : ${BOB_UID}`);
  console.log(`  Conv   : ${CONV_ID}`);

  // ── STEP 1 : Génération des clés long-terme ──────────────────────────────
  logStep("Génération des clés long-terme Alice & Bob");

  const aliceKem = await kemGenerateKeyPair();
  logOk("Alice KEM keypair générée");
  const bobKem = await kemGenerateKeyPair();
  logOk("Bob   KEM keypair générée");

  logInfo(`Alice pubKey : ${aliceKem.publicKey.slice(0, 24)}…`);
  logInfo(`Bob   pubKey : ${bobKem.publicKey.slice(0, 24)}…`);

  // ── STEP 2 : Bootstrap Alice → Bob ──────────────────────────────────────
  logStep("Bootstrap — Alice → Bob (message 0, X3DH)");

  const bootstrapPlaintext = "Salut Bob, c'est le premier message chiffré !";

  let aliceBootstrap: Awaited<ReturnType<typeof doubleRatchetEncrypt>>;
  try {
    aliceBootstrap = await doubleRatchetEncrypt(
      bootstrapPlaintext, null, CONV_ID,
      aliceKem.privateKey, aliceKem.publicKey, bobKem.publicKey,
    );
    logOk("doubleRatchetEncrypt (bootstrap) réussi");
    logInfo(`kemCiphertext     : "${aliceBootstrap.kemCiphertext}" (doit être vide)`);
    logInfo(`initKemCiphertext : ${aliceBootstrap.initKemCiphertext?.slice(0, 24)}…`);
    logInfo(`senderEphPub      : ${aliceBootstrap.senderEphPub.slice(0, 24)}…`);
    logInfo(`messageIndex      : ${aliceBootstrap.messageIndex}`);
  } catch (e) {
    logErr(`doubleRatchetEncrypt bootstrap FAIL : ${e}`);
    throw e;
  }

  saveRatchetState(db, ALICE_UID, aliceBootstrap.newStateJson);
  saveMessage(db, {
    id: "msg_0",
    ciphertext       : aliceBootstrap.ciphertext,
    nonce            : aliceBootstrap.nonce,
    kemCiphertext    : aliceBootstrap.kemCiphertext,
    senderEphPub     : aliceBootstrap.senderEphPub,
    messageIndex     : aliceBootstrap.messageIndex,
    initKemCiphertext: aliceBootstrap.initKemCiphertext,
    senderId         : ALICE_UID,
  });

  logRatchetState("Alice après bootstrap encrypt", aliceBootstrap.newStateJson);

  assert(aliceBootstrap.kemCiphertext === "",  "kemCiphertext vide sur bootstrap");
  assert(aliceBootstrap.messageIndex  === 0,   "messageIndex === 0 sur bootstrap");
  assert(
    typeof aliceBootstrap.initKemCiphertext === "string" && aliceBootstrap.initKemCiphertext.length > 0,
    "initKemCiphertext présent sur bootstrap",
  );

  // Bob déchiffre le bootstrap
  const msgDoc0 = loadMessage(db, 0)!;
  let bobBootstrap: Awaited<ReturnType<typeof doubleRatchetDecrypt>>;
  try {
    bobBootstrap = await doubleRatchetDecrypt(
      msgDoc0.ciphertext, msgDoc0.nonce, msgDoc0.messageIndex,
      msgDoc0.kemCiphertext, msgDoc0.senderEphPub,
      null, CONV_ID,
      bobKem.privateKey, bobKem.publicKey, aliceKem.publicKey,
      msgDoc0.initKemCiphertext,
    );
    logOk("doubleRatchetDecrypt (bootstrap) réussi");
  } catch (e) {
    logErr(`doubleRatchetDecrypt bootstrap FAIL : ${e}`);
    throw e;
  }

  saveRatchetState(db, BOB_UID, bobBootstrap.newStateJson);
  logRatchetState("Bob après bootstrap decrypt", bobBootstrap.newStateJson);

  assert(bobBootstrap.plaintext === bootstrapPlaintext,
    `Bootstrap plaintext OK : "${bobBootstrap.plaintext}"`);
  assert(bobBootstrap.fileSecret.length > 0, "fileSecret présent chez Bob (bootstrap)");

  // ── STEP 3 : 5 messages Alice → Bob ─────────────────────────────────────
  logStep("5 messages successifs Alice → Bob");

  const aliceMessages = [
    "Message 1 : tout va bien de mon côté.",
    "Message 2 : test du ratchet step.",
    "Message 3 : vérification de la rotation des clés.",
    "Message 4 : avant-dernier message de la séquence.",
    "Message 5 : dernier message Alice → Bob de cette séquence.",
  ];

  for (let i = 0; i < aliceMessages.length; i++) {
    const plaintext = aliceMessages[i];
    let encResult: Awaited<ReturnType<typeof doubleRatchetEncrypt>>;

    try {
      encResult = await doubleRatchetEncrypt(
        plaintext, loadRatchetState(db, ALICE_UID), CONV_ID,
        aliceKem.privateKey, aliceKem.publicKey, bobKem.publicKey,
      );
      logOk(`Alice encrypt msg ${i + 1}/5 — messageIndex=${encResult.messageIndex}`);
    } catch (e) {
      logErr(`Alice encrypt msg ${i + 1} FAIL : ${e}`);
      throw e;
    }

    saveRatchetState(db, ALICE_UID, encResult.newStateJson);
    saveMessage(db, {
      id: `msg_${encResult.messageIndex}`,
      ciphertext   : encResult.ciphertext,
      nonce        : encResult.nonce,
      kemCiphertext: encResult.kemCiphertext,
      senderEphPub : encResult.senderEphPub,
      messageIndex : encResult.messageIndex,
      senderId     : ALICE_UID,
    });

    const stateJsonBob = loadRatchetState(db, BOB_UID);
    let decResult: Awaited<ReturnType<typeof doubleRatchetDecrypt>>;
    try {
      decResult = await doubleRatchetDecrypt(
        encResult.ciphertext, encResult.nonce, encResult.messageIndex,
        encResult.kemCiphertext, encResult.senderEphPub,
        stateJsonBob, CONV_ID,
        bobKem.privateKey, bobKem.publicKey, aliceKem.publicKey,
      );
      logOk(`Bob   decrypt msg ${i + 1}/5 — OK`);
    } catch (e) {
      logErr(`Bob decrypt msg ${i + 1} FAIL : ${e}`);
      if (stateJsonBob) logRatchetState("Bob avant decrypt", stateJsonBob);
      throw e;
    }

    saveRatchetState(db, BOB_UID, decResult.newStateJson);
    assert(decResult.plaintext === plaintext,
      `Msg ${i + 1} plaintext OK : "${decResult.plaintext.slice(0, 40)}"`);
    assert(decResult.fileSecret.length > 0, `fileSecret présent msg ${i + 1}`);

    logRatchetState(`Alice après encrypt msg ${i + 1}`, encResult.newStateJson);
    logRatchetState(`Bob   après decrypt msg ${i + 1}`, decResult.newStateJson);
  }

  // ── STEP 4 : 3 réponses Bob → Alice ─────────────────────────────────────
  logStep("3 réponses Bob → Alice (vérification ratchet step inversé)");

  const bobMessages = [
    "Réponse Bob 1 : bien reçu Alice !",
    "Réponse Bob 2 : le ratchet step fonctionne dans les deux sens.",
    "Réponse Bob 3 : clés tournées correctement.",
  ];

  for (let i = 0; i < bobMessages.length; i++) {
    const plaintext = bobMessages[i];
    let encResult: Awaited<ReturnType<typeof doubleRatchetEncrypt>>;

    try {
      encResult = await doubleRatchetEncrypt(
        plaintext, loadRatchetState(db, BOB_UID), CONV_ID,
        bobKem.privateKey, bobKem.publicKey, aliceKem.publicKey,
      );
      logOk(`Bob   encrypt réponse ${i + 1}/3 — messageIndex=${encResult.messageIndex}`);
    } catch (e) {
      logErr(`Bob encrypt réponse ${i + 1} FAIL : ${e}`);
      throw e;
    }

    saveRatchetState(db, BOB_UID, encResult.newStateJson);
    saveMessage(db, {
      id: `bob_msg_${encResult.messageIndex}`,
      ciphertext   : encResult.ciphertext,
      nonce        : encResult.nonce,
      kemCiphertext: encResult.kemCiphertext,
      senderEphPub : encResult.senderEphPub,
      messageIndex : encResult.messageIndex,
      senderId     : BOB_UID,
    });

    const stateJsonAlice = loadRatchetState(db, ALICE_UID);
    let decResult: Awaited<ReturnType<typeof doubleRatchetDecrypt>>;
    try {
      decResult = await doubleRatchetDecrypt(
        encResult.ciphertext, encResult.nonce, encResult.messageIndex,
        encResult.kemCiphertext, encResult.senderEphPub,
        stateJsonAlice, CONV_ID,
        aliceKem.privateKey, aliceKem.publicKey, bobKem.publicKey,
      );
      logOk(`Alice decrypt réponse Bob ${i + 1}/3 — OK`);
    } catch (e) {
      logErr(`Alice decrypt réponse Bob ${i + 1} FAIL : ${e}`);
      if (stateJsonAlice) logRatchetState("Alice avant decrypt", stateJsonAlice);
      throw e;
    }

    saveRatchetState(db, ALICE_UID, decResult.newStateJson);
    assert(decResult.plaintext === plaintext,
      `Réponse Bob ${i + 1} plaintext OK : "${decResult.plaintext.slice(0, 40)}"`);

    logRatchetState(`Bob   après encrypt réponse ${i + 1}`, encResult.newStateJson);
    logRatchetState(`Alice après decrypt réponse ${i + 1}`, decResult.newStateJson);
  }

  // ── STEP 5 : Simulation message perdu (skipped keys) ────────────────────
  //
  // NOTE : Le buffer skippedMessageKeys fonctionne dans la même chaîne symétrique.
  // Ici Bob envoie N et N+1 depuis le même KEM step — Alice reçoit N+1 avant N.
  // _advanceReceivingChain cache la messageKey de N lors du decrypt de N+1,
  // puis la consomme quand N arrive enfin.
  logStep("Simulation message perdu — skipped keys (Bob → Alice, même KEM step)");

  const skippedPlaintext1 = "Bob msg N   — Alice le recevra en second.";
  const skippedPlaintext2 = "Bob msg N+1 — Alice le reçoit en premier.";

  let skippedEncN: Awaited<ReturnType<typeof doubleRatchetEncrypt>>;
  let skippedEncN1: Awaited<ReturnType<typeof doubleRatchetEncrypt>>;

  try {
    // Bob envoie N
    skippedEncN = await doubleRatchetEncrypt(
      skippedPlaintext1, loadRatchetState(db, BOB_UID), CONV_ID,
      bobKem.privateKey, bobKem.publicKey, aliceKem.publicKey,
    );
    logOk(`Bob encrypt msg N   — messageIndex=${skippedEncN.messageIndex}`);

    // Bob envoie N+1 depuis l'état APRÈS N (même KEM step, chaîne symétrique avancée)
    skippedEncN1 = await doubleRatchetEncrypt(
      skippedPlaintext2, skippedEncN.newStateJson, CONV_ID,
      bobKem.privateKey, bobKem.publicKey, aliceKem.publicKey,
    );
    logOk(`Bob encrypt msg N+1 — messageIndex=${skippedEncN1.messageIndex}`);
    saveRatchetState(db, BOB_UID, skippedEncN1.newStateJson);
  } catch (e) {
    logErr(`Bob encrypt skipped keys FAIL : ${e}`);
    throw e;
  }

  logWarn(`Alice reçoit N+1 (index=${skippedEncN1.messageIndex}) AVANT N (index=${skippedEncN.messageIndex})`);

  // Alice reçoit N+1 en premier — _advanceReceivingChain cache la messageKey de N
  try {
    const aliceDecN1 = await doubleRatchetDecrypt(
      skippedEncN1.ciphertext, skippedEncN1.nonce, skippedEncN1.messageIndex,
      skippedEncN1.kemCiphertext, skippedEncN1.senderEphPub,
      loadRatchetState(db, ALICE_UID), CONV_ID,
      aliceKem.privateKey, aliceKem.publicKey, bobKem.publicKey,
    );
    logOk(`Alice decrypt N+1 (reçu en premier) — OK`);
    saveRatchetState(db, ALICE_UID, aliceDecN1.newStateJson);
    assert(aliceDecN1.plaintext === skippedPlaintext2, `Skipped N+1 plaintext OK`);
  } catch (e) {
    logErr(`Alice decrypt N+1 FAIL : ${e}`);
    throw e;
  }

  logWarn(`Alice reçoit maintenant le message retardé N (index=${skippedEncN.messageIndex})`);

  // Alice reçoit N — la messageKey est dans le cache skippedMessageKeys
  try {
    const aliceDecN = await doubleRatchetDecrypt(
      skippedEncN.ciphertext, skippedEncN.nonce, skippedEncN.messageIndex,
      skippedEncN.kemCiphertext, skippedEncN.senderEphPub,
      loadRatchetState(db, ALICE_UID), CONV_ID,
      aliceKem.privateKey, aliceKem.publicKey, bobKem.publicKey,
    );
    logOk(`Alice decrypt N (depuis cache skippedMessageKeys) — OK`);
    saveRatchetState(db, ALICE_UID, aliceDecN.newStateJson);
    assert(aliceDecN.plaintext === skippedPlaintext1, `Skipped N plaintext OK (cache)`);
 // ... (suite du catch de l'étape 5)
  } catch (e) {
    logErr(`Alice decrypt N FAIL : ${e}`);
    logInfo("Note : Si cela échoue, vérifiez la gestion du buffer 'skippedMessageKeys' dans double-ratchet.ts");
    throw e;
  }

  // ── STEP 6 : Vérification finale Firebase ───────────────────────────────
  logStep("Vérification finale — cohérence des états Firebase simulés");

  const finalAliceState = loadRatchetState(db, ALICE_UID)!;
  const finalBobState   = loadRatchetState(db, BOB_UID)!;

  assert(finalAliceState !== null, "Alice a un état ratchet en Firebase");
  assert(finalBobState   !== null, "Bob   a un état ratchet en Firebase");

  const aliceParsed = deserializeRatchetState(finalAliceState);
  const bobParsed   = deserializeRatchetState(finalBobState);

  logInfo(`Alice sendCount    : ${aliceParsed.sendCount}`);
  logInfo(`Alice receiveCount : ${aliceParsed.receiveCount}`);
  logInfo(`Bob   sendCount    : ${bobParsed.sendCount}`);
  logInfo(`Bob   receiveCount : ${bobParsed.receiveCount}`);

  assert(aliceParsed.conversationId === CONV_ID, "Alice conversationId correct");
  assert(bobParsed.conversationId   === CONV_ID, "Bob   conversationId correct");

  console.log(`\n${BOLD}${GREEN}╔════════════════════════════════════════════════════════╗`);
  console.log(`║            TOUS LES TESTS ONT RÉUSSI ✔                ║`);
  console.log(`╚════════════════════════════════════════════════════════╝${RESET}\n`);
}

// L'appel Vitest qui englobe tout
it("double-ratchet stress test", async () => {
  await main();
}, 120_000);