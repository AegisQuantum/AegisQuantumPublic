/**
 * setup.ts — Environnement de test pour src/services/
 *
 * Résout :
 *  1. `indexedDB is not defined`     → fake-indexeddb injecté dans globalThis
 *  2. `auth/configuration-not-found` → mock offline de firebase/auth + firebase/firestore
 *  3. `argon2/liboqs not loaded`     → mock de src/crypto (PBKDF2 + clés fictives)
 *  4. `file.arrayBuffer is not a function` → polyfill Blob/File.prototype.arrayBuffer
 *  5. `localStorage.setItem is not a function` → polyfill localStorage
 *
 * Note sur vi.mock et les chemins :
 *  - vi.mock() dans un setupFile résout les chemins relativement à ce fichier.
 *  - "../../crypto" depuis src/services/__tests__/ → src/crypto/index.ts ✓
 *  - Ce mock s'applique à TOUS les modules qui importent "../crypto"
 *    (notamment key-store.ts et auth.ts dans src/services/).
 *
 * Note sur _accounts :
 *  - La Map des comptes Firebase est CONSERVÉE entre les tests.
 *  - Cela permet aux beforeAll de provisionner des comptes stables
 *    réutilisables dans toute la suite sans re-provisionner entre tests.
 *  - Seuls l'état de connexion courant, Firestore, et IDB sont réinitialisés.
 */

// ── 1. Fake IndexedDB ─────────────────────────────────────────────────────
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";

(globalThis as Record<string, unknown>).indexedDB   = new IDBFactory();
(globalThis as Record<string, unknown>).IDBKeyRange = IDBKeyRange;

// ── 1b. Polyfill File/Blob.prototype.arrayBuffer ──────────────────────────
// jsdom (used by vitest services environment) may not implement arrayBuffer()
// on Blob/File. This polyfill uses FileReader which IS available in jsdom.
if (typeof Blob !== "undefined" && typeof (Blob.prototype as unknown as { arrayBuffer?: unknown }).arrayBuffer !== "function") {
  Object.defineProperty(Blob.prototype, "arrayBuffer", {
    value: function (this: Blob): Promise<ArrayBuffer> {
      return new Promise<ArrayBuffer>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload  = () => resolve(reader.result as ArrayBuffer);
        reader.onerror = () => reject(reader.error);
        reader.readAsArrayBuffer(this);
      });
    },
    writable: true,
    configurable: true,
  });
}
if (typeof File !== "undefined" && typeof (File.prototype as unknown as { arrayBuffer?: unknown }).arrayBuffer !== "function") {
  File.prototype.arrayBuffer = Blob.prototype.arrayBuffer as () => Promise<ArrayBuffer>;
}

// ── 1c. Polyfill localStorage ─────────────────────────────────────────────
// jsdom should provide localStorage, but some versions have it broken.
(function ensureLocalStorage() {
  try {
    globalThis.localStorage.setItem("__aq_probe__", "1");
    globalThis.localStorage.removeItem("__aq_probe__");
  } catch {
    const _data: Record<string, string> = {};
    const _mock = {
      getItem   : (k: string) => _data[k] ?? null,
      setItem   : (k: string, v: string) => { _data[k] = String(v); },
      removeItem: (k: string) => { delete _data[k]; },
      clear     : () => { for (const k of Object.keys(_data)) delete _data[k]; },
      get length() { return Object.keys(_data).length; },
      key       : (i: number) => Object.keys(_data)[i] ?? null,
    } as Storage;
    Object.defineProperty(globalThis, "localStorage", {
      value: _mock, writable: false, configurable: true,
    });
  }
})();

// ── 2. Mock src/crypto ────────────────────────────────────────────────────
// Doit être déclaré AVANT les imports qui en dépendent.
// Le chemin "../../crypto" est résolu depuis src/services/__tests__/
// → correspond à src/crypto/index.ts, qui est le module importé par
//   key-store.ts ("../crypto") et auth.ts ("../crypto").

import { vi, beforeEach } from "vitest";

vi.mock("../../crypto", () => {
  let _keyCounter = 0;

  // Helper Base64 sans dépendance externe
  const _b64 = (b: Uint8Array): string => {
    let s = ""; for (const x of b) s += String.fromCharCode(x); return btoa(s);
  };
  const _fromb64 = (s: string): Uint8Array =>
    Uint8Array.from(atob(s), c => c.charCodeAt(0));

  return {
    // ── argon2Derive → PBKDF2-SHA256, zéro WASM ──────────────────────────
    argon2Derive: vi.fn(async (password: string, saltB64?: string) => {
      const saltBytes = saltB64 ? _fromb64(saltB64) : crypto.getRandomValues(new Uint8Array(16));
      const km = await crypto.subtle.importKey(
        "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
      );
      const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt: saltBytes as unknown as BufferSource, iterations: 1 }, km, 256
      ); //HERE FIX
      return { key: _b64(new Uint8Array(bits)), salt: _b64(saltBytes) };
    }),

    // ── KEM keypair → Base64 fictif unique ──────────────────────────────
    kemGenerateKeyPair: vi.fn(async () => {
      const id = ++_keyCounter;
      return {
        publicKey : btoa(`kem-pub-${id}-` + "x".repeat(20)),
        privateKey: btoa(`kem-priv-${id}-` + "y".repeat(20)),
      };
    }),

    // ── DSA keypair → Base64 fictif unique ──────────────────────────────
    dsaGenerateKeyPair: vi.fn(async () => {
      const id = ++_keyCounter;
      return {
        publicKey : btoa(`dsa-pub-${id}-` + "a".repeat(20)),
        privateKey: btoa(`dsa-priv-${id}-` + "b".repeat(20)),
      };
    }),

    // ── Crypto primitives légères ────────────────────────────────────────
    dsaSign   : vi.fn(async () => btoa("mock-sig")),
    dsaVerify : vi.fn(async () => true),

    kemEncapsulate: vi.fn(async () => ({
      sharedSecret: btoa("mock-shared-secret-32bytes====="),
      ciphertext  : btoa("mock-kem-ciphertext"),
    })),
    kemDecapsulate: vi.fn(async () => btoa("mock-shared-secret-32bytes=====")),

    // ── aesGcmEncrypt / Decrypt → pass-through SubtleCrypto ─────────────
    // Utilisés dans saveRatchetState / loadRatchetState (key-store.ts).
    // On les laisse fonctionnels pour que les tests ratchet passent.
    aesGcmEncrypt: vi.fn(async (plaintext: string, keyB64: string) => {
      const keyBytes = new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(keyB64))
      );
      const key   = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const enc   = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, tagLength: 128 }, key, new TextEncoder().encode(plaintext));
      return { ciphertext: _b64(new Uint8Array(enc)), nonce: _b64(nonce) };
    }),

    aesGcmDecrypt: vi.fn(async (ciphertextB64: string, nonceB64: string, keyB64: string) => {
      const keyBytes = new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(keyB64))
      );
      const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
      const dec = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: _fromb64(nonceB64) as unknown as BufferSource, tagLength: 128 },
        key, _fromb64(ciphertextB64) as unknown as BufferSource
      ); //HERE FIX
      return new TextDecoder().decode(dec);
    }),

    // ── Helpers Base64 re-exportés ───────────────────────────────────────
    toBase64  : vi.fn(_b64),
    fromBase64: vi.fn(_fromb64),

    // ── Autres exports (non utilisés dans les tests mais exportés) ───────
    hkdfDerive       : vi.fn(async () => btoa("mock-hkdf-32bytes==============")),
    hkdfDerivePair   : vi.fn(async () => ({ rootKey: btoa("rk"), sendingChainKey: btoa("ck") })),
    HKDF_INFO        : "aegisquantum-v1",
    doubleRatchetEncrypt: vi.fn(async () => ({
      ciphertext: btoa("mock-ct"), nonce: btoa("mock-nonce"),
      kemCiphertext: btoa("mock-kem"), messageIndex: 0, newStateJson: "{}"
    })),
    doubleRatchetDecrypt: vi.fn(async () => ({ plaintext: "mock-plaintext", newStateJson: "{}" })),
    serializeRatchetState  : vi.fn((s: unknown) => JSON.stringify(s)),
    deserializeRatchetState: vi.fn((s: string) => JSON.parse(s)),
  };
});

// ── 3. Mock Firebase Auth ─────────────────────────────────────────────────
// _accounts est persisté entre les tests pour les beforeAll de provisioning.
const _accounts = new Map<string, { uid: string; password: string }>();
let   _uidCounter = 0;
let   _currentFirebaseUser: { uid: string } | null = null;
const _authListeners: Array<(user: { uid: string } | null) => void> = [];

function _notifyAuth(user: { uid: string } | null) {
  _currentFirebaseUser = user;
  for (const cb of _authListeners) cb(user);
}

vi.mock("firebase/auth", async () => {
  const actual = await vi.importActual<typeof import("firebase/auth")>("firebase/auth");
  return {
    ...actual,
    // auth object with currentUser getter so auth.currentUser works in deleteAccount, etc.
    getAuth: vi.fn(() => ({
      _mock: true,
      get currentUser() { return _currentFirebaseUser; },
    })),

    createUserWithEmailAndPassword: vi.fn(async (_auth: unknown, fakeEmail: string, password: string) => {
      if (!fakeEmail?.includes("@"))
        throw Object.assign(new Error("Firebase: Error (auth/invalid-email)."), { code: "auth/invalid-email" });
      if (!password || password.length < 6)
        throw Object.assign(new Error("Firebase: Error (auth/weak-password)."), { code: "auth/weak-password" });
      if (_accounts.has(fakeEmail))
        throw Object.assign(new Error("Firebase: Error (auth/email-already-in-use)."), { code: "auth/email-already-in-use" });
      const uid = `mock-uid-${++_uidCounter}-${Date.now()}`;
      _accounts.set(fakeEmail, { uid, password });
      _notifyAuth({ uid });
      return { user: { uid } };
    }),

    signInWithEmailAndPassword: vi.fn(async (_auth: unknown, fakeEmail: string, password: string) => {
      if (!fakeEmail?.includes("@"))
        throw Object.assign(new Error("Firebase: Error (auth/invalid-email)."), { code: "auth/invalid-email" });
      if (!password)
        throw Object.assign(new Error("Firebase: Error (auth/missing-password)."), { code: "auth/missing-password" });
      const account = _accounts.get(fakeEmail);
      if (!account || account.password !== password)
        throw Object.assign(new Error("Firebase: Error (auth/wrong-password)."), { code: "auth/wrong-password" });
      _notifyAuth({ uid: account.uid });
      return { user: { uid: account.uid } };
    }),

    signOut: vi.fn(async () => { _notifyAuth(null); }),

    onAuthStateChanged: vi.fn((_auth: unknown, cb: (u: { uid: string } | null) => void) => {
      _authListeners.push(cb);
      cb(_currentFirebaseUser);
      return () => {
        const i = _authListeners.indexOf(cb);
        if (i !== -1) _authListeners.splice(i, 1);
      };
    }),

    updatePassword: vi.fn(async () => {}),

    // deleteUser — supprime le compte du mock et notifie les listeners
    deleteUser: vi.fn(async (user: { uid: string }) => {
      for (const [email, acct] of _accounts.entries()) {
        if (acct.uid === user.uid) { _accounts.delete(email); break; }
      }
      _notifyAuth(null);
    }),
  };
});

// ── 4. Mock Firebase Firestore ────────────────────────────────────────────
const _store         = new Map<string, unknown>();
const _snapListeners = new Map<string, Array<(snap: unknown) => void>>();
const _listenerSeenIds = new Map<(snap: unknown) => void, Set<string>>();

function _buildSnap(colPath: string, seenIds?: Set<string>) {
  const docs = [..._store.entries()]
    .filter(([k]) => k.startsWith(colPath + "/") && !k.slice(colPath.length + 1).includes("/"))
    .map(([k, v]) => ({
      id  : k.split("/").pop()!,
      ref : { _path: k, _type: "doc" },    // ← ref needed for batch.delete(doc.ref)
      data: () => v,
      ...(v as object),
    }));
  const changes = seenIds
    ? docs.map(d => ({ type: seenIds.has(d.id) ? "modified" : "added", doc: d }))
    : docs.map(d => ({ type: "added", doc: d }));
  if (seenIds) docs.forEach(d => seenIds.add(d.id));
  return { docs, empty: docs.length === 0, forEach: (fn: (d: unknown) => void) => docs.forEach(fn), docChanges: () => changes };
}

function _fireSnap(colPath: string) {
  for (const cb of _snapListeners.get(colPath) ?? []) {
    const seenIds = _listenerSeenIds.get(cb) ?? new Set<string>();
    _listenerSeenIds.set(cb, seenIds);
    cb(_buildSnap(colPath, seenIds));
  }
}

vi.mock("firebase/firestore", async () => {
  const actual = await vi.importActual<typeof import("firebase/firestore")>("firebase/firestore");
  return {
    ...actual,
    getFirestore: vi.fn(() => ({ _mock: true })),

    // collection(db, "conversations", convId, "messages")
    //   → { _path: "conversations/convId/messages" }
    collection: vi.fn((dbOrRef: unknown, ...segs: string[]) => {
      const base = (dbOrRef as { _path?: string })?._path;
      const path = base ? [base, ...segs].join("/") : segs.join("/");
      return { _path: path, _type: "collection" };
    }),

    // doc(db, "conversations", convId, "messages", msgId)
    //   → { _path: "conversations/convId/messages/msgId" }
    // doc(collection(db, ...), msgId)
    //   → { _path: "conversations/.../msgId" }  (prepends collection path)
    doc: vi.fn((dbOrRef: unknown, ...segs: string[]) => {
      const base = (dbOrRef as { _path?: string; _mock?: boolean })?._path;
      const path = base ? [base, ...segs].join("/") : segs.join("/");
      return { _path: path, _type: "doc" };
    }),

    setDoc: vi.fn(async (ref: { _path: string }, data: unknown) => {
      _store.set(ref._path, data);
      const parts = ref._path.split("/"); parts.pop(); _fireSnap(parts.join("/"));
    }),
    getDoc: vi.fn(async (ref: { _path: string }) => {
      const data = _store.get(ref._path);
      return { exists: () => data !== undefined, data: () => data };
    }),
    addDoc: vi.fn(async (ref: { _path: string }, data: unknown) => {
      const id = `doc-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      const fullPath = `${ref._path}/${id}`;
      _store.set(fullPath, { id, ...(data as object) }); _fireSnap(ref._path);
      return { id };
    }),
    updateDoc: vi.fn(async (ref: { _path: string }, data: unknown) => {
      const existing = _store.get(ref._path) ?? {};
      _store.set(ref._path, { ...(existing as object), ...(data as object) });
      const parts = ref._path.split("/"); parts.pop(); _fireSnap(parts.join("/"));
    }),

    // deleteDoc — supprime un document de _store et notifie les listeners
    deleteDoc: vi.fn(async (ref: { _path: string }) => {
      _store.delete(ref._path);
      const parts = ref._path.split("/"); parts.pop();
      _fireSnap(parts.join("/"));
    }),

    // writeBatch — lot de mutations exécutées atomiquement (simulé séquentiellement)
    writeBatch: vi.fn((_db: unknown) => {
      const ops: Array<() => void> = [];
      const batch = {
        delete: (ref: { _path: string }) => {
          ops.push(() => {
            _store.delete(ref._path);
            const parts = ref._path.split("/"); parts.pop();
            _fireSnap(parts.join("/"));
          });
          return batch;
        },
        set: (ref: { _path: string }, data: unknown, _opts?: unknown) => {
          ops.push(() => {
            _store.set(ref._path, data);
            const parts = ref._path.split("/"); parts.pop();
            _fireSnap(parts.join("/"));
          });
          return batch;
        },
        update: (ref: { _path: string }, data: unknown) => {
          ops.push(() => {
            const existing = _store.get(ref._path) ?? {};
            _store.set(ref._path, { ...(existing as object), ...(data as object) });
            const parts = ref._path.split("/"); parts.pop();
            _fireSnap(parts.join("/"));
          });
          return batch;
        },
        commit: async () => { for (const op of ops) op(); },
      };
      return batch;
    }),

    arrayUnion: vi.fn((...items: unknown[]) => items),
    getDocs   : vi.fn(async (queryRef: { _path: string }) => _buildSnap(queryRef._path)),
    query     : vi.fn((colRef: { _path: string }, ...constraints: unknown[]) => ({ _path: colRef._path, _constraints: constraints })),
    where     : vi.fn(() => ({})),
    orderBy   : vi.fn(() => ({})),
    onSnapshot: vi.fn((queryRef: { _path: string }, cb: (snap: unknown) => void) => {
      const path = queryRef._path;
      if (!_snapListeners.has(path)) _snapListeners.set(path, []);
      _snapListeners.get(path)!.push(cb);
      const seenIds = new Set<string>();
      _listenerSeenIds.set(cb, seenIds);
      setTimeout(() => cb(_buildSnap(path, seenIds)), 0);
      return () => {
        const list = _snapListeners.get(path) ?? []; const i = list.indexOf(cb);
        if (i !== -1) list.splice(i, 1); _listenerSeenIds.delete(cb);
      };
    }),
    serverTimestamp: vi.fn(() => Date.now()),
  };
});

// ── 5. Reset entre chaque test ────────────────────────────────────────────
// _accounts est CONSERVÉ (comptes provisionnés par beforeAll restent actifs).
// IDB est recréé pour l'isolation (chaque test part d'un vault vide).
beforeEach(() => {
  _currentFirebaseUser  = null;
  _authListeners.length = 0;
  _store.clear();
  _snapListeners.clear();
  _listenerSeenIds.clear();
  (globalThis as Record<string, unknown>).indexedDB = new IDBFactory();
});
