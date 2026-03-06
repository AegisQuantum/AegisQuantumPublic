/**
 * setup.ts — Environnement de test pour src/services/
 *
 * Problèmes résolus :
 *  1. `indexedDB is not defined`       → fake-indexeddb injecté dans globalThis
 *  2. `auth/configuration-not-found`   → mock offline firebase/auth + firebase/firestore
 *
 * Conception :
 *  - Pas d'email stocké nulle part — l'identité est uniquement le uid Firebase.
 *  - Le mock Auth utilise email+password comme vecteur de connexion (Firebase le requiert)
 *    mais l'uid retourné dans AQUser ne contient PAS d'email.
 *  - Le mock Firestore est un Map en mémoire qui simule setDoc/getDoc/addDoc/onSnapshot.
 *  - Tout est réinitialisé entre chaque test via beforeEach.
 */

// ── 1. Fake IndexedDB ─────────────────────────────────────────────────────
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";

(globalThis as Record<string, unknown>).indexedDB   = new IDBFactory();
(globalThis as Record<string, unknown>).IDBKeyRange = IDBKeyRange;

// ── 2. Mock Firebase Auth ─────────────────────────────────────────────────
import { vi, beforeEach } from "vitest";

// Compteur d'UIDs — garantit l'unicité même si plusieurs tests créent le même email
let _uidCounter = 0;

// Stocke email → { uid, password } — email utilisé UNIQUEMENT comme clé de lookup Auth
// Il n'est jamais exposé dans les retours de service ni dans Firestore
const _accounts = new Map<string, { uid: string; password: string }>();

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

    getAuth: vi.fn(() => ({ _mock: true })),

    createUserWithEmailAndPassword: vi.fn(async (_auth: unknown, email: string, password: string) => {
      if (!email?.includes("@"))
        throw Object.assign(new Error("Firebase: Error (auth/invalid-email)."),   { code: "auth/invalid-email" });
      if (!password || password.length < 6)
        throw Object.assign(new Error("Firebase: Error (auth/weak-password)."),   { code: "auth/weak-password" });
      if (_accounts.has(email))
        throw Object.assign(new Error("Firebase: Error (auth/email-already-in-use)."), { code: "auth/email-already-in-use" });

      const uid = `mock-uid-${++_uidCounter}-${Date.now()}`;
      _accounts.set(email, { uid, password });
      _notifyAuth({ uid });
      // email présent dans le user Firebase (requis par l'API) mais ignoré par nos services
      return { user: { uid, email } };
    }),

    signInWithEmailAndPassword: vi.fn(async (_auth: unknown, email: string, password: string) => {
      if (!email?.includes("@"))
        throw Object.assign(new Error("Firebase: Error (auth/invalid-email)."),    { code: "auth/invalid-email" });
      if (!password)
        throw Object.assign(new Error("Firebase: Error (auth/missing-password)."), { code: "auth/missing-password" });
      const account = _accounts.get(email);
      if (account?.password !== password)
        throw Object.assign(new Error("Firebase: Error (auth/wrong-password)."),   { code: "auth/wrong-password" });

      _notifyAuth({ uid: account.uid });
      return { user: { uid: account.uid, email } };
    }),

    signOut: vi.fn(async (_auth: unknown) => {
      _notifyAuth(null);
    }),

    onAuthStateChanged: vi.fn((_auth: unknown, cb: (u: { uid: string } | null) => void) => {
      _authListeners.push(cb);
      cb(_currentFirebaseUser); // appel immédiat comme Firebase
      return () => {
        const i = _authListeners.indexOf(cb);
        if (i !== -1) _authListeners.splice(i, 1);
      };
    }),
  };
});

// ── 3. Mock Firebase Firestore ────────────────────────────────────────────
// Store en mémoire : Map<docPath, data>
// Paths : "col/docId" pour un document, "col/docId/subCol/subDocId" pour sous-collection

const _store       = new Map<string, unknown>();
const _snapListeners = new Map<string, Array<(snap: unknown) => void>>();

/** Construit un snapshot Firestore-like à partir du store en mémoire */
function _buildSnap(colPath: string) {
  const docs = [..._store.entries()]
    .filter(([k]) => {
      if (!k.startsWith(colPath + "/")) return false;
      // Uniquement les documents directs (pas les sous-collections)
      return !k.slice(colPath.length + 1).includes("/");
    })
    .map(([k, v]) => ({
      id  : k.split("/").pop()!,
      data: () => v,
      ...(v as object),
    }));
  return {
    docs,
    empty  : docs.length === 0,
    forEach: (fn: (d: unknown) => void) => docs.forEach(fn),
  };
}

function _fireSnap(colPath: string) {
  const snap = _buildSnap(colPath);
  for (const cb of _snapListeners.get(colPath) ?? []) cb(snap);
}

vi.mock("firebase/firestore", async () => {
  const actual = await vi.importActual<typeof import("firebase/firestore")>("firebase/firestore");
  return {
    ...actual,

    getFirestore: vi.fn(() => ({ _mock: true })),

    // Références — retournent des objets avec _path pour les autres mocks
    collection: vi.fn((_db: unknown, ...segs: string[]) => ({
      _path: segs.join("/"),
      _type: "collection",
    })),
    doc: vi.fn((_db: unknown, ...segs: string[]) => ({
      _path: segs.join("/"),
      _type: "doc",
    })),

    // Écriture document
    setDoc: vi.fn(async (ref: { _path: string }, data: unknown) => {
      _store.set(ref._path, data);
      const parts = ref._path.split("/");
      parts.pop();
      _fireSnap(parts.join("/"));
    }),

    // Lecture document
    getDoc: vi.fn(async (ref: { _path: string }) => {
      const data = _store.get(ref._path);
      return { exists: () => data !== undefined, data: () => data };
    }),

    // Ajout document avec ID auto
    addDoc: vi.fn(async (ref: { _path: string }, data: unknown) => {
      const id       = `doc-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      const fullPath = `${ref._path}/${id}`;
      _store.set(fullPath, { id, ...(data as object) });
      _fireSnap(ref._path);
      return { id };
    }),

    // Lecture collection (query simplifiée — pas de filtrage réel en mock)
    getDocs: vi.fn(async (queryRef: { _path: string }) => _buildSnap(queryRef._path)),

    // Helpers query (stub — le mock getDocs ne filtre pas)
    query  : vi.fn((colRef: { _path: string }, ...constraints: unknown[]) => ({
      _path       : colRef._path,
      _constraints: constraints,
    })),
    where  : vi.fn(() => ({})),
    orderBy: vi.fn(() => ({})),

    // Listener temps-réel
    onSnapshot: vi.fn((queryRef: { _path: string }, cb: (snap: unknown) => void) => {
      const path = queryRef._path;
      if (!_snapListeners.has(path)) _snapListeners.set(path, []);
      _snapListeners.get(path)!.push(cb);

      // Appel initial asynchrone (comme Firestore)
      setTimeout(() => cb(_buildSnap(path)), 0);

      return () => {
        const list = _snapListeners.get(path) ?? [];
        const i    = list.indexOf(cb);
        if (i !== -1) list.splice(i, 1);
      };
    }),

    serverTimestamp: vi.fn(() => Date.now()),
  };
});

// ── 4. Reset entre chaque test ────────────────────────────────────────────

beforeEach(() => {
  // Auth
  _accounts.clear();
  _uidCounter          = 0;
  _currentFirebaseUser = null;
  _authListeners.length = 0;

  // Firestore
  _store.clear();
  _snapListeners.clear();

  // IndexedDB — nouvelle instance vierge (isolation complète)
  (globalThis as Record<string, unknown>).indexedDB = new IDBFactory();
});
