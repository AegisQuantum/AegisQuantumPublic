/**
 * setup.ts — Environnement de test pour src/services/
 *
 * Résout :
 *  1. `indexedDB is not defined`     → fake-indexeddb injecté dans globalThis
 *  2. `auth/configuration-not-found` → mock offline de firebase/auth + firebase/firestore
 *
 * Conception :
 *  - L'utilisateur saisit USERNAME + PASSWORD, jamais d'email.
 *  - auth.ts dérive en interne un fakeEmail @aq.local pour Firebase Auth.
 *  - Le mock Auth accepte ce fakeEmail comme clé de lookup uniquement.
 *  - AQUser ne contient que `uid` — aucun email n'est retourné ou stocké.
 *  - Tout est réinitialisé entre chaque test via beforeEach.
 */

// ── 1. Fake IndexedDB ─────────────────────────────────────────────────────
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";

(globalThis as Record<string, unknown>).indexedDB   = new IDBFactory();
(globalThis as Record<string, unknown>).IDBKeyRange = IDBKeyRange;

// ── 2. Mock Firebase Auth ─────────────────────────────────────────────────
import { vi, beforeEach } from "vitest";

let _uidCounter = 0;
// fakeEmail (@aq.local) → { uid, password }
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

    // auth.ts appelle ceci avec fakeEmail = username@aq.local
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
      return { user: { uid } }; // pas d'email dans le retour — auth.ts n'en extrait que uid
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
const _store        = new Map<string, unknown>();
const _snapListeners = new Map<string, Array<(snap: unknown) => void>>();

function _buildSnap(colPath: string) {
  const docs = [..._store.entries()]
    .filter(([k]) => k.startsWith(colPath + "/") && !k.slice(colPath.length + 1).includes("/"))
    .map(([k, v]) => ({ id: k.split("/").pop()!, data: () => v, ...(v as object) }));
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

    collection: vi.fn((_db: unknown, ...segs: string[]) => ({ _path: segs.join("/"), _type: "collection" })),
    doc       : vi.fn((_db: unknown, ...segs: string[]) => ({ _path: segs.join("/"), _type: "doc" })),

    setDoc: vi.fn(async (ref: { _path: string }, data: unknown) => {
      _store.set(ref._path, data);
      const parts = ref._path.split("/"); parts.pop();
      _fireSnap(parts.join("/"));
    }),

    getDoc: vi.fn(async (ref: { _path: string }) => {
      const data = _store.get(ref._path);
      return { exists: () => data !== undefined, data: () => data };
    }),

    addDoc: vi.fn(async (ref: { _path: string }, data: unknown) => {
      const id       = `doc-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      const fullPath = `${ref._path}/${id}`;
      _store.set(fullPath, { id, ...(data as object) });
      _fireSnap(ref._path);
      return { id };
    }),

    getDocs: vi.fn(async (queryRef: { _path: string }) => _buildSnap(queryRef._path)),

    query  : vi.fn((colRef: { _path: string }, ...constraints: unknown[]) => ({
      _path: colRef._path, _constraints: constraints,
    })),
    where  : vi.fn(() => ({})),
    orderBy: vi.fn(() => ({})),

    onSnapshot: vi.fn((queryRef: { _path: string }, cb: (snap: unknown) => void) => {
      const path = queryRef._path;
      if (!_snapListeners.has(path)) _snapListeners.set(path, []);
      _snapListeners.get(path)!.push(cb);
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
  _accounts.clear();
  _uidCounter          = 0;
  _currentFirebaseUser = null;
  _authListeners.length = 0;
  _store.clear();
  _snapListeners.clear();
  (globalThis as Record<string, unknown>).indexedDB = new IDBFactory();
});
