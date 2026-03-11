/**
 * presence.test.ts — Tests unitaires pour presence.ts
 *
 * Couvre :
 *  1. setTyping  — écriture / suppression Firestore
 *  2. subscribeToTyping — filtrage TTL, exclusion myUid
 *  3. markMessageRead  — arrayUnion idempotent
 *  4. markAllRead      — sélection correcte des messages
 *  5. createTypingDebouncer — debounce, stop auto, destroy
 *  6. KPI — latences < seuils
 *  7. Pentests robustesse
 */

import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import {
  setTyping,
  subscribeToTyping,
  markMessageRead,
  markAllRead,
  createTypingDebouncer,
  TYPING_TTL_MS,
  TYPING_STOP_DELAY_MS,
} from '../presence';

// ─────────────────────────────────────────────────────────────────────────────
// Mocks Firestore
// ─────────────────────────────────────────────────────────────────────────────

// Stockage mémoire des docs typing simulés
let _typingDocs: Map<string, { uid: string; updatedAt: number }> = new Map();
// Callbacks d'abonnement onSnapshot actifs
let _snapCallbacks: Array<(docs: typeof _typingDocs) => void> = [];

// Stockage mémoire des readBy par message
let _readByStore: Map<string, string[]> = new Map();

vi.mock('firebase/firestore', () => ({
  collection : vi.fn((_db: unknown, ...segs: string[]) => ({ _path: segs.join('/') })),
  doc        : vi.fn((_db: unknown, ...segs: string[]) => ({ _path: segs.join('/'), _id: segs[segs.length - 1] })),
  setDoc     : vi.fn(async (ref: { _id: string }, data: { uid: string; updatedAt: number }) => {
    _typingDocs.set(ref._id, data);
    _snapCallbacks.forEach(cb => cb(_typingDocs));
  }),
  deleteDoc  : vi.fn(async (ref: { _id: string }) => {
    _typingDocs.delete(ref._id);
    _snapCallbacks.forEach(cb => cb(_typingDocs));
  }),
  updateDoc  : vi.fn(async (ref: { _path: string }, data: { readBy: { _union: string[] } }) => {
    const key      = ref._path;
    const current  = _readByStore.get(key) ?? [];
    const toAdd    = data.readBy?._union ?? [];
    const merged   = Array.from(new Set([...current, ...toAdd]));
    _readByStore.set(key, merged);
  }),
  onSnapshot : vi.fn((_col: { _path: string }, cb: (snap: { docs: Array<{ data: () => unknown }> }) => void) => {
    // Appel immédiat avec l'état courant, puis enregistrement
    const snap = () => ({
      docs: Array.from(_typingDocs.entries()).map(([, v]) => ({ data: () => v })),
    });
    cb(snap());
    const listener = (docs: typeof _typingDocs) => {
      cb({ docs: Array.from(docs.entries()).map(([, v]) => ({ data: () => v })) });
    };
    _snapCallbacks.push(listener);
    return () => { _snapCallbacks = _snapCallbacks.filter(fn => fn !== listener); };
  }),
  arrayUnion : vi.fn((...args: string[]) => ({ _union: args })),
  serverTimestamp: vi.fn(() => Date.now()),
}));

vi.mock('../firebase', () => ({ db: {} }));

// ─────────────────────────────────────────────────────────────────────────────
// Setup
// ─────────────────────────────────────────────────────────────────────────────

beforeEach(() => {
  _typingDocs     = new Map();
  _snapCallbacks  = [];
  _readByStore    = new Map();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
});

// ─────────────────────────────────────────────────────────────────────────────
// 1. setTyping
// ─────────────────────────────────────────────────────────────────────────────

describe('setTyping', () => {
  it('écrit un doc typing quand isTyping=true', async () => {
    const { setDoc } = await import('firebase/firestore');
    await setTyping('conv1', 'alice', true);
    expect(setDoc).toHaveBeenCalledOnce();
  });

  it('supprime le doc typing quand isTyping=false', async () => {
    const { deleteDoc } = await import('firebase/firestore');
    await setTyping('conv1', 'alice', false);
    expect(deleteDoc).toHaveBeenCalledOnce();
  });

  it('ne lance pas d\'exception si deleteDoc échoue (doc inexistant)', async () => {
    const { deleteDoc } = await import('firebase/firestore');
    (deleteDoc as Mock).mockRejectedValueOnce(new Error('not found'));
    await expect(setTyping('conv1', 'alice', false)).resolves.toBeUndefined();
  });

  it('le doc contient uid + updatedAt récent', async () => {
    const before = Date.now();
    await setTyping('conv1', 'alice', true);
    const after  = Date.now();
    const doc = _typingDocs.get('alice');
    expect(doc).toBeDefined();
    expect(doc!.uid).toBe('alice');
    expect(doc!.updatedAt).toBeGreaterThanOrEqual(before);
    expect(doc!.updatedAt).toBeLessThanOrEqual(after);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. subscribeToTyping
// ─────────────────────────────────────────────────────────────────────────────

describe('subscribeToTyping', () => {
  it('callback initial avec liste vide si personne n\'écrit', () => {
    const cb = vi.fn();
    subscribeToTyping('conv1', 'alice', cb);
    expect(cb).toHaveBeenCalledWith([]);
  });

  it('exclut myUid du résultat', async () => {
    _typingDocs.set('alice', { uid: 'alice', updatedAt: Date.now() });
    const cb = vi.fn();
    subscribeToTyping('conv1', 'alice', cb);
    expect(cb).toHaveBeenCalledWith([]);
  });

  it('inclut les autres UIDs en cours d\'écriture', async () => {
    _typingDocs.set('bob', { uid: 'bob', updatedAt: Date.now() });
    const cb = vi.fn();
    subscribeToTyping('conv1', 'alice', cb);
    expect(cb).toHaveBeenCalledWith(['bob']);
  });

  it('filtre les docs expirés (> TTL_MS)', async () => {
    const expiredAt = Date.now() - TYPING_TTL_MS - 1;
    _typingDocs.set('bob', { uid: 'bob', updatedAt: expiredAt });
    const cb = vi.fn();
    subscribeToTyping('conv1', 'alice', cb);
    expect(cb).toHaveBeenCalledWith([]);
  });

  it('inclut un doc à exactement TTL_MS - 1ms (non expiré)', async () => {
    const recentAt = Date.now() - (TYPING_TTL_MS - 1);
    _typingDocs.set('bob', { uid: 'bob', updatedAt: recentAt });
    const cb = vi.fn();
    subscribeToTyping('conv1', 'alice', cb);
    expect(cb).toHaveBeenCalledWith(['bob']);
  });

  it('retourne une fonction unsubscribe fonctionnelle', async () => {
    const cb  = vi.fn();
    const off = subscribeToTyping('conv1', 'alice', cb);
    off();
    // Après unsubscribe, le callback ne devrait plus être appelé
    await setTyping('conv1', 'bob', true);
    expect(cb).toHaveBeenCalledTimes(1); // seulement l'appel initial
  });

  it('met à jour le callback quand un nouvel utilisateur commence à écrire', async () => {
    const cb = vi.fn();
    subscribeToTyping('conv1', 'alice', cb);
    // Simuler bob qui commence à écrire
    await setTyping('conv1', 'bob', true);
    const calls = (cb as Mock).mock.calls.map((c: unknown[][]) => c[0]);
    expect(calls.some((uids: unknown) => Array.isArray(uids) && (uids as string[]).includes('bob'))).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. markMessageRead
// ─────────────────────────────────────────────────────────────────────────────

describe('markMessageRead', () => {
  it('appelle updateDoc avec arrayUnion(uid)', async () => {
    const { updateDoc, arrayUnion } = await import('firebase/firestore');
    await markMessageRead('conv1', 'msg1', 'alice');
    expect(updateDoc).toHaveBeenCalledOnce();
    expect(arrayUnion).toHaveBeenCalledWith('alice');
  });

  it('est idempotent — arrayUnion garantit 1 seul uid dans readBy', async () => {
    await markMessageRead('conv1', 'msg1', 'alice');
    await markMessageRead('conv1', 'msg1', 'alice');
    const stored = _readByStore.get('conversations/conv1/messages/msg1') ?? [];
    expect(stored.filter((u: string) => u === 'alice')).toHaveLength(1);
  });

  it('ne lance pas d\'exception si updateDoc échoue (race condition)', async () => {
    const { updateDoc } = await import('firebase/firestore');
    (updateDoc as Mock).mockRejectedValueOnce(new Error('doc not found'));
    await expect(markMessageRead('conv1', 'msg1', 'alice')).resolves.toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. markAllRead
// ─────────────────────────────────────────────────────────────────────────────

describe('markAllRead', () => {
  it('ne marque pas les messages envoyés par myUid', async () => {
    const { updateDoc } = await import('firebase/firestore');
    const messages = [
      { id: 'msg1', senderUid: 'alice', readBy: [] },
      { id: 'msg2', senderUid: 'alice', readBy: [] },
    ];
    await markAllRead('conv1', messages, 'alice');
    expect(updateDoc).not.toHaveBeenCalled();
  });

  it('marque uniquement les messages reçus non encore lus', async () => {
    const { updateDoc } = await import('firebase/firestore');
    const messages = [
      { id: 'msg1', senderUid: 'bob',   readBy: [] },       // à marquer
      { id: 'msg2', senderUid: 'bob',   readBy: ['alice'] }, // déjà lu
      { id: 'msg3', senderUid: 'alice', readBy: [] },        // notre propre msg
    ];
    await markAllRead('conv1', messages, 'alice');
    expect(updateDoc).toHaveBeenCalledTimes(1);
  });

  it('marque plusieurs messages en parallèle sans erreur', async () => {
    const messages = Array.from({ length: 10 }, (_, i) => ({
      id: `msg${i}`, senderUid: 'bob', readBy: [],
    }));
    await expect(markAllRead('conv1', messages, 'alice')).resolves.toBeUndefined();
  });

  it('gère une liste vide sans erreur', async () => {
    await expect(markAllRead('conv1', [], 'alice')).resolves.toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. createTypingDebouncer
// ─────────────────────────────────────────────────────────────────────────────

describe('createTypingDebouncer', () => {
  it('onInput déclenche setTyping(true) au premier appel', async () => {
    const { setDoc } = await import('firebase/firestore');
    const d = createTypingDebouncer('conv1', 'alice', 1000);
    d.onInput();
    await Promise.resolve();
    expect(setDoc).toHaveBeenCalledOnce();
  });

  it('plusieurs onInput successifs n\'appellent setTyping(true) qu\'une seule fois', async () => {
    const { setDoc } = await import('firebase/firestore');
    const d = createTypingDebouncer('conv1', 'alice', 1000);
    d.onInput();
    d.onInput();
    d.onInput();
    await Promise.resolve();
    expect(setDoc).toHaveBeenCalledTimes(1);
  });

  it('onBlur arrête le typing immédiatement', async () => {
    const { deleteDoc } = await import('firebase/firestore');
    const d = createTypingDebouncer('conv1', 'alice', 1000);
    d.onInput();
    await Promise.resolve();
    d.onBlur();
    await Promise.resolve();
    expect(deleteDoc).toHaveBeenCalledOnce();
  });

  it('arrêt automatique après stopDelay ms d\'inactivité', async () => {
    const { deleteDoc } = await import('firebase/firestore');
    const d = createTypingDebouncer('conv1', 'alice', 500);
    d.onInput();
    await Promise.resolve();
    vi.advanceTimersByTime(500);
    await Promise.resolve();
    expect(deleteDoc).toHaveBeenCalledOnce();
  });

  it('reset du timer si onInput avant la fin du délai', async () => {
    const { deleteDoc } = await import('firebase/firestore');
    const d = createTypingDebouncer('conv1', 'alice', 500);
    d.onInput();
    vi.advanceTimersByTime(400); // pas encore arrêté
    d.onInput();                 // reset du timer
    vi.advanceTimersByTime(400); // toujours pas (400 < 500 depuis dernier onInput)
    await Promise.resolve();
    expect(deleteDoc).not.toHaveBeenCalled();
    vi.advanceTimersByTime(101); // maintenant oui
    await Promise.resolve();
    expect(deleteDoc).toHaveBeenCalledOnce();
  });

  it('destroy nettoie sans erreur même si jamais appelé onInput', () => {
    const d = createTypingDebouncer('conv1', 'alice', 500);
    expect(() => d.destroy()).not.toThrow();
  });

  it('destroy stoppe le typing si actif', async () => {
    const { deleteDoc } = await import('firebase/firestore');
    const d = createTypingDebouncer('conv1', 'alice', 1000);
    d.onInput();
    await Promise.resolve();
    d.destroy();
    await Promise.resolve();
    expect(deleteDoc).toHaveBeenCalledOnce();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. KPI — performance
// ─────────────────────────────────────────────────────────────────────────────

describe('KPI performance', () => {
  beforeEach(() => { vi.useRealTimers(); });
  afterEach  (() => { vi.useFakeTimers(); });

  it('setTyping(true) résout en < 50ms', async () => {
    const t0 = performance.now();
    await setTyping('conv1', 'alice', true);
    expect(performance.now() - t0).toBeLessThan(50);
  });

  it('markMessageRead résout en < 50ms', async () => {
    const t0 = performance.now();
    await markMessageRead('conv1', 'msg1', 'alice');
    expect(performance.now() - t0).toBeLessThan(50);
  });

  it('markAllRead sur 50 messages résout en < 200ms', async () => {
    const messages = Array.from({ length: 50 }, (_, i) => ({
      id: `msg${i}`, senderUid: 'bob', readBy: [],
    }));
    const t0 = performance.now();
    await markAllRead('conv1', messages, 'alice');
    expect(performance.now() - t0).toBeLessThan(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Pentests robustesse
// ─────────────────────────────────────────────────────────────────────────────

describe('Robustesse / pentests', () => {
  it('setTyping avec convId vide ne crash pas', async () => {
    await expect(setTyping('', 'alice', true)).resolves.toBeUndefined();
  });

  it('setTyping avec uid vide ne crash pas', async () => {
    await expect(setTyping('conv1', '', true)).resolves.toBeUndefined();
  });

  it('markMessageRead avec msgId vide ne crash pas', async () => {
    await expect(markMessageRead('conv1', '', 'alice')).resolves.toBeUndefined();
  });

  it('subscribeToTyping avec plusieurs UIDs expirés + valides filtre correctement', () => {
    const now     = Date.now();
    const expired = now - TYPING_TTL_MS - 100;
    _typingDocs.set('bob',   { uid: 'bob',   updatedAt: expired });
    _typingDocs.set('carol', { uid: 'carol', updatedAt: now });
    _typingDocs.set('dave',  { uid: 'dave',  updatedAt: expired });
    const cb = vi.fn();
    subscribeToTyping('conv1', 'alice', cb);
    const received = (cb as Mock).mock.calls[0][0] as string[];
    expect(received).toEqual(['carol']);
  });

  it('markAllRead avec readBy undefined ne crash pas', async () => {
    const messages = [{ id: 'msg1', senderUid: 'bob' }]; // pas de readBy
    await expect(markAllRead('conv1', messages, 'alice')).resolves.toBeUndefined();
  });

  it('createTypingDebouncer avec stopDelay=0 s\'arrête immédiatement', async () => {
    vi.useRealTimers();
    const { deleteDoc } = await import('firebase/firestore');
    const d = createTypingDebouncer('conv1', 'alice', 0);
    d.onInput();
    await new Promise(r => setTimeout(r, 10));
    expect(deleteDoc).toHaveBeenCalled();
    vi.useFakeTimers();
  });

  it('unsubscribe empêche les appels fantômes après fermeture de conv', async () => {
    const cb  = vi.fn();
    const off = subscribeToTyping('conv1', 'alice', cb);
    off();
    const callsBefore = (cb as Mock).mock.calls.length;
    // Simuler un snapshot qui arrive après désabonnement
    await setTyping('conv1', 'bob', true);
    expect((cb as Mock).mock.calls.length).toBe(callsBefore);
  });

  it('TYPING_TTL_MS est bien 5000ms (invariant de sécurité)', () => {
    expect(TYPING_TTL_MS).toBe(5_000);
  });

  it('TYPING_STOP_DELAY_MS est bien 3000ms', () => {
    expect(TYPING_STOP_DELAY_MS).toBe(3_000);
  });
});
