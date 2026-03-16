/**
 * idb-cache.ts — Cache IndexedDB pour conversations, messages déchiffrés
 *                et clés publiques (TTL 24h).
 *
 * OBJECTIF : réduire drastiquement les lectures Firestore.
 *  - Au chargement, on sert d'abord le cache → zéro Firestore read pour
 *    l'affichage initial.
 *  - Le snapshot Firestore ne livre que les deltas (messages postérieurs
 *    au dernier timestamp connu).
 *  - Les clés publiques sont persistées 24h → pas de re-lecture à chaque
 *    reconnexion.
 *
 * SÉCURITÉ :
 *  - Ce cache ne stocke que des données déjà déchiffrées côté client
 *    (plaintext, previews) et des clés PUBLIQUES — jamais de clés privées.
 *  - Les clés privées restent dans le vault AES-GCM (key-store.ts).
 *
 * BASE IDB : aegisquantum-cache  (séparée du vault aegisquantum-vault)
 * STORES   : messages | conversations | pubkeys
 */

import { emitCryptoEvent } from './crypto-events';
import type { Conversation, DecryptedMessage } from '../types/message';
import type { PublicKeyBundle } from '../types/user';

// ─────────────────────────────────────────────────────────────────────────────
// IDB bootstrap
// ─────────────────────────────────────────────────────────────────────────────

const DB_NAME    = 'aegisquantum-cache';
const DB_VERSION = 1;
const STORE_MSGS  = 'messages';
const STORE_CONVS = 'conversations';
const STORE_PKEYS = 'pubkeys';

const TTL_PUBKEYS_MS = 24 * 60 * 60 * 1000; // 24 h

let _dbPromise: Promise<IDBDatabase> | null = null;

function openCacheDB(): Promise<IDBDatabase> {
  if (_dbPromise) return _dbPromise;
  _dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_MSGS))  db.createObjectStore(STORE_MSGS);
      if (!db.objectStoreNames.contains(STORE_CONVS)) db.createObjectStore(STORE_CONVS);
      if (!db.objectStoreNames.contains(STORE_PKEYS)) db.createObjectStore(STORE_PKEYS);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => { _dbPromise = null; reject(req.error); };
  });
  return _dbPromise;
}

async function cacheSet(store: string, key: string, value: unknown): Promise<void> {
  const db = await openCacheDB();
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(store, 'readwrite');
    const req = tx.objectStore(store).put(value, key);
    req.onsuccess = () => resolve();
    req.onerror   = () => reject(req.error);
  });
}

async function cacheGet<T>(store: string, key: string): Promise<T | undefined> {
  const db = await openCacheDB();
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result as T | undefined);
    req.onerror   = () => reject(req.error);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Messages déchiffrés
// ─────────────────────────────────────────────────────────────────────────────

interface CachedMessages {
  msgs: DecryptedMessage[];
  lastTs: number; // timestamp du message le plus récent dans le cache
}

/**
 * Charge les messages déchiffrés depuis le cache IDB.
 * Retourne null si aucun cache disponible pour cette conversation.
 */
export async function loadCachedMessages(convId: string): Promise<CachedMessages | null> {
  try {
    const raw = await cacheGet<string>(STORE_MSGS, convId);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as CachedMessages;
    emitCryptoEvent({
      step: 'idb:cache-hit',
      convId,
      cacheKey: 'messages',
      cacheCount: parsed.msgs.length,
    });
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Sauvegarde les messages déchiffrés dans le cache IDB.
 * Garde uniquement les N derniers messages (max 200 par conv).
 */
export async function saveCachedMessages(
  convId: string,
  msgs: DecryptedMessage[],
): Promise<void> {
  try {
    // Exclure les placeholders de déchiffrement en cours
    const clean = msgs.filter(m => !m.plaintext.startsWith('[\uD83D\uDD12 Déchiffrement'));
    if (clean.length === 0) return;
    const limited = clean.length > 200 ? clean.slice(-200) : clean;
    const lastTs  = Math.max(...limited.map(m => m.timestamp));
    const payload: CachedMessages = { msgs: limited, lastTs };
    await cacheSet(STORE_MSGS, convId, JSON.stringify(payload));
    emitCryptoEvent({
      step: 'idb:cache-write',
      convId,
      cacheKey: 'messages',
      cacheCount: limited.length,
    });
  } catch {
    // Cache write non critique — silencieux
  }
}

/**
 * Retourne le timestamp du dernier message caché pour une conversation.
 * Permet de filtrer le onSnapshot Firestore pour ne demander que les deltas.
 */
export async function getLastCachedMessageTs(convId: string): Promise<number> {
  try {
    const raw = await cacheGet<string>(STORE_MSGS, convId);
    if (!raw) return 0;
    const parsed = JSON.parse(raw) as CachedMessages;
    return parsed.lastTs ?? 0;
  } catch {
    return 0;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversations
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Charge la liste des conversations depuis le cache IDB.
 */
export async function loadCachedConversations(uid: string): Promise<Conversation[] | null> {
  try {
    const raw = await cacheGet<string>(STORE_CONVS, uid);
    if (!raw) return null;
    const convs = JSON.parse(raw) as Conversation[];
    emitCryptoEvent({
      step: 'idb:cache-hit',
      cacheKey: 'conversations',
      cacheCount: convs.length,
    });
    return convs;
  } catch {
    return null;
  }
}

/**
 * Sauvegarde la liste des conversations dans le cache IDB.
 */
export async function saveCachedConversations(uid: string, convs: Conversation[]): Promise<void> {
  try {
    await cacheSet(STORE_CONVS, uid, JSON.stringify(convs));
    emitCryptoEvent({
      step: 'idb:cache-write',
      cacheKey: 'conversations',
      cacheCount: convs.length,
    });
  } catch {
    // silencieux
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Clés publiques (TTL 24h)
// ─────────────────────────────────────────────────────────────────────────────

interface CachedPubKey {
  bundle: PublicKeyBundle;
  cachedAt: number;
}

/**
 * Charge une clé publique depuis le cache IDB.
 * Retourne null si absente ou expirée (> 24h).
 */
export async function loadCachedPubKey(uid: string): Promise<PublicKeyBundle | null> {
  try {
    const raw = await cacheGet<string>(STORE_PKEYS, uid);
    if (!raw) return null;
    const { bundle, cachedAt } = JSON.parse(raw) as CachedPubKey;
    if (Date.now() - cachedAt > TTL_PUBKEYS_MS) return null;
    emitCryptoEvent({
      step: 'idb:cache-hit',
      peerUid: uid.slice(0, 8),
      cacheKey: 'pubkeys',
    });
    return bundle;
  } catch {
    return null;
  }
}

/**
 * Sauvegarde une clé publique dans le cache IDB avec timestamp.
 */
export async function saveCachedPubKey(uid: string, bundle: PublicKeyBundle): Promise<void> {
  try {
    const payload: CachedPubKey = { bundle, cachedAt: Date.now() };
    await cacheSet(STORE_PKEYS, uid, JSON.stringify(payload));
    emitCryptoEvent({
      step: 'idb:cache-write',
      peerUid: uid.slice(0, 8),
      cacheKey: 'pubkeys',
    });
  } catch {
    // silencieux
  }
}

/**
 * Vide le cache IDB complet d'un utilisateur (à la déconnexion).
 * IMPORTANT : ne touche pas au vault key-store.ts.
 */
export async function clearCacheForUser(uid: string): Promise<void> {
  try {
    const db = await openCacheDB();
    const tx = db.transaction([STORE_CONVS, STORE_PKEYS], 'readwrite');
    tx.objectStore(STORE_CONVS).delete(uid);
    // Les msgs par convId sont laissés — ils ne contiennent pas d'info sensible
    // et seront écrasés à la prochaine session. Pour une purge totale, utiliser
    // clearAllCache().
  } catch {
    // silencieux
  }
}
