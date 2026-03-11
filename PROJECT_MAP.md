# AegisQuantum — Carte du projet

> Fichier de référence rapide. À lire en début de chat pour éviter de re-analyser tous les fichiers.
> Mis à jour : 2025-03

---

## Vue d'ensemble

Messagerie E2E post-quantique. SPA TypeScript bundlée par Vite, hébergée sur Firebase Hosting.
Chiffrement 100% client : Firebase ne voit que des blobs chiffrés.

**Stack** : TypeScript · Vite · Firebase (Auth + Firestore + Hosting) · liboqs (WASM) · argon2-browser (CDN)

**Algorithmes** :
- ML-KEM-768 (FIPS 203) — Key Encapsulation (échange de clé post-quantique)
- ML-DSA-65 (FIPS 204 / Dilithium3) — Signatures numériques post-quantiques
- AES-256-GCM — Chiffrement symétrique authentifié
- HKDF-SHA256 — Dérivation de clés
- Argon2id — Dérivation mot de passe → master key

---

## Structure racine

```
AegisQuantum/
├── frontend/           ← Application SPA (tout le code client)
├── admin/              ← Scripts admin (provisioning users, logs dev)
├── shared/             ← Types partagés (si besoin cross-boundary)
├── docs/               ← Documentation complémentaire
├── firebase.json       ← Config Firebase Hosting + Firestore
├── firestore.rules     ← Règles de sécurité Firestore
├── firestore.indexes.json
└── PROJECT_MAP.md      ← CE FICHIER
```

---

## frontend/

```
frontend/
├── index.html                  ← Point d'entrée HTML — importe main.ts, argon2 CDN
├── public/
│   ├── chat.html               ← Template HTML du chat (chargé dynamiquement par initChat)
│   ├── BIGLOGO.png             ← Logo affiché dans la topnav
│   └── dist/                  ← Fichiers liboqs WASM copiés ici par copyLiboqsPlugin
├── src/
│   ├── main.ts                 ← Point d'entrée JS — initialise auth, gère la déconnexion
│   ├── app.ts                  ← (vide — réservé)
│   ├── crypto/                 ← Primitives cryptographiques (voir ci-dessous)
│   ├── services/               ← Couche métier / Firebase (voir ci-dessous)
│   ├── ui/                     ← Contrôleurs UI (voir ci-dessous)
│   ├── types/                  ← Interfaces TypeScript
│   ├── styles/                 ← CSS (chat.css importé dans chat.ts)
│   └── utils/
│       └── logger.ts           ← Intercepte console.* et POST /api/log en dev
├── vite.config.ts              ← Config Vite (plugins liboqs, top-level await, logger)
├── vite-plugin-logger.ts       ← Plugin Vite dev : endpoint POST /api/log → admin/logs/app.log
└── tsconfig.json
```

---

## frontend/src/crypto/ — Primitives cryptographiques

| Fichier | Rôle | API clé |
|---|---|---|
| `index.ts` | Barrel — re-exporte tout crypto/ | — |
| `kem.ts` | ML-KEM-768 (FIPS 203) via liboqs WASM | `kemGenerateKeyPair()`, `kemEncapsulate(pubKey)`, `kemDecapsulate(ct, privKey)`, `toBase64()`, `fromBase64()` |
| `dsa.ts` | ML-DSA-65 / Dilithium3 (FIPS 204) via liboqs WASM | `dsaGenerateKeyPair()`, `dsaSign(msg, privKey)`, `dsaVerify(msg, sig, pubKey)` |
| `hkdf.ts` | HKDF-SHA256 (RFC 5869) via Web Crypto | `hkdfDerive(secretB64, info, len?)`, `hkdfDerivePair(secretB64)`, `HKDF_INFO` (constantes contexte) |
| `aes-gcm.ts` | AES-256-GCM via Web Crypto | `aesGcmEncrypt(plaintext, keyB64)` → `{ciphertext, nonce}`, `aesGcmDecrypt(ct, nonce, keyB64)` → plaintext |
| `argon2.ts` | Argon2id via `window.argon2` (CDN) — 64MB/3iter | `argon2Derive(password, saltB64?)` → `{key, salt}` |
| `double-ratchet.ts` | **STUB** — Double Ratchet à implémenter | `doubleRatchetEncrypt(...)`, `doubleRatchetDecrypt(...)` — **jettent `TODO` pour l'instant** |
| `ratchet-state.ts` | Sérialisation RatchetState JSON | `serializeRatchetState(state)`, `deserializeRatchetState(json)` |

**Invariant** : toutes les clés/ciphertexts circulent en **Base64 string**. Jamais de `Uint8Array` hors de ces modules.

---

## frontend/src/services/ — Couche métier

| Fichier | Rôle | API clé |
|---|---|---|
| `firebase.ts` | Init Firebase app/auth/firestore | Exporte `app`, `auth`, `db` |
| `auth.ts` | Authentification + pipeline crypto au login | `signIn(user, pass)`, `signOut()`, `changePassword(uid, pass)`, `mustChangePassword(uid)`, `onAuthChange(cb)`, `loadCryptoKeys(uid, pass)` |
| `key-store.ts` | Clés privées en mémoire + vault chiffré AES-GCM dans IndexedDB | `storePrivateKeys(uid, bundle)`, `unlockPrivateKeys(uid, masterKey)`, `getKemPrivateKey(uid)`, `getDsaPrivateKey(uid)`, `saveRatchetState(uid, convId, json)`, `loadRatchetState(uid, convId)`, `clearPrivateKeys()` |
| `key-registry.ts` | Clés **publiques** dans Firestore `/publicKeys/{uid}` | `publishPublicKeys(uid, bundle)`, `getPublicKeys(uid)`, `getPublicKeysBatch(uids[])` |
| `messaging.ts` | Envoi/réception de messages chiffrés + abonnements Firestore | `sendMessage(myUid, contactUid, plaintext)`, `decryptMessage(myUid, EncryptedMessage)`, `subscribeToMessages(myUid, convId, cb)`, `subscribeToConversations(myUid, cb)`, `getOrCreateConversation(myUid, contactUid)`, `getConversationId(uid1, uid2)` |
| `presence.ts` | Typing indicator + read receipts | `setTyping(convId, uid, bool)`, `subscribeToTyping(convId, myUid, cb)`, `markMessageRead(convId, msgId, uid)`, `markAllRead(convId, messages[], myUid)`, `createTypingDebouncer(convId, uid)` |

### Flux login (auth.ts)
```
signIn(username, password)
  → Firebase signInWithEmailAndPassword (email = username@aq.local)
  → loadCryptoKeys(uid, password)
      → getPublicKeys(uid) : clés déjà publiées ?
          NON → _generateAndPublishKeys() : génère KEM+DSA, chiffre vault IDB, publie Firestore
          OUI → getDoc("users/uid") pour argon2Salt
              → argon2Derive(password, salt) → masterKey
              → unlockPrivateKeys(uid, masterKey) : déchiffre vault IDB → mémoire
              [échec vault] → _generateAndPublishKeys()
```

### Race condition send (messaging.ts) — CORRIGÉ
Firestore envoie le snapshot local **avant** que `addDoc` retourne l'ID.
Fix : `_storePendingKey(convId, nonce, messageKey)` avant `addDoc`, indexé par nonce (unique).
`decryptMessage` consulte ce cache mémoire en priorité, puis IDB, puis KEM decapsulate.

---

## frontend/src/ui/ — Contrôleurs UI

| Fichier | Rôle |
|---|---|
| `login.ts` | Formulaire login → `aqSignIn()` → navigation vers chat ou change-password |
| `chat.ts` | **Principal** — monte le DOM depuis `public/chat.html`, gère toute l'UI du chat : liste convs, messages, envoi, typing, read receipts, avatar, settings, modales |
| `fingerprint.ts` | Safety Numbers : calcule SHA-256 des clés publiques KEM+DSA des deux participants, affiche en 12 groupes de 5 chiffres |
| `change-password.ts` | Écran changement de mot de passe obligatoire (première connexion) → `changePassword()` → `initChat()` |
| `components.ts` | Composants UI réutilisables (si utilisé) |

### Chargement du template chat
`initChat(uid)` fait un `fetch('/chat.html')` pour charger le template dans `#chat-screen`.
**En prod Firebase** : `/chat.html` doit être exclu du rewrite SPA `** → /index.html`.
Fix dans `firebase.json` : règle explicite `{ source: "/chat.html", destination: "/chat.html" }` en premier.

---

## frontend/src/types/

| Fichier | Types définis |
|---|---|
| `message.ts` | `EncryptedMessage` (doc Firestore), `DecryptedMessage` (UI), `Conversation`, `TypingStatus` |
| `user.ts` | `AQUser { uid }`, `PublicKeyBundle { uid, kemPublicKey, dsaPublicKey, createdAt }` |
| `ratchet.ts` | `RatchetState` — état complet du Double Ratchet (rootKey, chainKeys, counters…) |

---

## Firestore — Collections

| Collection | Document | Contenu | Accès |
|---|---|---|---|
| `/publicKeys/{uid}` | `PublicKeyBundle` | kemPublicKey, dsaPublicKey, uid, createdAt | Lu par tous auth, écrit par le propriétaire |
| `/users/{uid}` | `{ argon2Salt }` | Salt Argon2id pour dériver la master key | Lu/écrit par le propriétaire uniquement |
| `/provisioned/{uid}` | `{ mustChangePassword }` | Flag première connexion, posé par admin | Lu/mis à jour par le propriétaire, pas de create/delete |
| `/conversations/{convId}` | `Conversation` | participants[], lastMessageAt, lastMessagePreview | Participants seulement |
| `/conversations/{convId}/messages/{msgId}` | `EncryptedMessage` | ciphertext, nonce, kemCiphertext, signature, messageIndex, timestamp, readBy[] | Participants seulement |
| `/conversations/{convId}/typing/{uid}` | `{ uid, updatedAt }` | Statut "en train d'écrire" (TTL 5s côté client) | Participants seulement, chacun son propre doc |

**`convId`** = `[uid1, uid2].sort().join("_")` — déterministe et symétrique.

---

## IndexedDB — `aegisquantum-vault`

| Clé IDB | Valeur | Posé par |
|---|---|---|
| `vault:{uid}` | JSON `{ ciphertext, nonce }` — vault AES-GCM des clés privées | `key-store.ts → storePrivateKeys()` |
| `msgkey:{convId}:{msgId}` | Base64 messageKey | `messaging.ts → storeMessageKey()` |
| `ratchet:{uid}:{convId}` | JSON `{ ciphertext, nonce }` ou état brut | `key-store.ts → saveRatchetState()` |

---

## Pipeline message — Envoi

```
sendMessage(myUid, contactUid, plaintext)
  1. getPublicKeys(contactUid)              → kemPublicKey (Firestore)
  2. getDsaPrivateKey(myUid)               → mémoire
  3. kemEncapsulate(kemPublicKey)          → sharedSecret + kemCiphertext (WASM)
  4. hkdfDerive(sharedSecret, INFO)       → messageKey 256 bits
  5. aesGcmEncrypt(plaintext, messageKey) → ciphertext + nonce
  6. dsaSign(ct+nonce+kemCT, dsaPrivKey)  → signature (WASM)
  7. _storePendingKey(convId, nonce, key) ← AVANT addDoc (anti race-condition snapshot)
  8. addDoc(messagesCol)                   → Firestore
  9. storeMessageKey(convId, msgId, key)  → IDB (pour sessions futures)
 10. updateConversationPreview()           → Firestore
```

## Pipeline message — Réception / Déchiffrement

```
decryptMessage(myUid, EncryptedMessage)
  1. getPublicKeys(senderUid)                → dsaPublicKey (Firestore)
  2. dsaVerify(ct+nonce+kemCT, sig, dsaPub)  → verified bool
  3a. _consumePendingKey(convId, nonce)      → messageKey si envoi de cette session (mémoire)
  3b. loadMessageKey(convId, msgId)          → messageKey depuis IDB si déjà vu
  3c. kemDecapsulate(kemCT, kemPrivKey)      → sharedSecret → hkdfDerive → messageKey
      + storeMessageKey() pour futures sessions
  4. aesGcmDecrypt(ciphertext, nonce, key)   → plaintext
```

---

## Double Ratchet (TODO — scaffolding prêt)

`crypto/double-ratchet.ts` contient des **stubs documentés** qui lèvent `TODO`.

Le protocole actuel (sans forward secrecy) : 1 KEM par message → HKDF direct → AES.

Pour brancher le Double Ratchet dans `messaging.ts` :
- Remplacer les étapes 3-5 de `sendMessage` par `doubleRatchetEncrypt(...)`
- Remplacer l'étape 3c de `decryptMessage` par `doubleRatchetDecrypt(...)`
- Appeler `saveRatchetState` / `loadRatchetState` depuis `key-store.ts`
- `messageIndex` passe de `0` fixe à `drResult.messageIndex`

Tout le scaffolding est prêt : types (`ratchet.ts`), sérialisation (`ratchet-state.ts`), stockage IDB (`key-store.ts → saveRatchetState / loadRatchetState`).

---

## Scripts npm (frontend/)

| Commande | Action |
|---|---|
| `npm run dev` | Vite dev server (HMR, plugin logger, liboqs dev middleware) |
| `npm run build` | `tsc && vite build` → `dist/` |
| `npm run preview` | Préview du build prod |
| `npm run test` | Vitest (unit tests) |
| `npm run coverage` | Couverture — seuil 80% sur crypto/ et services/ |

## Déploiement

```bash
cd frontend && npm run build
cd ..
firebase deploy --only hosting    # déploie frontend/dist/
firebase deploy --only firestore  # déploie les règles Firestore
firebase deploy                   # tout
```

---

## Points de vigilance / bugs connus / TODO

| Problème | Statut | Fix / emplacement |
|---|---|---|
| `fetch('/chat.html')` retournait `index.html` en prod (rewrite SPA interceptait) | ✅ Corrigé | `firebase.json` : règle `/chat.html → /chat.html` avant `** → /index.html` |
| Flash "[🔒 non déchiffrable]" à l'envoi (race condition snapshot Firestore) | ✅ Corrigé | `_storePendingKey` avant `addDoc`, retry `setTimeout 80ms` via `scheduleRetry()`, `_evictPendingKey` après persist IDB |
| Double Ratchet / forward secrecy | ⏳ TODO | Stubs dans `crypto/double-ratchet.ts` — tout le scaffolding est prêt |
| `TS6133: 'col' declared but never read` dans `presence.test.ts` | ✅ Corrigé | Renommé en `_col` |
| Typing indicator absent en prod + conv qui clignote à l'envoi | ✅ Corrigé | `renderConversationList` réécrivait `item.innerHTML` à chaque snapshot → listener typing détruit + reflow. Fix : DOM construit une seule fois, mises à jour par `textContent` ciblé |
| `argon2-browser` ne peut pas être bundlé par Vite | ⚠️ Par design | Chargé via `<script>` CDN dans `index.html`, accédé via `window.argon2` |
| Vault IDB perdu si l'user efface les données du navigateur | ⚠️ Par design | Régénère des clés → anciens messages non déchiffrables (sans Double Ratchet) |

---

## Fichiers de config importants

| Fichier | Rôle |
|---|---|
| `firebase.json` | Public dir = `frontend/dist`, rewrites SPA (avec exception `/chat.html`), headers cache |
| `firestore.rules` | Règles sécurité : readBy limité à `arrayUnion(uid)` propre, typing limité à son propre doc |
| `firestore.indexes.json` | Index Firestore (lastMessageAt desc pour conversations) |
| `frontend/vite.config.ts` | Plugins : `topLevelAwait`, `liboqsDevPlugin`, `copyLiboqsPlugin`, `loggerPlugin` |
| `frontend/tsconfig.json` | Target ES2022, strict |
| `frontend/.env.local` | Variables d'env locales (non commité — voir `.env.example`) |
| `frontend/src/pages/chat.html` | ⚠️ INUTILISÉ — le vrai template est `public/chat.html` |
