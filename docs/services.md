# Couche Services — AegisQuantum

La couche services orchestre la logique métier entre l'UI et la couche crypto. Elle gère l'accès à Firebase, la persistance locale (IndexedDB), et l'état applicatif.

---

## `services/firebase.ts`

**Rôle :** Initialise l'application Firebase et exporte les singletons.

```typescript
export const app  = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db   = initializeFirestore(app, {
  experimentalAutoDetectLongPolling: true,
});
```

**Pourquoi `experimentalAutoDetectLongPolling` ?**
Safari bloque les WebChannel (WebSocket-like) en raison de sa politique CORS stricte. Ce flag active automatiquement le long-polling comme fallback, ce qui corrige les erreurs CORS sur Safari sans impact sur les autres navigateurs.

---

## `services/auth.ts`

**Rôle :** Gestion complète du cycle de vie d'un compte — connexion, vault, provisioning, suppression.

### Fonctions principales

**`signIn(username, password)`**
1. `Firebase.signInWithEmailAndPassword(auth, email, password)`
2. Lit le salt Argon2 depuis Firestore `/users/{uid}`
3. `argon2Derive(password, salt)` → vaultKey
4. Déchiffre le vault IndexedDB → charge KEM + DSA privkeys en mémoire
5. Si vault absent → lance `VaultMissingError` (capturée dans login.ts pour proposer la récupération)

**`signOut()`**
- `Firebase.signOut()`
- Efface les clés privées de la mémoire volatile

**`mustChangePassword(uid)`**
- Lit `/provisioned/{uid}` dans Firestore
- Retourne `true` si le document existe

**`changePassword(uid, newPassword)`**
- Génère un nouveau salt Argon2
- Re-dérive vaultKey avec le nouveau mot de passe
- Re-chiffre le vault avec la nouvelle clé
- Met à jour Firestore (`/users/{uid}` salt) et IndexedDB (vault)
- Supprime `/provisioned/{uid}`
- Appelle `Firebase.updatePassword()`

**`generateFreshKeys(uid, password)`**
- Génère une nouvelle paire KEM + une nouvelle paire DSA
- Crée un nouveau vault chiffré
- Publie les nouvelles clés publiques dans Firestore `/publicKeys/{uid}`
- Utilisé pour "Démarrer de zéro" depuis l'écran de récupération

**`onAuthChange(callback)`**
- Wrapper sur `Firebase.onAuthStateChanged()`
- Appelé dans `main.ts` pour détecter la déconnexion

### Classe `VaultMissingError`
```typescript
class VaultMissingError extends Error {
  uid: string;
  // Lancée quand signIn() réussit côté Firebase mais qu'aucun vault
  // n'est trouvé dans IndexedDB (nouvel appareil, données effacées)
}
```

---

## `services/messaging.ts`

**Rôle :** Envoi, réception, déchiffrement de messages et fichiers.

### Fonctions principales

**`sendMessage(senderUid, recipientUid, plaintext)`**
1. Récupère l'état ratchet depuis IndexedDB
2. `doubleRatchetEncrypt(plaintext, recipientPublicKey, state)` → `{ ciphertext, nonce, kemCiphertext, messageIndex, newState }`
3. `dsaSign(ciphertext ‖ nonce ‖ kemCiphertext, dsaPrivKey)` → signature
4. Écrit dans Firestore `/conversations/{convId}/messages/`
5. Sauvegarde le nouvel état ratchet

**`sendFile(senderUid, recipientUid, file)`**
1. Lit le fichier comme ArrayBuffer
2. Dérive une clé de fichier depuis la clé ratchet courante
3. `aesGcmEncrypt(fileBytes → Base64, fileKey)`
4. Inclut `{ fileCiphertext, fileNonce, fileName, fileSize, fileType }` dans le message Firestore

**`subscribeToMessages(convId, myUid, callback)`**
- `onSnapshot` Firestore sur la sous-collection `messages`
- Pour chaque nouveau message : `doubleRatchetDecrypt()` → `dsaVerify()` → callback avec `DecryptedMessage`
- Cache les messages en IndexedDB (`idb-cache.ts`)
- Gère les messages `type: "ratchet-reset"` (resynchronisation)

**`deleteMessage(convId, msgId, editKey)`**
- `aesGcmEncrypt("__DELETED__", editKey)` → nouveau ciphertext
- `setDoc()` Firestore avec `{ deleted: true, ciphertext: new }`

**`editMessage(convId, msgId, newPlaintext, editKey)`**
- `aesGcmEncrypt(newPlaintext, editKey)` → nouveau ciphertext
- `setDoc()` Firestore avec `{ edited: true, editedAt, ciphertext: new }`

**`sendRatchetReset(senderUid, recipientUid)`**
- Publie un message `{ type: "ratchet-reset" }` dans Firestore
- Les deux clients effacent leur état ratchet et repartent en bootstrap

**`getOrCreateConversation(uid1, uid2)`**
- `convId = [uid1, uid2].sort().join("_")`
- `getDoc()` → si existe : retourner ; sinon `setDoc()` avec les deux participants

**`resetMessagingState()`**
- Remet à zéro les caches mémoire (utile avant vault recovery)

---

## `services/key-registry.ts`

**Rôle :** Registre des clés publiques — lecture et écriture dans Firestore `/publicKeys/`.

### Fonctions principales

**`getPublicKeys(uid)`**
- Lit `/publicKeys/{uid}` depuis Firestore
- Cache en mémoire pour éviter des lectures répétées
- Retourne `PublicKeyBundle | null`

**`publishPublicKeys(uid, kemPublicKey, dsaPublicKey)`**
- Écrit `/publicKeys/{uid}` dans Firestore
- Appelé à la création de compte et après `generateFreshKeys()`

**`invalidatePublicKeyCache(uid)`**
- Vide le cache mémoire pour forcer une relecture Firestore
- Appelé avant la vérification d'un ratchet-reset pour s'assurer d'avoir les clés à jour

---

## `services/key-store.ts`

**Rôle :** Stockage chiffré des clés privées en IndexedDB.

### Structure du vault (stocké chiffré en IndexedDB)
```typescript
{
  kemPrivateKey : string;  // Base64 — ML-KEM-768 private key (2400 bytes)
  dsaPrivateKey : string;  // Base64 — ML-DSA-65 private key
}
```

### Fonctions principales

**`storeVault(uid, vault, vaultKey)`**
- `aesGcmEncrypt(JSON.stringify(vault), vaultKey)` → `{ ciphertext, nonce }`
- `indexedDB.set("vault-{uid}", { ciphertext, nonce })`

**`loadVault(uid, vaultKey)`**
- Lit `indexedDB.get("vault-{uid}")`
- `aesGcmDecrypt(ciphertext, nonce, vaultKey)` → vault JSON
- Retourne `{ kemPrivateKey, dsaPrivateKey }`

**`getKemPrivateKey()`** / **`getDsaPrivateKey()`**
- Accesseurs vers les clés privées chargées en mémoire volatile
- Retournent `string | null` (null si l'utilisateur n'est pas connecté)

**`clearKeys()`**
- Efface les clés privées de la mémoire volatile
- Appelé lors de la déconnexion

**Sécurité :** L'API n'expose pas `getMasterKey()` ni `getPassword()` — ces primitives n'existent pas dans l'interface publique du module.

---

## `services/session-keys.ts`

**Rôle :** Export et import d'une session complète (clés + états ratchet) entre appareils.

### Format `.aqsession`
```json
{
  "v": 1,
  "mnemonicSalt": "Base64",
  "nonce": "Base64",
  "ciphertext": "Base64"
}
```

Le payload chiffré contient :
- `kemPrivateKey`, `dsaPrivateKey`
- Tous les états ratchet (`{ [convId]: RatchetState }`)

### Fonctions principales

**`exportSessionKeys(uid, password, onProgress)`**
1. Charge les clés privées depuis le vault
2. Charge tous les états ratchet depuis IndexedDB
3. Génère `10 mots mnémotechniques`
4. Dérive une clé depuis les mots : `deriveKeyFromMnemonic(words)`
5. Chiffre le payload : `aesGcmEncrypt(JSON.stringify(payload), mnemonicKey)`
6. Retourne `{ file: Blob, mnemonic: string[] }`

**`importSessionKeys(fileContent, words, password, onProgress)`**
1. Parse le fichier JSON
2. `deriveKeyFromMnemonic(words)` → mnemonicKey
3. `aesGcmDecrypt(ciphertext, nonce, mnemonicKey)` → payload
4. Restaure les clés dans le vault IndexedDB
5. Restaure chaque état ratchet dans IndexedDB
6. Phases reportées via `onProgress(phase)` : parsing → deriving → decrypting → restoring → done

---

## `services/backup.ts`

**Rôle :** Export/import d'un backup `.aqbackup` protégé par un mot de passe dédié.

Différence avec `.aqsession` : le backup utilise Argon2id sur un mot de passe indépendant (pas la phrase mnémotechnique).

### Format `.aqbackup`
```json
{
  "v": 1,
  "argon2Salt": "Base64",
  "nonce": "Base64",
  "ciphertext": "Base64"
}
```

### Fonctions principales

**`exportBackup(uid, backupPassword)`**
1. `argon2Derive(backupPassword)` → `{ key, salt }`
2. `aesGcmEncrypt(JSON.stringify(payload), key)`
3. Télécharge `aegisquantum-backup-{date}.aqbackup`

**`importBackup(file, backupPassword)`**
1. Parse le fichier
2. `argon2Derive(backupPassword, argon2Salt)` → key
3. `aesGcmDecrypt(ciphertext, nonce, key)` → payload
4. Lève une erreur si mot de passe incorrect (tag GCM invalide)

---

## `services/presence.ts`

**Rôle :** Présence en ligne, indicateurs de frappe, accusés de lecture.

### Fonctions principales

**`setPresence(uid, status)`**
- Écrit dans Firestore `/presence/{uid}` : `{ online: bool, updatedAt: timestamp }`

**`subscribeToPresence(contactUid, callback)`**
- `onSnapshot` sur `/presence/{contactUid}` → callback avec statut en ligne

**`setTyping(myUid, contactUid, isTyping)`**
- `isTyping = true` : écrit `/conversations/{convId}/typing/{myUid}` avec `updatedAt`
- `isTyping = false` : supprime le document
- Debounced dans l'UI : appelé à chaque keystroke, supprimé après 3s d'inactivité

**`subscribeToTyping(convId, myUid, callback)`**
- `onSnapshot` sur `/conversations/{convId}/typing/`
- Filtre les docs dont le `updatedAt` est récent (< 5s)
- Retourne les UIDs des utilisateurs en train d'écrire

**`markMessageRead(convId, msgId, myUid)`**
- `updateDoc(msgRef, { readBy: arrayUnion(myUid) })`
- Protégé par les règles Firestore : seul `readBy` peut être modifié

---

## `services/idb-cache.ts`

**Rôle :** Cache des messages déchiffrés en IndexedDB pour éviter de re-déchiffrer à chaque rechargement.

### Fonctions principales

**`cacheMessage(convId, message: DecryptedMessage)`**
- Stocke le message déchiffré (plaintext inclus) en IndexedDB
- Clé : `"msg-{convId}-{msgId}"`

**`getCachedMessages(convId)`**
- Retourne tous les messages cachés pour une conversation
- Triés par timestamp

**`clearConversationCache(convId)`**
- Vide le cache d'une conversation (ex : après ratchet-reset)

**Note de sécurité :** Le cache stocke les plaintexts en IndexedDB non chiffré. Sur un appareil partagé, cela pourrait exposer des messages. À considérer pour une future version : chiffrer le cache avec la vaultKey.

---

## `services/crypto-events.ts`

**Rôle :** Bus d'événements pour la communication entre modules lors de changements de clés.

### Événements

**`KEY_ROTATED`** — émis après `generateFreshKeys()` ou `changePassword()`
- Abonnés : `key-registry.ts` (invalider le cache), `messaging.ts` (réinitialiser les ratchets)

**`SESSION_IMPORTED`** — émis après `importSessionKeys()`
- Abonnés : `messaging.ts` (recharger les états ratchet)

### Usage
```typescript
cryptoEvents.emit('KEY_ROTATED', { uid });
cryptoEvents.on('KEY_ROTATED', ({ uid }) => { /* ... */ });
```
