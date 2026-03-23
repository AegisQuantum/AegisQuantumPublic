# Features — AegisQuantum

Ce document décrit chaque fonctionnalité de l'application, comment elle est implémentée et à quoi elle sert.

---

## 1. Authentification

### Connexion (`ui/login.ts` + `services/auth.ts`)

**Ce que c'est :** L'utilisateur entre son pseudo (email Firebase) et son mot de passe.

**Comment ça marche :**
1. `signIn(username, password)` appelle `Firebase.signInWithEmailAndPassword()`.
2. Le salt Argon2 est lu depuis Firestore `/users/{uid}`.
3. Argon2id(password, salt) → vaultKey (32 bytes).
4. Le vault IndexedDB est déchiffré → les clés privées KEM + DSA sont chargées en mémoire volatile.
5. Navigation vers le chat.

**Sécurité :** Les clés privées ne sont jamais persistées en clair. À chaque rechargement de page, l'utilisateur doit se reconnecter pour les recharger.

---

### Changement de mot de passe obligatoire (`ui/change-password.ts`)

**Ce que c'est :** À la première connexion (compte provisionné par l'admin), l'utilisateur est forcé à définir son propre mot de passe.

**Comment ça marche :**
1. `mustChangePassword(uid)` vérifie le document `/provisioned/{uid}` dans Firestore.
2. Si présent → affiche l'écran de changement MDP.
3. `changePassword(uid, newPw)` :
   - Génère un nouveau salt Argon2.
   - Dérive une nouvelle vaultKey.
   - Re-chiffre le vault avec la nouvelle clé.
   - Met à jour Firestore et IndexedDB.
   - Supprime le document `/provisioned/{uid}`.

---

### Récupération de vault (`ui/login.ts` → `showVaultRecoveryScreen()`)

**Ce que c'est :** Si les clés privées IndexedDB sont absentes (nouvel appareil, suppression du navigateur), trois options sont proposées :

| Option | Description |
|---|---|
| Importer un fichier .aqsession | Restaurer les clés depuis un export précédent |
| Démarrer de zéro | Régénérer des nouvelles clés (perd l'accès aux anciennes conversations) |
| Accès en lecture seule | Naviguer dans l'app sans pouvoir déchiffrer (pour importer plus tard) |

---

## 2. Liste des contacts et conversations

### Chargement des contacts (`services/messaging.ts`)

**Ce que c'est :** La colonne gauche du chat affiche les conversations existantes de l'utilisateur.

**Comment ça marche :**
- Firestore query : `where("participants", "array-contains", myUid), orderBy("lastMessageAt", "desc")`
- Pour chaque conversation, afficher le pseudo du contact (résolu depuis `/publicKeys/{contactUid}`) et le preview du dernier message (`"Message chiffré"` — jamais le plaintext).

### Recherche de nouveaux contacts

**Ce que c'est :** Champ de recherche pour trouver un utilisateur par pseudo.

**Comment ça marche :**
- Recherche dans Firestore `/publicKeys` par champ `uid` ou via index.
- Création d'une nouvelle conversation via `getOrCreateConversation(myUid, contactUid)`.
- `convId = [myUid, contactUid].sort().join("_")` — déterministe.

---

## 3. Messagerie chiffrée

### Envoi d'un message (`services/messaging.ts → sendMessage()`)

**Ce que c'est :** L'utilisateur tape un message et l'envoie.

**Comment ça marche :**
1. `doubleRatchetEncrypt(plaintext, contactUid)` chiffre le message.
2. `dsaSign(payload, dsaPrivKey)` signe l'enveloppe.
3. Publication dans Firestore `/conversations/{convId}/messages/`.
4. Mise à jour des métadonnées de conversation (lastMessageAt, lastMessagePreview).

### Réception en temps réel (`services/messaging.ts → subscribeToMessages()`)

**Ce que c'est :** Les messages arrivent instantanément via Firestore `onSnapshot`.

**Comment ça marche :**
1. `onSnapshot` reçoit les nouveaux documents.
2. Pour chaque message : `doubleRatchetDecrypt()` → `dsaVerify()`.
3. Affichage dans l'UI avec indicateur de vérification (✓ ou ⚠).

### Messages système (ratchet-reset)

**Ce que c'est :** Bulle centrée dans le chat signalant une resynchronisation des clés.

**Comment ça marche :**
- Message avec `type: "ratchet-reset"` dans Firestore.
- Pas de déchiffrement — affiché directement comme bulle système.
- Déclenche l'effacement des états ratchet locaux et un nouveau bootstrap.

---

## 4. Suppression de messages

### Supprimer pour tous (`chat.ts → deleteMessage()`)

**Ce que c'est :** L'expéditeur peut supprimer un message pour tous les participants.

**Comment ça marche :**
1. Dériver `editKey` depuis le shared secret du message original.
2. `AES-GCM.encrypt("__DELETED__", editKey)` → nouveau ciphertext.
3. Mettre à jour le document Firestore avec le nouveau ciphertext + `deleted: true`.
4. Les deux participants voient le message remplacé par *"Ce message a été supprimé"*.

**Sécurité :** Seul l'expéditeur connaît `editKey` (dérivée depuis ses clés privées). La règle Firestore autorise la mise à jour du document par les participants, mais la vérification de l'authenticité est côté client via la signature.

---

## 5. Modification de messages

### Éditer un message (`chat.ts → editMessage()`)

**Ce que c'est :** L'expéditeur peut modifier le texte d'un message déjà envoyé.

**Comment ça marche :**
1. L'UI affiche une zone de texte pré-remplie avec le plaintext original.
2. À la validation : dériver `editKey` depuis le shared secret du message.
3. `AES-GCM.encrypt(newPlaintext, editKey)` → nouveau ciphertext.
4. Mettre à jour Firestore : nouveau ciphertext + `edited: true` + `editedAt`.
5. Le message affiche *(modifié)* sous le texte.

---

## 6. Envoi d'images

### Partage d'image (`chat.ts + services/messaging.ts → sendFile()`)

**Ce que c'est :** L'utilisateur peut envoyer une image (JPEG, PNG, GIF, WebP).

**Comment ça marche :**
1. Sélection via l'input file filtré sur `image/*`.
2. Chiffrement côté client : `AES-GCM.encrypt(imageBytes, fileKey)`.
3. Stockage du ciphertext + nonce + métadonnées dans le message Firestore.
4. À la réception : déchiffrement → `URL.createObjectURL(blob)` → `<img>`.
5. Tap sur l'image → lightbox (zoom, téléchargement).

**Taille limite :** Les images sont envoyées en base64 dans Firestore. Une limite de taille est appliquée côté UI.

---

## 7. Envoi de fichiers

### Partage de fichiers génériques

**Ce que c'est :** Envoi de n'importe quel fichier (PDF, ZIP, etc.).

**Comment ça marche :** Identique aux images — chiffrement AES-GCM, stockage Firestore, déchiffrement à la réception. La bulle affiche nom + taille + bouton de téléchargement.

**MIME types :**
- `image/*` → bulle image avec aperçu inline
- Autre → bulle fichier générique avec icône et nom

---

## 8. Indicateurs de présence et de frappe

### Statut en ligne (`services/presence.ts`)

**Ce que c'est :** Indicateur vert/gris montrant si un contact est en ligne.

**Comment ça marche :**
- `setPresence(uid, "online")` écrit dans Firestore `/presence/{uid}`.
- Firestore `onSnapshot` sur `/presence/{contactUid}` → mise à jour temps réel.
- Déconnexion détectée via `onDisconnect()` Firebase Realtime Database (non utilisé) ou timeout sur `updatedAt`.

### Indicateur de frappe (`services/presence.ts`)

**Ce que c'est :** Affichage "*... est en train d'écrire*" en temps réel.

**Comment ça marche :**
1. À chaque keystroke dans l'input : `setTyping(myUid, contactUid, true)`.
2. Écrit dans Firestore `/conversations/{convId}/typing/{myUid}` avec `updatedAt`.
3. L'autre participant surveille ce document via `onSnapshot`.
4. Après 3 secondes sans frappe : `setTyping(myUid, contactUid, false)` → doc supprimé.

---

## 9. Accusés de lecture

### Read receipts (`services/presence.ts → markMessageRead()`)

**Ce que c'est :** Coche double visible quand le destinataire a lu le message.

**Comment ça marche :**
1. Quand un message devient visible dans le viewport : `markMessageRead(convId, msgId, myUid)`.
2. Firestore `arrayUnion(myUid)` sur le champ `readBy` du message.
3. L'expéditeur voit ✓✓ quand son UID et l'UID du contact sont tous les deux dans `readBy`.

**Règle Firestore :** Seul `readBy` peut être modifié (update protégé via `affectedKeys().hasOnly(['readBy'])`).

---

## 10. Safety Numbers (vérification MITM)

### Empreinte de sécurité (`ui/fingerprint.ts`)

**Ce que c'est :** Un code de 60 chiffres (12 groupes de 5) permettant de vérifier qu'aucune attaque MITM n'a eu lieu.

**Comment ça marche :**
1. Bouton "Empreinte de sécurité" dans les paramètres du chat.
2. Récupérer les 4 clés publiques (KEM + DSA) des deux participants depuis Firestore.
3. `computeSafetyNumbers(uid1, kemPub1, dsaPub1, uid2, kemPub2, dsaPub2)` :
   - Concatène les bytes des clés triés par UID.
   - SHA-256 sur la concaténation.
   - 20 premiers bytes → 12 groupes de 5 chiffres.
4. Alice et Bob voient la **même** empreinte.
5. Si différente → clé substituée → MITM détecté.

---

## 11. Export / Import de session

### Export `.aqsession` (`services/session-keys.ts`)

**Ce que c'est :** Exporter les clés privées et les états ratchet pour les importer sur un nouvel appareil.

**Comment ça marche :**
1. Récupérer les clés privées (KEM + DSA) depuis le vault.
2. Récupérer tous les états ratchet depuis IndexedDB.
3. Générer une phrase mnémotechnique de 10 mots.
4. Chiffrer le payload avec une clé dérivée de la phrase.
5. Télécharger le fichier `{uid}.aqsession`.

### Import `.aqsession` (`ui/login.ts + services/session-keys.ts`)

**Ce que c'est :** Restaurer les clés sur un nouvel appareil ou après suppression du navigateur.

**Comment ça marche :**
1. Connexion Firebase (sans vault = VaultMissingError attendue).
2. Sélectionner le fichier `.aqsession` + saisir la phrase mnémotechnique (10 mots).
3. Argon2id/PBKDF2 sur la phrase → clé de déchiffrement.
4. Déchiffrer le payload → restaurer vault + états ratchet dans IndexedDB.
5. Connexion complète avec accès aux messages historiques.

**Progression affichée :** 5 phases (parsing → deriving → decrypting → restoring → done) avec barre de progression.

---

## 12. Backup chiffré `.aqbackup`

### Export backup (`services/backup.ts`)

**Ce que c'est :** Sauvegarde complète chiffrée avec un mot de passe (différent du mot de passe de connexion).

**Format du fichier :**
```json
{
  "v": 1,
  "argon2Salt": "Base64 — salt pour dériver la clé depuis le mot de passe backup",
  "nonce": "Base64 — nonce AES-GCM",
  "ciphertext": "Base64 — payload chiffré AES-256-GCM"
}
```

**Payload chiffré contient :**
- Version
- Clés privées KEM + DSA
- Tous les états ratchet actifs
- Timestamp de création

### Import backup (`services/backup.ts → importBackup()`)

1. Lire et parser le fichier `.aqbackup`.
2. Argon2id(backupPassword, argon2Salt) → clé de déchiffrement.
3. AES-GCM decrypt → payload JSON.
4. Restaurer vault + états ratchet.

---

## 13. Provisioning administrateur

### Création de compte (`admin/`)

**Ce que c'est :** L'administrateur crée des comptes via l'Admin SDK Firebase (backend).

**Comment ça marche :**
1. Admin crée un compte Firebase Authentication avec un mot de passe temporaire.
2. Admin écrit `/provisioned/{uid}` : `{ mustChangePassword: true }`.
3. À la première connexion, l'utilisateur est redirigé vers l'écran de changement MDP.
4. Après changement : le document `/provisioned/{uid}` est supprimé.

---

## 14. Suppression de compte

### Delete account (`chat.ts + services/auth.ts`)

**Ce que c'est :** L'utilisateur peut supprimer définitivement son compte.

**Comment ça marche :**
1. Modale de confirmation.
2. Suppression de toutes les conversations et messages (Firestore).
3. Suppression des clés publiques (`/publicKeys/{uid}`).
4. Suppression du vault IndexedDB.
5. `Firebase.deleteUser()`.

---

## 15. Notifications push

### Push notifications (`chat.ts → initPushNotifications()`)

**Ce que c'est :** Notifications système quand un message arrive (app en arrière-plan ou onglet inactif).

**Comment ça marche :**
- `Notification.requestPermission()` à l'initialisation.
- `new Notification(title, { body, icon })` quand un message arrive et que l'onglet n'est pas visible.
- Filtrer les messages de l'utilisateur courant (pas de notif pour ses propres messages).

---

## 16. Lightbox images

### Visionneuse d'images (`chat.ts → _openLightbox()`)

**Ce que c'est :** Clic sur une image → affichage plein écran avec options.

**Comment ça marche :**
- Overlay fullscreen avec l'image agrandie.
- Bouton de téléchargement (`<a download>`).
- Fermeture via Escape ou clic en dehors.
- L'URL object est créée à l'ouverture et révoquée à la fermeture pour éviter les fuites mémoire.

---

## 17. Paramètres utilisateur

### Settings (`chat.ts → switchView('settings')`)

**Ce que c'est :** Panneau de paramètres accessible depuis la barre de navigation.

**Contenu :**
- Export / Import de session (.aqsession)
- Export backup (.aqbackup)
- Safety Numbers
- Suppression de compte
- Déconnexion

---

## 18. Logger de développement

### `utils/logger.ts`

**Ce que c'est :** En mode développement (Vite DEV), tous les `console.log/error/warn` sont envoyés vers un fichier log via un plugin Vite.

**Comment ça marche :**
- Intercepte `console.log`, `console.error`, `console.warn`.
- POST `/api/log` → plugin Vite → `admin/logs/app.log`.
- Intercepte aussi `window.onerror` et `unhandledrejection`.
- En production : les requêtes échouent silencieusement (pas d'endpoint).
