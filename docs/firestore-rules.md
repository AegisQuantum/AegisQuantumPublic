# Règles de sécurité Firestore — AegisQuantum

## Principe général

Les règles Firestore constituent la dernière ligne de défense côté serveur. Elles garantissent que même si un attaquant obtient des credentials Firebase valides (token JWT), il ne peut lire ou écrire que **ses propres données**.

La sécurité du contenu est assurée par le chiffrement E2E côté client (les règles ne voient jamais les plaintexts).

---

## Collections et règles

### `/publicKeys/{userId}`

```javascript
match /publicKeys/{userId} {
  allow read:  if request.auth != null;
  allow write: if request.auth != null && request.auth.uid == userId;
}
```

**Contenu :** Clés publiques ML-KEM-768 et ML-DSA-65 de chaque utilisateur.

**Pourquoi ces règles ?**
- **Lecture ouverte à tous les authentifiés :** Pour envoyer un message à Bob, Alice doit pouvoir lire sa clé publique KEM. Ces données sont par nature publiques (c'est leur rôle).
- **Écriture uniquement par le propriétaire :** Un utilisateur ne peut pas modifier les clés publiques d'un autre. Cela évite qu'un attaquant substitue sa clé pour intercepter les messages (MITM). Les Safety Numbers permettent une vérification out-of-band supplémentaire.

---

### `/users/{userId}`

```javascript
match /users/{userId} {
  allow read:  if request.auth != null && request.auth.uid == userId;
  allow write: if request.auth != null && request.auth.uid == userId;
}
```

**Contenu :** Salt Argon2 utilisé pour dériver la clé de vault.

**Pourquoi ces règles ?**
- **Lecture/écriture uniquement par le propriétaire :** Le salt Argon2 est nécessaire pour se connecter, mais c'est une donnée sensible — exposer les salts de tous les utilisateurs faciliterait des attaques par dictionnaire ciblées. Chaque utilisateur n'accède qu'à son propre salt.

---

### `/provisioned/{userId}`

```javascript
match /provisioned/{userId} {
  allow read:   if request.auth != null && request.auth.uid == userId;
  allow update: if request.auth != null && request.auth.uid == userId;
  allow delete: if request.auth != null && request.auth.uid == userId;
  allow create: if false;  // uniquement via Admin SDK (backend)
}
```

**Contenu :** Flag `mustChangePassword` pour les comptes créés par l'administrateur.

**Pourquoi ces règles ?**
- **Création interdite côté client :** Seul l'Admin SDK (backend/admin) peut provisionner un compte. Un utilisateur ne peut pas créer son propre document `provisioned` pour contourner le workflow.
- **Lecture/update par le propriétaire :** L'utilisateur peut lire son statut `mustChangePassword` et le supprimer une fois le mot de passe changé.

---

### `/conversations/{convId}`

```javascript
match /conversations/{convId} {
  allow read: if request.auth != null
              && (resource == null
                  || request.auth.uid in resource.data.participants);

  allow create: if request.auth != null
                && request.auth.uid in request.resource.data.participants;

  allow update: if request.auth != null
                && resource != null
                && request.auth.uid in resource.data.participants;

  allow delete: if request.auth != null
                && resource != null
                && request.auth.uid in resource.data.participants;
}
```

**Contenu :** Métadonnées de conversation (participants, dernier message, timestamp).

**`convId` :** `[uid1, uid2].sort().join("_")` — déterministe, symétrique.

**Pourquoi `resource == null` pour la lecture ?**
`getOrCreateConversation()` doit d'abord faire un `getDoc()` pour savoir si la conversation existe. Si elle n'existe pas encore, `resource == null`. Sans cette exception, la vérification `request.auth.uid in resource.data.participants` lèverait une erreur sur un document inexistant.

**Pourquoi les participants peuvent delete ?**
Pour la suppression de compte : un utilisateur peut supprimer ses conversations (et donc ses messages chiffrés) lors de la clôture de son compte.

---

### `/conversations/{convId}/messages/{messageId}`

```javascript
match /messages/{messageId} {
  allow read: if request.auth != null
              && request.auth.uid in get(/databases/$(database)/documents/conversations/$(convId)).data.participants;

  allow create: if request.auth != null
                && request.auth.uid == request.resource.data.senderUid
                && request.auth.uid in get(...conversations/$(convId)).data.participants;

  allow update: if request.auth != null
                && request.auth.uid in get(...conversations/$(convId)).data.participants
                && request.resource.data.diff(resource.data).affectedKeys().hasOnly(['readBy'])
                && request.auth.uid in request.resource.data.readBy;

  allow delete: if request.auth != null
                && request.auth.uid in get(...conversations/$(convId)).data.participants;
}
```

**Contenu :** Messages chiffrés E2E (ciphertext, nonce, KEM ciphertext, signature, etc.)

**Points critiques :**

**Création (`create`) :**
- `request.auth.uid == request.resource.data.senderUid` : empêche l'usurpation d'identité. Un utilisateur ne peut pas envoyer un message en se faisant passer pour quelqu'un d'autre (même si ça resterait chiffré correctement — c'est une défense en profondeur).

**Mise à jour (`update`) — accusés de lecture uniquement :**
- `affectedKeys().hasOnly(['readBy'])` : seul le champ `readBy` peut être modifié. Cela empêche qu'un participant modifie le `ciphertext`, la `signature`, ou tout autre champ d'un message existant.
- `request.auth.uid in request.resource.data.readBy` : un utilisateur ne peut ajouter que son propre UID dans `readBy`.
- **Conséquence :** La modification et la suppression de messages (delete for both) passent par une réécriture complète du document (nouveau `ciphertext` contenant `__DELETED__` ou le texte édité), ce qui est autorisé par `delete` + `create` ou via les règles appropriées.

**Suppression (`delete`) :**
- N'importe quel participant peut supprimer un message. Côté UI, seul l'expéditeur voit le bouton "Supprimer pour tous", mais la règle Firestore autorise les deux participants (nécessaire pour la suppression de compte).

---

### `/conversations/{convId}/typing/{uid}`

```javascript
match /typing/{uid} {
  allow read: if request.auth != null
              && convId.matches('.*' + request.auth.uid + '.*');

  allow write: if request.auth != null
               && request.auth.uid == uid
               && convId.matches('.*' + request.auth.uid + '.*');
}
```

**Contenu :** Indicateur de frappe temps réel.

**Pourquoi `convId.matches()` au lieu de `get()` ?**

Un `get()` cross-document dans une règle Firestore nécessite un round-trip serveur. En production, si le document de conversation n'est pas encore dans le cache Firebase au moment où `onSnapshot` s'établit pour les typing indicators, la règle échoue silencieusement. En développement, le cache local masquait ce bug.

La vérification via `convId.matches('.*' + request.auth.uid + '.*')` est instantanée et ne dépend d'aucun état externe, car `convId` contient toujours les deux UIDs des participants.

---

### Catch-all

```javascript
match /{document=**} {
  allow read, write: if false;
}
```

Toute collection non explicitement couverte est refusée par défaut. Principe du moindre privilège.

---

## Récapitulatif des droits par collection

| Collection | Lecture | Écriture | Remarques |
|---|---|---|---|
| `/publicKeys/{uid}` | Tous authentifiés | Propriétaire uniquement | Clés publiques = données publiques |
| `/users/{uid}` | Propriétaire | Propriétaire | Salt Argon2 — privé |
| `/provisioned/{uid}` | Propriétaire | Propriétaire (no create) | Create via Admin SDK seulement |
| `/conversations/{convId}` | Participants | Participants | resource == null autorisé pour création |
| `/conversations/{convId}/messages/` | Participants | Participant (create), update limité | Seul readBy modifiable après création |
| `/conversations/{convId}/typing/` | Participants (via convId) | Propriétaire du doc | Pas de cross-doc get pour éviter race condition |
