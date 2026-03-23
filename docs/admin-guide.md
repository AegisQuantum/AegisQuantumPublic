# Guide Administrateur — AegisQuantum

AegisQuantum n'a pas d'auto-inscription. Les comptes sont créés exclusivement par l'administrateur via des scripts Node.js utilisant le **Firebase Admin SDK**.

---

## Prérequis

### 1. Installer les dépendances admin

```bash
cd admin/
npm install
```

### 2. Obtenir la clé de service Firebase

1. Ouvrir la [Firebase Console](https://console.firebase.google.com)
2. Sélectionner votre projet
3. Aller dans **Project Settings (⚙)** → onglet **Service accounts**
4. Cliquer sur **Generate new private key**
5. Télécharger le fichier JSON
6. Le renommer `serviceAccountKey.json`
7. Le placer dans `admin/serviceAccountKey.json`

> **Ne jamais committer ce fichier.** Il est dans `.gitignore`.
> Quiconque possède cette clé a un accès administrateur complet à votre Firebase.

---

## Créer un compte utilisateur

```bash
cd admin/
node create-user.js <username>
```

**Exemples :**
```bash
node create-user.js alice
node create-user.js bob --password MonMotDePasse!456
```

### Ce que fait le script

1. Crée un compte Firebase Authentication avec l'email `<username>@aq.local`
2. Génère un mot de passe aléatoire fort si aucun n'est fourni
3. Écrit dans Firestore `/provisioned/{uid}` :
   ```json
   {
     "username": "alice",
     "mustChangePassword": true,
     "createdAt": 1700000000000
   }
   ```
4. Affiche les identifiants à transmettre à l'utilisateur

### Sortie attendue

```
✅  Compte créé avec succès !
──────────────────────────────────────────────
  USERNAME  :  alice
  PASSWORD  :  Xk9mP2qLvBt3
  UID       :  abc123def456ghi789
──────────────────────────────────────────────

⚠️  Communiquez ces identifiants au client de façon sécurisée.
    Il devra changer son mot de passe à la première connexion.
```

### Première connexion de l'utilisateur

À la première connexion avec le mot de passe temporaire :
1. L'app détecte le flag `mustChangePassword: true` dans Firestore
2. L'utilisateur est redirigé vers l'écran de changement de mot de passe
3. Après changement : le document `/provisioned/{uid}` est supprimé
4. L'utilisateur accède au chat

---

## Lister les comptes

```bash
cd admin/
node list-users.js
```

### Sortie attendue

```
────────────────────────────────────────────────────────────────────────
  USERNAME       UID                    MDP CHANGÉ ?  CRÉÉ LE
────────────────────────────────────────────────────────────────────────
  alice          abc123def456             ⚠️  non      2025-03-09
  bob            xyz789ghi012             ✅  oui      2025-03-08
────────────────────────────────────────────────────────────────────────

  Total : 2 compte(s)
```

La colonne **MDP CHANGÉ ?** indique si l'utilisateur a effectué sa première connexion et défini son propre mot de passe.

---

## Supprimer un compte utilisateur

```bash
cd admin/
node delete-user.js <username>
```

**Exemple :**
```bash
node delete-user.js alice
```

### Ce que fait le script

1. Recherche l'UID associé au username dans Firebase Authentication
2. Demande une confirmation avant de procéder
3. Supprime dans cet ordre :
   - Toutes les conversations et messages Firestore où l'utilisateur est participant
   - Les clés publiques Firestore `/publicKeys/{uid}`
   - Le document `/users/{uid}` (salt Argon2)
   - Le document `/provisioned/{uid}` si présent
   - Le compte Firebase Authentication

> Les données locales (vault IndexedDB, états ratchet) sur l'appareil de l'utilisateur ne peuvent pas être supprimées à distance — elles disparaissent si l'utilisateur efface les données du navigateur ou l'utilise sur un seul appareil.

### Sortie attendue

```
⚠️  Vous êtes sur le point de supprimer le compte : alice (uid: abc123)
    Cette action est irréversible.

Confirmer la suppression ? [tapez 'supprimer' pour confirmer] : supprimer

🗑️  Suppression des messages (3 conversations)...
🗑️  Suppression des clés publiques...
🗑️  Suppression du compte Firebase Auth...
✅  Compte alice supprimé avec succès.
```

---

## Réinitialiser le mot de passe d'un utilisateur

Si un utilisateur perd son mot de passe et ne peut plus accéder à son vault :

```bash
cd admin/
node reset-password.js <username>
```

### Ce que fait le script

1. Génère un nouveau mot de passe temporaire
2. Met à jour Firebase Authentication
3. Recrée le document `/provisioned/{uid}` avec `mustChangePassword: true`

> **Important :** L'utilisateur devra aussi importer son fichier `.aqsession` après le changement de mot de passe, car sa vaultKey dépend de l'ancien mot de passe. Sans le `.aqsession`, il perdra l'accès à ses anciennes conversations.

### Sortie attendue

```
✅  Mot de passe réinitialisé pour : alice
──────────────────────────────────────────
  USERNAME    :  alice
  NEW PASSWORD:  Rp7kL2mZvXq9
──────────────────────────────────────────
⚠️  L'utilisateur devra aussi importer son .aqsession pour retrouver ses clés.
```

---

## Flux complet de création d'un compte

```
Admin                            Firebase Auth          Firestore
  │                                    │                    │
  │── node create-user.js alice ──────▶│ createUser(        │
  │                                    │   email: alice@aq  │
  │                                    │   password: Xk9m.. │
  │                                    │ )                  │
  │◀────────────────────── uid ────────│                    │
  │                                    │                    │
  │── setDoc /provisioned/{uid} ──────────────────────────▶│
  │   { mustChangePassword: true }     │                    │
  │                                    │                    │
  │── Communiquer username + pw        │                    │
  │   à l'utilisateur                  │                    │
  │                                    │                    │
                      ...première connexion...
  │                                    │                    │
  │   alice entre login + password ──▶│ signIn()           │
  │                                    │                    │
  │   Détecte mustChangePassword ────────────────────────▶│
  │   → écran changement MDP           │                    │
  │                                    │                    │
  │   alice change son MDP ──────────▶│ updatePassword()   │
  │                                    │                    │
  │   delete /provisioned/{uid} ──────────────────────────▶│
  │                                    │                    │
  │   initChat() → accès au chat       │                    │
```

---

## Sécurité des comptes admin

- **Ne partagez jamais** `serviceAccountKey.json` — accès root Firebase complet
- Stockez-le en dehors du repo (gestionnaire de secrets, vault, etc.)
- Révoquez et régénérez la clé si elle est compromise (Firebase Console → Service accounts → Supprimer)
- Les scripts admin ne tournent que localement — jamais sur un serveur web
- Utilisez des mots de passe temporaires forts (les scripts génèrent 12 caractères alphanumériques aléatoires par défaut)
