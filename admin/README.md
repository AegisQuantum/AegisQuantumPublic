# admin/ — Outils de provisioning AegisQuantum

Scripts Node.js utilisant **Firebase Admin SDK** pour créer et gérer les comptes utilisateurs.  
Les utilisateurs finaux ne peuvent **pas** s'inscrire eux-mêmes — c'est nous qui créons les comptes.

## Setup (à faire une seule fois)

```bash
cd admin/
npm install
```

Télécharger la clé de service Firebase :
1. [Firebase Console](https://console.firebase.google.com) → Project settings → Service accounts
2. **Generate new private key** → télécharger le JSON
3. Le renommer `serviceAccountKey.json` et le placer dans `admin/`

> ⚠️ `serviceAccountKey.json` est dans `.gitignore` — **ne jamais le committer**.

---

## Créer un compte

```bash
node create-user.js <username>
# Exemple
node create-user.js alice
```

Avec un mot de passe personnalisé :
```bash
node create-user.js bob --password MonMotDePasse123
```

**Sortie :**
```
✅  Compte créé avec succès !
──────────────────────────────────────────────
  USERNAME  :  alice
  PASSWORD  :  Xk9mP2qLvBt3
  UID       :  abc123def456ghi789
──────────────────────────────────────────────

⚠️   Communique ces identifiants au client de façon sécurisée.
    Il devra changer son mot de passe à la première connexion.
```

**Ce qui se passe en base :**
- Firebase Auth : compte créé avec `alice@aq.local` + mot de passe haché par Firebase
- Firestore `/provisioned/{uid}` : `{ username, passwordHash (SHA-256), mustChangePassword: true, createdAt }`
- Le mot de passe en clair n'est **jamais** stocké

---

## Lister les comptes

```bash
node list-users.js
```

**Sortie :**
```
────────────────────────────────────────────────────────────────────────
  USERNAME              UID                           MDP CHANGÉ ?  CRÉÉ LE
────────────────────────────────────────────────────────────────────────
  alice                 abc123def456                    ⚠️  non      2025-03-09
  bob                   xyz789ghi012                    ✅  oui      2025-03-08
────────────────────────────────────────────────────────────────────────

  Total : 2 compte(s)
```

---

## Flux complet

```
Admin                         Firebase Auth              Firestore
  │                                 │                        │
  │── create-user.js alice ──────→  │ createUser(            │
  │                                 │   alice@aq.local,      │
  │                                 │   password             │
  │                                 │ ) → uid                │
  │                                 │                        │── /provisioned/{uid}
  │                                 │                        │   { username, hash,
  │                                 │                        │     mustChangePassword: true }
  │
  │  → Communique username + password au client
  │
Client (1ère connexion)
  │── signIn(alice, tempPassword) ──→ Firebase Auth (OK)
  │── détecte mustChangePassword: true
  │── affiche écran "Choisissez votre nouveau mot de passe"
  │── changePassword(newPassword) ──→ Firebase Auth (updatePassword)
  │                                   Firestore : mustChangePassword: false
  │                                              passwordHash: supprimé
```
