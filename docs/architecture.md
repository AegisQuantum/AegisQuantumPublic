# Architecture — AegisQuantum

## Vue d'ensemble

AegisQuantum est une application de messagerie chiffrée de bout en bout (E2EE) construite sur des primitives **post-quantiques**. Toute la cryptographie s'exécute **dans le navigateur** — le serveur (Firebase) ne voit jamais les plaintexts, ni les clés privées.

```
┌────────────────────────────────────────────────────────────┐
│                        Navigateur                           │
│                                                             │
│  ┌──────────┐   ┌───────────────┐   ┌──────────────────┐   │
│  │ UI Layer │──▶│ Services Layer│──▶│  Crypto Layer    │   │
│  │          │   │               │   │                  │   │
│  │ chat.ts  │   │ messaging.ts  │   │ kem.ts           │   │
│  │ login.ts │   │ auth.ts       │   │ dsa.ts           │   │
│  │ finger-  │   │ key-store.ts  │   │ aes-gcm.ts       │   │
│  │ print.ts │   │ key-registry  │   │ hkdf.ts          │   │
│  │ change-  │   │ session-keys  │   │ argon2.ts        │   │
│  │ password │   │ backup.ts     │   │ double-ratchet   │   │
│  │ .ts      │   │ presence.ts   │   │ ratchet-state    │   │
│  └──────────┘   └──────┬────────┘   └──────────────────┘   │
│                        │                                    │
│                 ┌──────▼────────┐                           │
│                 │  IndexedDB    │                           │
│                 │  (vault chif.)│                           │
│                 └───────────────┘                           │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTPS
             ┌──────────▼──────────┐
             │   Firebase (Google) │
             │                     │
             │  Authentication     │
             │  Firestore (NoSQL)  │
             │  — tout chiffré E2E │
             └─────────────────────┘
```

---

## Stack technique

| Composant | Technologie |
|---|---|
| Frontend | TypeScript + Vite |
| UI | HTML/CSS vanilla (sans framework) |
| Auth | Firebase Authentication (email/password) |
| Base de données | Cloud Firestore |
| KEM post-quantique | ML-KEM-768 (CRYSTALS-Kyber, NIST niveau 3) |
| DSA post-quantique | ML-DSA-65 (CRYSTALS-Dilithium, NIST niveau 3) |
| Chiffrement symétrique | AES-256-GCM via Web Crypto API |
| Dérivation de clé | HKDF-SHA-256 via Web Crypto API |
| Hash mot de passe | Argon2id via WASM (`argon2-browser`) |
| Stockage local clés | IndexedDB (vault AES-256-GCM chiffré) |
| Tests | Vitest |

---

## Structure du projet

```
frontend/src/
├── main.ts                    # Point d'entrée — gestion auth state Firebase
├── app.ts                     # (réservé)
│
├── crypto/                    # Couche cryptographique pure (zero side-effects)
│   ├── aes-gcm.ts             # AES-256-GCM : encrypt/decrypt AEAD
│   ├── argon2.ts              # Argon2id : KDF pour le vault (mot de passe → clé)
│   ├── hkdf.ts                # HKDF-SHA-256 : dérivation de clés de session
│   ├── kem.ts                 # ML-KEM-768 : encapsulation/décapsulation
│   ├── dsa.ts                 # ML-DSA-65 : signature/vérification
│   ├── mnemonic.ts            # Phrase mnémotechnique 10 mots (export session)
│   ├── double-ratchet.ts      # Protocole Double Ratchet post-quantique
│   ├── ratchet-state.ts       # Persistance état ratchet en IndexedDB
│   └── index.ts               # Re-exports publics du module crypto
│
├── services/                  # Couche métier — accès données et orchestration
│   ├── firebase.ts            # Initialisation Firebase (app, auth, db)
│   ├── auth.ts                # Connexion, déconnexion, vault, provisioning
│   ├── messaging.ts           # Envoi/réception/déchiffrement messages
│   ├── key-registry.ts        # Registre clés publiques Firestore
│   ├── key-store.ts           # Stockage clés privées IndexedDB (chiffré)
│   ├── session-keys.ts        # Export/import session .aqsession (multi-device)
│   ├── backup.ts              # Export/import backup .aqbackup (Argon2 + AES)
│   ├── presence.ts            # Présence en ligne, typing, accusés de lecture
│   ├── idb-cache.ts           # Cache messages en IndexedDB
│   └── crypto-events.ts       # Bus événements cryptographiques (changement clés)
│
├── ui/                        # Couche présentation
│   ├── chat.ts                # UI principale : contacts, messages, settings
│   ├── login.ts               # Connexion + récupération vault + import session
│   ├── fingerprint.ts         # Safety Numbers (vérification MITM)
│   ├── change-password.ts     # Changement MDP obligatoire (1ère connexion)
│   └── components.ts          # (réservé)
│
├── types/                     # Interfaces TypeScript
│   ├── message.ts             # EncryptedMessage, DecryptedMessage, Conversation
│   ├── user.ts                # AQUser, PublicKeyBundle
│   ├── ratchet.ts             # RatchetState
│   └── crypto.ts              # Types crypto internes
│
└── utils/
    ├── logger.ts              # Intercepteur console → fichier log (dev uniquement)
    ├── encoding.ts            # (réservé)
    └── validator.ts           # (réservé)
```

---

## Flux de démarrage

```
1. Chargement de la page
   └─ main.ts → initAuth()        Affiche l'écran de login

2. Utilisateur entre login + password
   └─ aqSignIn(username, pw)
       ├─ Firebase signInWithEmailAndPassword()
       ├─ Lire salt Argon2 depuis Firestore /users/{uid}
       ├─ Argon2id(password, salt) → vaultKey (32 bytes)
       ├─ AES-GCM decrypt vault IndexedDB → { kemPrivKey, dsaPrivKey }
       └─ Clés stockées en mémoire volatile (jamais re-persistées)

3. Navigation post-login
   ├─ mustChangePassword() → écran changement MDP (1ère connexion admin)
   └─ sinon → initChat(uid)

4. initChat(uid)
   ├─ Charger contacts (conversations Firestore)
   ├─ Ouvrir conversation sélectionnée
   │   ├─ onSnapshot messages → déchiffrement temps réel
   │   └─ Double Ratchet : dériver clé message par message
   └─ Initialiser présence, typing, notifications

5. Déconnexion / rechargement page
   └─ onAuthChange(null) → retour écran login
      Les clés privées disparaissent de la mémoire (volatile)
      L'utilisateur doit se reconnecter pour les recharger
```

---

## Collections Firestore

```
/publicKeys/{uid}                   Clés publiques ML-KEM-768 + ML-DSA-65
/users/{uid}                        Salt Argon2 (dérivation vault)
/provisioned/{uid}                  Flag mustChangePassword (admin)
/conversations/{convId}             Métadonnées conversation
/conversations/{convId}/messages/   Messages chiffrés (E2EE)
/conversations/{convId}/typing/     Indicateurs de frappe temps réel
```

`convId` = `[uid1, uid2].sort().join("_")` — identifiant déterministe et symétrique.

---

## Principes de sécurité fondamentaux

| Principe | Implémentation |
|---|---|
| Zero-knowledge serveur | Firebase ne stocke que des ciphertexts AES-GCM |
| Résistance post-quantique | ML-KEM-768 + ML-DSA-65 (NIST PQC Round 3) |
| Forward secrecy | Double Ratchet — une clé par message |
| Break-in recovery | Ratchet KEM : re-génération du secret à chaque step |
| Clés privées locales | Jamais transmises, jamais en clair en IndexedDB |
| Authenticité messages | Signature ML-DSA-65 vérifiée à la réception |
| Authentification serveur | Firestore rules : chaque user accède uniquement à ses données |
