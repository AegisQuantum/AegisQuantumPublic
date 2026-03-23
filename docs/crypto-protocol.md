# Protocole Cryptographique — AegisQuantum

## Vue d'ensemble

AegisQuantum combine des primitives **post-quantiques** (ML-KEM-768, ML-DSA-65) avec des primitives classiques éprouvées (AES-256-GCM, HKDF-SHA-256, Argon2id) pour garantir une sécurité complète même face à un adversaire disposant d'un ordinateur quantique.

---

## 1. Primitives cryptographiques

### 1.1 ML-KEM-768 — `crypto/kem.ts`

**Qu'est-ce que c'est ?**
ML-KEM-768 (anciennement CRYSTALS-Kyber) est un algorithme d'encapsulation de clé (KEM) standardisé par le NIST en 2024. Il est résistant aux attaques quantiques (niveau de sécurité 3 ≈ AES-192).

**À quoi ça sert dans AegisQuantum ?**
- Établir un **shared secret** entre l'expéditeur et le destinataire sans que le serveur puisse le reconstituer.
- Utilisé dans le Double Ratchet pour chaque "step" du ratchet KEM.

**Comment ça fonctionne ?**
```
Alice génère : (publicKey, privateKey) ← kemGenerateKeyPair()

Bob encapsule : (kemCiphertext, sharedSecret) ← kemEncapsulate(alice.publicKey)
  → sharedSecret est connu de Bob uniquement

Alice décapsule : sharedSecret ← kemDecapsulate(kemCiphertext, alice.privateKey)
  → Alice retrouve le même sharedSecret

Le serveur voit kemCiphertext mais ne peut pas retrouver sharedSecret sans alice.privateKey
```

**Tailles des données :**
| Donnée | Taille |
|---|---|
| Clé publique | 1184 bytes |
| Clé privée | 2400 bytes |
| Ciphertext KEM | 1088 bytes |
| Shared secret | 32 bytes |

**Fonctions exportées :**
- `kemGenerateKeyPair()` → `{ publicKey: Base64, privateKey: Base64 }`
- `kemEncapsulate(recipientPublicKeyB64)` → `{ kemCiphertext: Base64, sharedSecret: Base64 }`
- `kemDecapsulate(kemCiphertextB64, privateKeyB64)` → `sharedSecret: Base64`
- `toBase64(bytes)` / `fromBase64(b64)` — utilitaires d'encodage

---

### 1.2 ML-DSA-65 — `crypto/dsa.ts`

**Qu'est-ce que c'est ?**
ML-DSA-65 (anciennement CRYSTALS-Dilithium) est un algorithme de signature numérique post-quantique standardisé par le NIST en 2024.

**À quoi ça sert dans AegisQuantum ?**
Authentifier chaque message : le destinataire vérifie que le message vient bien de l'expéditeur déclaré et n'a pas été altéré en transit.

**Comment ça fonctionne ?**
```
Alice signe : signature ← dsaSign(message, alice.dsaPrivateKey)
Bob vérifie : valid ← dsaVerify(message, signature, alice.dsaPublicKey)
  → valid = true  : message authentique, expéditeur confirmé
  → valid = false : message altéré ou expéditeur usurpé
```

**Ce qui est signé :** `ciphertext ‖ nonce ‖ kemCiphertext` (la totalité de l'enveloppe chiffrée)

**Fonctions exportées :**
- `dsaGenerateKeyPair()` → `{ publicKey: Base64, privateKey: Base64 }`
- `dsaSign(message: Uint8Array, privateKeyB64)` → `signature: Base64`
- `dsaVerify(message: Uint8Array, signatureB64, publicKeyB64)` → `boolean`

---

### 1.3 AES-256-GCM — `crypto/aes-gcm.ts`

**Qu'est-ce que c'est ?**
AES-256-GCM est un algorithme de chiffrement symétrique authentifié (AEAD). Le tag GCM (128 bits) garantit simultanément la confidentialité et l'intégrité.

**À quoi ça sert dans AegisQuantum ?**
- Chiffrement du **plaintext** de chaque message (avec une clé dérivée via HKDF depuis le shared secret KEM).
- Chiffrement du **vault** de clés privées en IndexedDB.
- Chiffrement des **pièces jointes** (images, fichiers).
- Chiffrement du **backup** `.aqbackup`.
- Utilisé en interne dans le Double Ratchet pour chiffrer les clés intermédiaires.

**Comment ça fonctionne ?**
```
chiffrer :
  nonce   ← crypto.getRandomValues(12 bytes)  // aléatoire par message
  { ciphertext, tag } ← AES-256-GCM(plaintext, key, nonce)
  stocker : { ciphertext + tag (Base64), nonce (Base64) }

déchiffrer :
  plaintext ← AES-256-GCM.decrypt(ciphertext + tag, key, nonce)
  si tag invalide → DOMException (OperationError) → rejet du message
```

**Propriété clé :** un nonce ne doit JAMAIS être réutilisé avec la même clé. AegisQuantum génère un nonce aléatoire frais pour chaque opération via `crypto.getRandomValues`.

**Fonctions exportées :**
- `aesGcmEncrypt(plaintext: string, keyB64: string)` → `{ ciphertext: Base64, nonce: Base64 }`
- `aesGcmDecrypt(ciphertextB64, nonceb64, keyB64)` → `plaintext: string`

---

### 1.4 HKDF-SHA-256 — `crypto/hkdf.ts`

**Qu'est-ce que c'est ?**
HKDF (HMAC-based Extract-and-Expand Key Derivation Function) est une fonction de dérivation de clé standardisée (RFC 5869). Elle transforme un matériau de clé de longueur variable (shared secret KEM, par exemple) en une clé AES de taille fixe.

**À quoi ça sert dans AegisQuantum ?**
Dériver la clé AES-256 d'un message depuis le shared secret ML-KEM-768 et l'index du message.

**Comment ça fonctionne ?**
```
messageKey ← HKDF(
  ikm  = sharedSecret (32 bytes du KEM),
  salt = "AegisQuantum-v1" (contexte fixe),
  info = messageIndex  (index du message dans le ratchet),
  len  = 32 bytes
)
```

**Fonctions exportées :**
- `hkdfDerive(ikmB64, salt, info, length)` → `keyB64: string`

---

### 1.5 Argon2id — `crypto/argon2.ts`

**Qu'est-ce que c'est ?**
Argon2id est la fonction de hachage de mot de passe recommandée par le NIST et gagnante de la Password Hashing Competition (PHC). Elle est résistante aux attaques par GPU et FPGA grâce à son utilisation intensive de mémoire.

**À quoi ça sert dans AegisQuantum ?**
Dériver la **clé de vault** (vaultKey) depuis le mot de passe utilisateur. Cette clé chiffre/déchiffre le vault IndexedDB contenant les clés privées.

**Comment ça fonctionne ?**
```
{ key, salt } ← argon2Derive(password, existingSalt?)

  salt  : 16 bytes aléatoires (generé à la création, stocké dans Firestore /users/{uid})
  key   : 32 bytes — clé AES-256 pour chiffrer le vault

Paramètres :
  - Algorithme : Argon2id (résistant side-channel + GPU)
  - Mémoire    : 64 MB (m = 65536)
  - Itérations : 3 (t = 3)
  - Parallélisme : 1 (p = 1)
```

**Sécurité :** Si le mot de passe est compromis mais pas IndexedDB, l'attaquant doit brute-forcer le mot de passe via Argon2id (coûteux). Si IndexedDB est compromis mais pas le mot de passe, les clés privées restent chiffrées.

**Fonctions exportées :**
- `argon2Derive(password, existingSalt?)` → `{ key: Base64, salt: Base64 }`

---

### 1.6 Phrase mnémotechnique — `crypto/mnemonic.ts`

**Qu'est-ce que c'est ?**
Un système de code de récupération à 10 mots (inspiré de BIP-39) permettant d'exporter et importer une session sur un nouvel appareil.

**À quoi ça sert dans AegisQuantum ?**
Protéger le fichier d'export de session `.aqsession` (qui contient les clés privées chiffrées) par une phrase humainement mémorisable.

**Comment ça fonctionne ?**
```
export :
  words ← generateMnemonic()  // 10 mots tirés d'une wordlist prédéfinie
  seed  ← deriveFromMnemonic(words)  // PBKDF2 ou hash des mots
  key   ← seed  // utilisée pour chiffrer le .aqsession

import :
  words ← saisie utilisateur (normalisée : minuscule, trimée)
  validateMnemonic(words) → 10 mots valides de la wordlist
  seed  ← deriveFromMnemonic(words)
  key   ← seed  // pour déchiffrer le .aqsession
```

**Fonctions exportées :**
- `generateMnemonic()` → `string[]` (10 mots)
- `validateMnemonic(words)` → `boolean`
- `normalizeMnemonic(input)` → `string[]` (nettoyage de la saisie utilisateur)
- `deriveKeyFromMnemonic(words)` → `Base64`

---

## 2. Flux de chiffrement d'un message

```
EXPÉDITEUR (Alice)
══════════════════════════════════════════════════════════════

1. Récupérer clé publique ML-KEM-768 de Bob depuis Firestore

2. Double Ratchet — étape KEM :
   (kemCiphertext, sharedSecret) ← kemEncapsulate(bob.kemPublicKey)
   sharedSecret contient 32 bytes de secret partagé frais

3. Dériver clé de message :
   messageKey ← hkdfDerive(sharedSecret, "AegisQuantum-v1", messageIndex)

4. Chiffrer le plaintext :
   { ciphertext, nonce } ← aesGcmEncrypt(plaintext, messageKey)

5. Signer l'enveloppe :
   payload    = ciphertext ‖ nonce ‖ kemCiphertext
   signature  ← dsaSign(payload, alice.dsaPrivateKey)

6. Publier dans Firestore :
   {
     senderUid, ciphertext, nonce,
     kemCiphertext, signature,
     messageIndex, timestamp
   }

DESTINATAIRE (Bob)
══════════════════════════════════════════════════════════════

1. Lire le message depuis Firestore (onSnapshot)

2. Vérifier la signature :
   payload   = ciphertext ‖ nonce ‖ kemCiphertext
   valid     ← dsaVerify(payload, signature, alice.dsaPublicKey)
   si !valid → rejeter le message

3. Double Ratchet — étape KEM :
   sharedSecret ← kemDecapsulate(kemCiphertext, bob.kemPrivateKey)

4. Dériver clé de message :
   messageKey ← hkdfDerive(sharedSecret, "AegisQuantum-v1", messageIndex)

5. Déchiffrer :
   plaintext ← aesGcmDecrypt(ciphertext, nonce, messageKey)
   si tag GCM invalide → rejeter (message altéré)

6. Afficher le message avec ✓ si signature valide
```

---

## 3. Gestion du vault de clés privées

```
Création de compte / changement de mot de passe :
  salt    ← crypto.getRandomValues(16 bytes)
  vaultKey ← Argon2id(password, salt)
  vault    = { kemPrivateKey, dsaPrivateKey }  // JSON
  { ciphertext, nonce } ← AES-GCM(JSON.stringify(vault), vaultKey)
  IndexedDB.set("vault", { ciphertext, nonce })
  Firestore.set("/users/{uid}", { argon2Salt: salt })

Connexion :
  salt    ← Firestore.get("/users/{uid}").argon2Salt
  vaultKey ← Argon2id(password, salt)         // ~1s (intentionnellement lent)
  vault    ← AES-GCM.decrypt(IndexedDB["vault"], vaultKey)
  { kemPrivKey, dsaPrivKey } chargées en mémoire volatile
```

---

## 4. Chiffrement des pièces jointes

Les fichiers (images, etc.) sont chiffrés **client-side** avant d'être stockés dans Firestore :

```
1. Dériver une clé de fichier depuis la clé de message courante du ratchet
2. AES-GCM encrypt(fileBytes → Base64)
3. Stocker dans Firestore : { fileCiphertext, fileNonce, fileName, fileSize, fileType }
   — fileName, fileSize, fileType sont en clair (métadonnées acceptées)
4. À la réception : AES-GCM decrypt → Blob → URL.createObjectURL → affichage
```
