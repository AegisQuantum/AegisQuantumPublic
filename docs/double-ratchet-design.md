# Double Ratchet Post-Quantique — Design

## Principe général

Le Double Ratchet est le protocole utilisé par Signal, WhatsApp et iMessage pour garantir la **forward secrecy** (une clé compromise ne compromet pas les messages passés) et le **break-in recovery** (après compromission, la sécurité est rétablie dès le prochain échange).

AegisQuantum implémente une variante **post-quantique** : le ratchet Diffie-Hellman classique est remplacé par un ratchet **ML-KEM-768**, résistant aux ordinateurs quantiques.

---

## Structure de l'état ratchet

```typescript
// types/ratchet.ts
interface RatchetState {
  // Clé de chaîne émission : avance à chaque message envoyé
  sendChainKey    : string;  // Base64, 32 bytes

  // Clé de chaîne réception : avance à chaque message reçu
  recvChainKey    : string;  // Base64, 32 bytes

  // Index du prochain message à envoyer (compteur)
  sendMessageIndex: number;

  // Index du prochain message attendu en réception
  recvMessageIndex: number;

  // Clé publique KEM de l'autre participant (pour le prochain step KEM)
  theirKemPublicKey: string;  // Base64, 1184 bytes

  // Notre paire KEM éphémère courante
  ourKemPublicKey : string;   // Base64, 1184 bytes
  ourKemPrivateKey: string;   // Base64, 2400 bytes
}
```

L'état est persisté chiffré en **IndexedDB** via `ratchet-state.ts`.

---

## Initialisation d'une session (Bootstrap)

Quand Alice envoie le **premier message** à Bob :

```
1. Alice n'a pas d'état ratchet → bootstrap

2. Alice génère une paire KEM éphémère :
   (aliceEphPub, aliceEphPriv) ← kemGenerateKeyPair()

3. Alice encapsule avec la clé publique KEM permanente de Bob :
   (initKemCiphertext, initSecret) ← kemEncapsulate(bob.kemPublicKey)

4. Alice dérive les clés initiales :
   sendChainKey ← HKDF(initSecret, "send-chain")
   recvChainKey ← HKDF(initSecret, "recv-chain")

5. Alice envoie le message avec initKemCiphertext dans Firestore.
   Bob verra ce champ et saura qu'il doit bootstrapper.

6. Bob reçoit le message :
   initSecret ← kemDecapsulate(initKemCiphertext, bob.kemPrivateKey)
   recvChainKey ← HKDF(initSecret, "send-chain")  // inversé
   sendChainKey ← HKDF(initSecret, "recv-chain")

   Bob est maintenant synchronisé avec Alice.
```

---

## Envoi d'un message (ratchet step)

```
Pour chaque message envoyé par Alice :

1. Ratchet symétrique (KDF chain) :
   messageKey    ← HKDF(sendChainKey, "message-key", messageIndex)
   sendChainKey  ← HKDF(sendChainKey, "chain-advance")  // avancer la chaîne

2. Optionnellement : ratchet KEM (step asymétrique)
   Si c'est le bon moment pour un ratchet KEM :
   (newKemCiphertext, newSecret) ← kemEncapsulate(theirKemPublicKey)
   sendChainKey ← HKDF(sendChainKey ‖ newSecret, "ratchet-step")
   recvChainKey ← HKDF(recvChainKey ‖ newSecret, "ratchet-step")
   Inclure newKemCiphertext dans le message

3. Chiffrer :
   { ciphertext, nonce } ← AES-GCM(plaintext, messageKey)

4. Signer :
   signature ← ML-DSA-65.sign(ciphertext ‖ nonce ‖ kemCiphertext, dsaPrivKey)

5. Publier dans Firestore avec messageIndex
```

---

## Réception d'un message (déchiffrement)

```
1. Lire messageIndex depuis Firestore
2. Si messageIndex != recvMessageIndex → message hors ordre
   → les clés de messages passés sont mises en cache (skipped messages)

3. Ratchet symétrique :
   messageKey    ← HKDF(recvChainKey, "message-key", messageIndex)
   recvChainKey  ← HKDF(recvChainKey, "chain-advance")

4. Si le message contient un KEM ciphertext (ratchet KEM step) :
   newSecret ← kemDecapsulate(kemCiphertext, ourKemPrivKey)
   sendChainKey ← HKDF(sendChainKey ‖ newSecret, "ratchet-step")
   recvChainKey ← HKDF(recvChainKey ‖ newSecret, "ratchet-step")

5. Vérifier signature ML-DSA-65
   si invalide → rejeter

6. Déchiffrer :
   plaintext ← AES-GCM.decrypt(ciphertext, nonce, messageKey)

7. Sauvegarder le nouvel état ratchet en IndexedDB
```

---

## Ratchet Reset (resynchronisation)

Quand les états ratchet divergent (ex : import sur nouvel appareil, corruption IndexedDB), AegisQuantum envoie un **signal de resynchronisation** :

```typescript
// type: "ratchet-reset" dans Firestore
{
  type: "ratchet-reset",
  senderUid: "alice_uid",
  timestamp: ...,
  // pas de ciphertext, pas de signature
}
```

**Comportement à la réception :**
1. Les deux participants suppriment leur état ratchet local.
2. Le prochain message déclenche un bootstrap complet.
3. Une bulle système s'affiche dans le chat : "Session resynchronisée".

**Déclenchement automatique :**
- Si `doubleRatchetDecrypt` échoue plusieurs fois de suite (clé dérivée incorrecte).
- Envoyé automatiquement par `sendRatchetReset()` dans `messaging.ts`.

---

## Persistance de l'état — `ratchet-state.ts`

L'état ratchet est persisté chiffré en IndexedDB pour survivre aux recharges de page.

```
Clé IndexedDB : "ratchet-state:{myUid}:{contactUid}"

Valeur :
  { ciphertext: Base64, nonce: Base64 }
  → AES-GCM chiffré avec la vaultKey (même clé que le vault principal)

Lecture :
  stateJson ← IndexedDB.get(key)
  state ← AES-GCM.decrypt(stateJson, vaultKey)
  → RatchetState

Écriture :
  { ciphertext, nonce } ← AES-GCM.encrypt(JSON.stringify(state), vaultKey)
  IndexedDB.set(key, { ciphertext, nonce })
```

**Invalidation de cache :** Avant de vérifier un ratchet reset, le cache de clés publiques est invalidé pour forcer la relecture depuis Firestore. Cela évite qu'une clé publique obsolète en cache bloque la resynchronisation.

---

## Propriétés de sécurité

### Forward Secrecy
Chaque message est chiffré avec une `messageKey` dérivée via HKDF et **immédiatement effacée** après usage. Compromettre la clé de chaîne courante ne donne pas accès aux messages passés.

### Break-in Recovery
Après compromission d'un état ratchet, le ratchet KEM génère un nouveau `sharedSecret` via ML-KEM-768 dès l'échange suivant. L'adversaire ne peut plus déchiffrer les nouveaux messages sans compromettre la nouvelle clé privée KEM.

### Résistance post-quantique
Un ordinateur quantique peut casser X25519/X448 (Diffie-Hellman classique) via l'algorithme de Shor. ML-KEM-768 est basé sur le problème Module-LWE, pour lequel aucun algorithme quantique efficace n'est connu.

### Messages hors-ordre
Les `messageKey` pour les messages skipped sont mis en cache temporairement (`skippedMessageKeys` dans l'état ratchet). Un maximum de clés skipped est appliqué pour limiter l'empreinte mémoire.

---

## Comparaison avec le Double Ratchet classique (Signal)

| Aspect | Signal (classique) | AegisQuantum (post-quantique) |
|---|---|---|
| KEM | X25519 (ECDH) | ML-KEM-768 (CRYSTALS-Kyber) |
| Signature | Ed25519 | ML-DSA-65 (CRYSTALS-Dilithium) |
| Résistance quantique | Non | Oui (NIST niveau 3) |
| Taille ciphertext KEM | 32 bytes | 1088 bytes |
| Taille clé publique | 32 bytes | 1184 bytes |
| Taille signature | 64 bytes | ~3293 bytes |
| KDF | HKDF-SHA-256 | HKDF-SHA-256 (identique) |
| Chiffrement symétrique | AES-256-GCM | AES-256-GCM (identique) |
