# Analyse de Sécurité — AegisQuantum

## Modèle de menace

AegisQuantum est conçu pour résister à deux catégories d'adversaires :

### Adversaire passif sur le réseau
- Intercepte le trafic HTTPS
- Lit les données stockées dans Firestore
- Accède aux backups/exports interceptés

**Résistance :** AES-256-GCM + ML-KEM-768. L'adversaire voit uniquement des ciphertexts et des métadonnées (timestamp, UID expéditeur/destinataire, taille message).

### Adversaire actif (MITM)
- Tente de substituer des clés publiques dans Firestore
- Intercepte et modifie des messages en transit
- Rejoue des anciens messages

**Résistance :**
- Signatures ML-DSA-65 sur chaque message — toute modification invalide la signature
- Safety Numbers — vérification out-of-band des clés publiques
- Règles Firestore — seul le propriétaire peut écrire ses clés publiques

### Adversaire quantique futur
- Dispose d'un ordinateur quantique capable de casser RSA/ECDH/ECDSA

**Résistance :** ML-KEM-768 et ML-DSA-65 sont basés sur Module-LWE, résistant à l'algorithme de Shor. Niveau de sécurité NIST 3 (≈ AES-192 contre un adversaire quantique).

### Serveur compromis (Firebase)
- Firebase ou un employé Google lit les données Firestore

**Résistance :** Zero-knowledge — Firestore ne stocke que des ciphertexts. Même accès root Firebase ne compromet pas les messages en clair.

---

## Propriétés garanties

### Confidentialité
- Les messages ne peuvent être lus que par l'expéditeur et le destinataire.
- Chaque message est chiffré avec une clé dérivée via HKDF depuis un shared secret ML-KEM-768 frais.
- Les clés privées ne quittent jamais le navigateur de leur propriétaire.

### Intégrité
- Tag AES-GCM (128 bits) : toute modification du ciphertext invalide le tag → rejet.
- Signature ML-DSA-65 : toute modification de l'enveloppe invalide la signature → rejet.

### Authenticité
- Chaque message porte une signature ML-DSA-65 vérifiée avec la clé publique DSA de l'expéditeur.
- L'indicateur ✓ dans l'UI confirme que la signature est valide.
- Sans accès à la clé privée DSA d'Alice, personne ne peut se faire passer pour Alice.

### Forward Secrecy
- Le Double Ratchet dérive une `messageKey` unique par message via HKDF.
- La `messageKey` est effacée après usage.
- Compromettre l'état ratchet courant ne donne pas accès aux messages passés (les chaînes de clés ne permettent pas de remonter en arrière dans HKDF).

### Break-in Recovery
- Après compromission d'un état ratchet, le ratchet KEM génère un nouveau `sharedSecret` via ML-KEM-768 dès l'échange suivant.
- L'adversaire ne peut plus déchiffrer les nouveaux messages sans compromettre la nouvelle clé privée KEM.

### Résistance aux replay attacks
- Le `messageIndex` est inclus dans la dérivation HKDF.
- Un message rejoué avec un ancien `messageIndex` produirait une clé différente → déchiffrement échoue.

---

## Propriétés NON garanties

### Anonymat des métadonnées
Firestore stocke en clair :
- Les UIDs des participants (qui parle à qui)
- Les timestamps des messages
- La taille approximative des messages
- Les noms/tailles/types des pièces jointes (non chiffrés — métadonnées acceptées)

### Protection contre l'expéditeur
Alice peut envoyer n'importe quel message signé de sa propre clé. AegisQuantum ne protège pas Bob contre Alice.

### Suppression garantie
Firestore peut retenir des copies des documents supprimés (backups Google). La suppression d'un message côté client ne garantit pas l'effacement côté serveur.

### Deniability (déniabilité)
Les signatures ML-DSA-65 prouvent cryptographiquement que l'expéditeur a signé un message. Contrairement à Signal (qui utilise des MACs symétriques), AegisQuantum ne fournit pas de deniability.

---

## Analyse des vecteurs d'attaque

### 1. Compromission du mot de passe utilisateur

**Impact :** Si un attaquant obtient le mot de passe + accès à IndexedDB :
- Il peut dériver `vaultKey = Argon2id(password, salt)`.
- Déchiffrer le vault → obtenir les clés privées KEM + DSA.
- Déchiffrer tous les messages accessibles avec ces clés.

**Mitigation :**
- Argon2id (mémoire 64 MB, 3 itérations) rend le brute-force coûteux.
- Un attaquant sans accès à IndexedDB ne peut pas déchiffrer le vault même avec le mot de passe (il lui faut aussi le salt depuis Firestore).
- MDP fort recommandé (minimum 8 caractères enforced).

### 2. Compromission de IndexedDB

**Impact :** IndexedDB contient le vault chiffré AES-GCM.
- Sans le mot de passe : le vault est inaccessible (Argon2id est la seule voie de dérivation).
- Sans le salt Firestore : le vault est inaccessible (nécessaire pour Argon2id).

**Mitigation :** Double barrière — mot de passe + salt distant.

### 3. Substitution de clé publique (MITM)

**Scénario :** Un attaquant compromet Firestore et remplace la clé publique KEM de Bob par la sienne.

**Impact :** Les messages d'Alice seraient encapsulés avec la clé de l'attaquant → l'attaquant peut déchiffrer.

**Mitigation :**
- **Safety Numbers :** Alice et Bob comparent leur empreinte SHA-256 de clés via un canal out-of-band. Si elle diffère, une substitution a eu lieu.
- **Règles Firestore :** Seul Bob peut écrire `/publicKeys/bob`. Un attaquant sans token JWT de Bob ne peut pas modifier ses clés.
- **Limite :** Si Firebase est entièrement compromis (admin), les règles ne tiennent plus. Les Safety Numbers restent la défense ultime.

### 4. Compromission du serveur Firebase

**Impact :** L'attaquant voit tous les ciphertexts, les métadonnées (UIDs, timestamps), et les clés publiques.

**Ce qu'il ne peut PAS faire :**
- Déchiffrer les messages (pas de clés privées).
- Forger des messages (pas de clés privées DSA).
- Obtenir les clés privées (jamais stockées dans Firestore).

**Ce qu'il PEUT faire :**
- Supprimer ou modifier des messages (mais les clients verront des vérifications de signature échouer).
- Observer les métadonnées (qui parle à qui, quand).
- Substituer des clés publiques (mais les Safety Numbers permettent de détecter cela).

### 5. Export de session compromis (.aqsession)

**Impact :** Un fichier `.aqsession` intercepté contient les clés privées chiffrées + l'état ratchet.

**Mitigation :**
- Chiffré avec une clé dérivée de la phrase mnémotechnique (10 mots).
- Sans la phrase : indéchiffrable.
- La phrase n'est jamais stockée en clair — transmise séparément de manière sécurisée.

---

## Safety Numbers — Vérification d'empreinte

### Algorithme de calcul

```
input = kemPub_A ‖ dsaPub_A ‖ uid_A ‖ kemPub_B ‖ dsaPub_B ‖ uid_B
  (trié par UID pour la symétrie : même résultat pour A et pour B)

hash    = SHA-256(input)                   // 32 bytes
digits  = chaque byte → 3 chiffres décimaux // 20 premiers bytes = 60 chiffres
display = 12 groupes de 5 chiffres          // 60 chiffres total
```

### Propriétés

| Propriété | Valeur |
|---|---|
| Longueur de l'empreinte | 60 chiffres (12 groupes de 5) |
| Entropie effective | 160 bits (SHA-256 sur 20 premiers bytes) |
| Symétrie | Alice et Bob voient la même empreinte |
| Déterminisme | Identique à chaque recalcul si les clés n'ont pas changé |
| Sensibilité | Change si UNE des 4 clés change (KEM ou DSA, A ou B) |

### Usage pratique
1. Alice ouvre la modale "Safety Numbers" dans le chat.
2. Elle voit les 12 groupes de chiffres.
3. Elle appelle Bob et lui demande de lire ses chiffres.
4. Si identiques → pas de MITM.
5. Si différents → une clé a changé, possible compromission.

---

## Bilan de sécurité

| Catégorie | Niveau | Notes |
|---|---|---|
| Confidentialité messages | Très élevé | AES-256-GCM + ML-KEM-768 |
| Intégrité messages | Très élevé | AES-GCM tag + ML-DSA-65 |
| Forward secrecy | Élevé | Double Ratchet KDF chain |
| Break-in recovery | Élevé | Ratchet KEM ML-KEM-768 |
| Résistance quantique | Élevé | NIST PQC niveau 3 |
| Protection métadonnées | Faible | UIDs + timestamps en clair |
| Deniability | Faible | Signatures non-deniable |
| Anonymat | Faible | Firebase connaît les UIDs |
| Sécurité vault local | Élevé | Argon2id + AES-256-GCM |
| MITM avec Safety Numbers | Très élevé | Vérification out-of-band |
