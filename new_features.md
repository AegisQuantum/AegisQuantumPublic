### 🟢 Facile (1-2 jours)

**✅Statut de lecture (read receipts)**
- Firestore : ajouter `readBy: string[]` dans le message doc
- UI : coche simple ✓ / ✓✓ dans la bulle

**✅Indicateur "en train d'écrire"**
- Firestore : `/conversations/{id}/typing/{uid}` avec TTL 3 secondes
- Aucun impact crypto

**Réactions emoji**
- Firestore : `reactions: { [emoji]: uid[] }` dans le message doc
- UI seulement

**Recherche dans les messages**
- Déchiffrer les messages en local, filtrer côté client
- Aucun impact Firestore (les messages chiffrés ne sont pas cherchables côté serveur — c'est une feature de sécurité)

### 🟡 Moyen (2-4 jours)

**Messages qui s'autodétruisent**
- Ajouter `expiresAt: number` dans le message doc
- Cloud Function Firebase qui supprime les messages expirés
- Client : masquer après expiry côté UI

**Rotation de clés** (déjà dans ton plan)
- `rotateKeys(uid)` dans `auth.ts`
- Force réinitialisation DR pour toutes les conversations

**Export chiffré de l'historique**
- Déchiffrer en mémoire + re-chiffrer avec une clé dérivée du mot de passe
- Exporter en `.aqbackup` (JSON chiffré AES-GCM)

**Envoie de fichiers**
- Déchiffrer en mémoire + re-chiffrer avec une clé dérivée du mot de passe
- Exporter en `.aqbackup` (JSON chiffré AES-GCM)

### 🔴 Complexe (> 1 semaine)

**Messages vocaux chiffrés**
- MediaRecorder API → ArrayBuffer → AES-GCM → Firestore Storage
- Même pipeline crypto, nouveau type de contenu

**Appels audio E2E**
- WebRTC + DTLS-SRTP + clés négociées via KEM
- Hors scope raisonnable pour la soutenance