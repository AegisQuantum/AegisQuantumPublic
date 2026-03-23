# Couche UI — AegisQuantum

La couche UI gère toute la présentation et les interactions utilisateur. Elle est écrite en TypeScript vanilla (sans framework) et manipule le DOM directement.

---

## `ui/chat.ts`

Le fichier le plus volumineux de l'app (~2500 lignes). Il orchestre l'intégralité de l'interface de chat.

### Initialisation — `initChat(uid)`

Point d'entrée appelé après connexion réussie. Lance en parallèle :
- Chargement de la liste des contacts/conversations
- Souscription aux messages de la conversation courante
- Initialisation des composants UI (settings, lightbox, notifications, présence)

```
initChat(uid)
  ├─ loadContacts()           → liste conversations Firestore
  ├─ initCloseWarning()       → avertissement avant fermeture onglet
  ├─ initExportWarningBanner()→ bannière si clés non exportées
  ├─ initLightbox()           → visionneuse images
  └─ initPushNotifications()  → permissions notifications système
```

### Gestion des conversations

**`openConversation(contactUid)`**
1. Résout le pseudo du contact depuis Firestore
2. Démarre `subscribeToMessages(convId)` → `onSnapshot`
3. Charge les messages depuis le cache IndexedDB (affichage instantané)
4. Les nouveaux messages arrivent via l'abonnement temps réel

**`renderMessage(msg: DecryptedMessage)`**
Crée la bulle DOM correspondant au type de message :
- `msg.isDeleted` → bulle tombstone "*Ce message a été supprimé*"
- `msg.type === "system"` → bulle système centrée
- `msg.file` avec `image/*` → bulle image avec aperçu inline
- `msg.file` autre → bulle fichier avec icône + nom + taille
- Défaut → bulle texte

Chaque bulle affiche :
- Heure d'envoi
- Indicateur de vérification de signature (✓ ou ⚠)
- *(modifié)* si `msg.isEdited`
- Accusé de lecture (✓✓)

### Menu contextuel messages

Clic long / clic droit sur une bulle → menu avec actions :
- **Copier** (texte uniquement)
- **Modifier** (expéditeur uniquement, texte uniquement)
- **Supprimer pour tous** (expéditeur uniquement)
- **Répondre** (non implémenté — placeholder)

### Envoi de message — `handleSendMessage()`

1. Lire le contenu de l'input texte
2. Si `_pendingImageFile` → `sendFile()` au lieu de `sendMessage()`
3. `sendMessage(myUid, contactUid, plaintext)` → Firestore
4. Vider l'input + scroller vers le bas

### Upload d'image — input file `#input-image`

1. Sélection via `<input type="file" accept="image/*">`
2. Validation du type MIME côté client
3. `_setPendingImageUI(file)` → affiche une barre de prévisualisation
4. À l'envoi : `sendFile(myUid, contactUid, imageFile)`

### Indicateur de frappe

- Input `keydown` → `setTyping(true)` + debounce 3s → `setTyping(false)`
- Réception → affichage "... est en train d'écrire" sous la zone de messages

### Navigation vues

```typescript
switchView('chat' | 'settings' | 'contacts')
```

Affiche/masque les sections DOM avec `style.display`. Pas de routeur — SPA mono-page avec visibilité CSS.

### Settings panel

Accessible via le bouton ⚙ dans la navigation :
- Export session `.aqsession`
- Import session `.aqsession`
- Export backup `.aqbackup`
- Empreinte Safety Numbers
- Suppression de compte
- Déconnexion

### Bannière d'export de clés

Si les clés n'ont jamais été exportées (détection via IndexedDB flag), affiche une bannière en haut du chat invitant l'utilisateur à exporter ses clés pour ne pas les perdre.

### Avertissement de fermeture

`window.beforeunload` → message d'avertissement si des messages non envoyés sont en cours.

### Lightbox — `_openLightbox(blob, name, size)`

Overlay plein écran avec :
- Image `<img>` avec URL.createObjectURL
- Bouton télécharger : `<a href={url} download={name}>`
- Fermeture : touche Escape ou clic en dehors
- Révocation de l'URL object à la fermeture (évite les fuites mémoire)

### Toast notifications — `showToast(message)`

Notification temporaire en bas de l'écran (4 secondes). Utilisée pour :
- Confirmations d'envoi
- Erreurs de chiffrement/déchiffrement
- Confirmations de suppression

---

## `ui/login.ts`

Gère l'écran d'authentification avec plusieurs scénarios de connexion.

### Flux normal
```
Saisie username + password
→ handleSubmit()
→ aqSignIn() → vault déchiffré → initChat()
```

### Écran de récupération vault

Affiché si `VaultMissingError` est levée (vault absent en IndexedDB) :

```
┌─────────────────────────────────────┐
│  Clés introuvables sur cet appareil  │
│                                      │
│  [📁 Importer .aqsession]           │
│  [💀 Démarrer de zéro]              │
│  [👁 Accès lecture seule]           │
└─────────────────────────────────────┘
```

**Option "Importer .aqsession" :**
- Sélectionner un fichier + saisir la phrase mnémotechnique (10 mots)
- Barre de progression avec 5 phases
- Affichage masqué de la phrase par défaut (toggle œil)

**Option "Démarrer de zéro" :**
- Confirmation d'avertissement (action irréversible)
- `generateFreshKeys()` → nouvelles clés publiées dans Firestore
- Perte d'accès aux anciennes conversations

**Option "Lecture seule" :**
- Accès au chat sans clés privées
- Les messages affichent `[🔒 Message chiffré]`
- L'utilisateur peut importer ses clés plus tard depuis les paramètres

### Import session depuis l'écran de login

Panneau dépliable "Nouvel appareil ?" sur l'écran de login principal :
1. Remplir username + password
2. Sélectionner le `.aqsession`
3. Saisir la phrase mnémotechnique
4. Clic "Se connecter et importer" → connexion Firebase + import en une étape

### Gestion d'erreurs Firebase

Messages d'erreur traduits pour les codes Firebase courants :
- `invalid-credential` / `wrong-password` → "Invalid username or password."
- `network-request-failed` → "Network error — check your connection."
- `too-many-requests` → "Too many attempts. Please wait a moment."
- `user-disabled` → "This account has been disabled."

---

## `ui/fingerprint.ts`

Calcul et affichage des Safety Numbers pour vérification MITM.

### Algorithme de calcul

```
input = concat(kemPub1, dsaPub1, uid1, kemPub2, dsaPub2, uid2)
  (trié par UID pour garantir la symétrie)
hash  = SHA-256(input)
→ 20 premiers bytes → 12 groupes de 5 chiffres décimaux
```

### Rendu de la modale

```
┌─────────────────────────────────────────┐
│  🔐  Empreinte de sécurité               │
│                                         │
│  Votre empreinte    Empreinte du contact │
│  ┌──────────────┐  ┌──────────────┐     │
│  │12345 67890   │  │12345 67890   │     │  ← identiques si pas de MITM
│  │11223 34455   │  │11223 34455   │     │
│  │...           │  │...           │     │
│  └──────────────┘  └──────────────┘     │
│                                         │
│  ⚠ Non vérifié — comparez hors app     │
└─────────────────────────────────────────┘
```

**Note :** Les deux sections affichent la même empreinte car elle est calculée symétriquement. L'utilisateur doit comparer avec ce que son contact voit sur son propre écran.

### API publique

```typescript
openFingerprintModal(myUid, contactUid)  // ouvre la modale
closeFingerprintModal()                   // ferme la modale
computeSafetyNumbers(uid1, kemPub1, dsaPub1, uid2, kemPub2, dsaPub2)  // calcul pur
loadAndComputeSafetyNumbers(myUid, contactUid)  // charger depuis Firestore + calculer
```

---

## `ui/change-password.ts`

Écran simple de changement de mot de passe affiché à la première connexion.

### Validations
- Minimum 8 caractères
- Confirmation identique
- Désactivation du bouton pendant le traitement

### Flux
```
Saisie nouveau MDP + confirmation
→ changePassword(uid, newPw)
    → argon2Derive(newPw)    → nouveau vaultKey
    → aesGcmEncrypt(vault)   → nouveau vault IndexedDB
    → Firestore update       → nouveau salt
    → delete /provisioned/   → flag effacé
→ initChat(uid)
```

---

## `main.ts`

Point d'entrée de l'application. Rôle minimal :

1. `initAuth()` → affiche l'écran de login
2. `onAuthChange(callback)` → écoute uniquement la **déconnexion**

```typescript
onAuthChange((user) => {
  if (!user) {
    // Token expiré ou signOut → retour écran login
    // Les clés privées disparaissent de la mémoire
  }
  // Si user != null au chargement (session Firebase persistée) :
  // ON NE FAIT RIEN — l'utilisateur doit se reconnecter pour
  // recharger ses clés privées (volatile, non persistées)
});
```

**Pourquoi ne pas auto-connecter si session Firebase active ?**
Firebase persiste le token JWT en localStorage. Au rechargement, `onAuthStateChanged` reçoit l'utilisateur. Mais les **clés privées** ne sont pas persistées (elles sont en mémoire volatile). Sans les clés, l'app ne peut pas déchiffrer les messages — l'utilisateur doit se reconnecter pour les recharger depuis le vault IndexedDB.

---

## Structure des vues DOM

```html
<body>
  #auth-screen           ← Connexion / inscription
  #vault-recovery-screen ← Récupération vault (nouvvel appareil)
  #change-password-screen← Changement MDP obligatoire
  #chat-screen           ← Application principale
    #contact-list        ← Colonne gauche : conversations
    #chat-view           ← Colonne centre : messages + input
    #settings-view       ← Panneau paramètres
  #fingerprint-modal     ← Overlay Safety Numbers
  #lightbox-overlay      ← Overlay visionneuse images
</body>
```

La navigation entre vues est gérée par `classList.add/remove('hidden', 'active')` et `style.display`. Pas de routeur côté client.
