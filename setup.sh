#!/usr/bin/env bash
# =============================================================================
#  AegisQuantum — Script de setup & déploiement
#  Usage : bash setup.sh
# =============================================================================
set -euo pipefail

# ─── Couleurs ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

header()  { echo -e "\n${BOLD}${CYAN}══  $1  ══${RESET}"; }
success() { echo -e "${GREEN}✔  $1${RESET}"; }
warn()    { echo -e "${YELLOW}⚠  $1${RESET}"; }
error()   { echo -e "${RED}✘  $1${RESET}"; exit 1; }
info()    { echo -e "   $1"; }

# ─── Banner ──────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
cat << 'EOF'
    _             _       ___                    _
   / \   ___  __ _(_)___ / _ \ _   _  __ _ _ __ | |_ _   _ _ __ ___
  / _ \ / _ \/ _` | / __| | | | | | |/ _` | '_ \| __| | | | '_ ` _ \
 / ___ \  __/ (_| | \__ \ |_| | |_| | (_| | | | | |_| |_| | | | | | |
/_/   \_\___|\__, |_|___/\__\_\\__,_|\__,_|_| |_|\__|\__,_|_| |_| |_|
             |___/
          Post-Quantum E2E Encrypted Messenger — Setup & Deploy
EOF
echo -e "${RESET}"

# ─── 1. Vérification des dépendances système ─────────────────────────────────
header "Vérification des dépendances"

check_cmd() {
  if command -v "$1" &>/dev/null; then
    success "$1 trouvé ($(command -v "$1"))"
  else
    error "$1 n'est pas installé. Installez-le puis relancez ce script."
  fi
}

check_cmd node
check_cmd npm
check_cmd firebase

# Vérification version Node >= 18
NODE_VERSION=$(node -e "process.exit(parseInt(process.versions.node.split('.')[0]) < 18 ? 1 : 0)" 2>&1 || true)
NODE_MAJOR=$(node -e "console.log(parseInt(process.versions.node.split('.')[0]))")
if [ "$NODE_MAJOR" -lt 18 ]; then
  error "Node.js >= 18 requis. Version actuelle : $(node -v)"
fi
success "Node.js $(node -v) — OK"

# ─── 2. Firebase Login ───────────────────────────────────────────────────────
header "Connexion Firebase"

if firebase projects:list &>/dev/null 2>&1; then
  success "Déjà connecté à Firebase CLI"
else
  info "Lancement de firebase login..."
  firebase login
fi

# ─── 3. Configuration du projet Firebase ─────────────────────────────────────
header "Configuration du projet Firebase"

echo ""
echo -e "${BOLD}Vous avez besoin de créer (ou d'avoir déjà) un projet Firebase.${RESET}"
echo "  → https://console.firebase.google.com"
echo "  → Créer un nouveau projet (ou sélectionner un existant)"
echo "  → Activer : Authentication (Email/Password) + Firestore Database"
echo ""

# Liste les projets disponibles
echo -e "${CYAN}Vos projets Firebase disponibles :${RESET}"
firebase projects:list || warn "Impossible de lister les projets (vérifiez votre connexion)"
echo ""

read -p "$(echo -e ${BOLD})Entrez votre Firebase Project ID : $(echo -e ${RESET})" FIREBASE_PROJECT_ID
[ -z "$FIREBASE_PROJECT_ID" ] && error "Project ID requis."

# Mettre à jour .firebaserc
cat > .firebaserc << FIREBASERC
{
  "projects": {
    "default": "${FIREBASE_PROJECT_ID}"
  }
}
FIREBASERC
success ".firebaserc mis à jour avec le projet : $FIREBASE_PROJECT_ID"

# Mettre à jour firebase.json (hosting site = project ID)
# Le site d'hébergement doit exister dans Firebase Hosting
sed -i.bak "s/\"site\": \"[^\"]*\"/\"site\": \"${FIREBASE_PROJECT_ID}\"/" firebase.json && rm -f firebase.json.bak
success "firebase.json mis à jour"

# ─── 4. Collecte des clés Firebase ───────────────────────────────────────────
header "Clés Firebase (SDK Web)"

echo ""
echo -e "${BOLD}Dans la Firebase Console :${RESET}"
echo "  1. Project Settings (⚙) → General"
echo "  2. Descendre jusqu'à 'Your apps' → cliquer sur '</>' (Web)"
echo "  3. Copier les valeurs du firebaseConfig"
echo ""

read -p "API Key            : " FB_API_KEY
read -p "Auth Domain        : " FB_AUTH_DOMAIN
read -p "Project ID         : " FB_PROJECT_ID_ENV
read -p "Storage Bucket     : " FB_STORAGE_BUCKET
read -p "Messaging Sender ID: " FB_MESSAGING_SENDER_ID
read -p "App ID             : " FB_APP_ID

# Valider que les champs ne sont pas vides
for field in FB_API_KEY FB_AUTH_DOMAIN FB_PROJECT_ID_ENV FB_STORAGE_BUCKET FB_MESSAGING_SENDER_ID FB_APP_ID; do
  [ -z "${!field}" ] && error "Le champ $field est requis."
done

# Écrire le fichier .env
cat > frontend/.env << ENV
# AegisQuantum — Firebase Config
# Généré automatiquement par setup.sh — ne pas committer
VITE_FIREBASE_API_KEY=${FB_API_KEY}
VITE_FIREBASE_AUTH_DOMAIN=${FB_AUTH_DOMAIN}
VITE_FIREBASE_PROJECT_ID=${FB_PROJECT_ID_ENV}
VITE_FIREBASE_STORAGE_BUCKET=${FB_STORAGE_BUCKET}
VITE_FIREBASE_MESSAGING_SENDER_ID=${FB_MESSAGING_SENDER_ID}
VITE_FIREBASE_APP_ID=${FB_APP_ID}
ENV
success "frontend/.env créé avec succès"

# ─── 5. Installation des dépendances ─────────────────────────────────────────
header "Installation des dépendances"

info "Installation frontend (peut prendre 1-2 minutes)..."
cd frontend
npm install
success "Dépendances frontend installées"
cd ..

info "Installation admin CLI..."
cd admin
npm install
success "Dépendances admin installées"
cd ..

# ─── 6. Déploiement Firestore (règles + index) ───────────────────────────────
header "Déploiement Firestore"

info "Déploiement des règles de sécurité Firestore..."
firebase deploy --only firestore --project "$FIREBASE_PROJECT_ID"
success "Règles Firestore et index déployés"

# ─── 7. Build du frontend ────────────────────────────────────────────────────
header "Build du frontend"

info "Compilation TypeScript + Vite..."
cd frontend
npm run build
cd ..
success "Build terminé → frontend/dist/"

# ─── 8. Déploiement Firebase Hosting ─────────────────────────────────────────
header "Déploiement Firebase Hosting"

echo ""
echo -e "${YELLOW}Note : Firebase Hosting doit être activé pour votre projet.${RESET}"
echo "  → Firebase Console → Build → Hosting → Get started"
echo ""
read -p "$(echo -e ${BOLD})Déployer vers Firebase Hosting ? [o/n] : $(echo -e ${RESET})" DEPLOY_HOSTING

if [[ "$DEPLOY_HOSTING" =~ ^[oOyY]$ ]]; then
  firebase deploy --only hosting --project "$FIREBASE_PROJECT_ID"
  success "Application déployée sur Firebase Hosting"
  echo ""
  echo -e "${GREEN}${BOLD}🚀 Votre application est accessible sur :${RESET}"
  echo -e "   ${CYAN}https://${FIREBASE_PROJECT_ID}.web.app${RESET}"
  echo -e "   ${CYAN}https://${FIREBASE_PROJECT_ID}.firebaseapp.com${RESET}"
else
  warn "Déploiement Hosting ignoré."
  info "Pour déployer manuellement plus tard :"
  info "  cd frontend && npm run build && cd .. && firebase deploy --only hosting"
fi

# ─── 9. Configuration admin CLI ──────────────────────────────────────────────
header "Configuration du CLI Admin"

echo ""
echo -e "${BOLD}Pour créer des comptes utilisateurs, vous avez besoin d'une Service Account Key.${RESET}"
echo "  1. Firebase Console → Project Settings (⚙) → Service accounts"
echo "  2. Cliquer 'Generate new private key' → télécharger le JSON"
echo "  3. Renommer ce fichier 'serviceAccountKey.json'"
echo "  4. Le placer dans le dossier admin/"
echo ""
echo -e "${RED}⚠  Ne jamais committer serviceAccountKey.json (déjà dans .gitignore)${RESET}"
echo ""

# ─── 10. Résumé ──────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  ✔  Setup AegisQuantum terminé avec succès !${RESET}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "${BOLD}Prochaines étapes :${RESET}"
echo ""
echo -e "  ${CYAN}1. Créer votre premier utilisateur :${RESET}"
echo "     cd admin && node create-user.js <username>"
echo ""
echo -e "  ${CYAN}2. Lancer le serveur de développement :${RESET}"
echo "     cd frontend && npm run dev"
echo ""
echo -e "  ${CYAN}3. Lire la documentation :${RESET}"
echo "     docs/README.md (ou le README.md racine)"
echo ""
echo -e "  ${CYAN}4. Guide admin complet :${RESET}"
echo "     docs/admin-guide.md"
echo ""
