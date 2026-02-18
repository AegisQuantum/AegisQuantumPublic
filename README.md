# 🛡️ AegisQuantum

> Messagerie instantanée chiffrée de bout en bout, résistante aux attaques quantiques.

AegisQuantum est une plateforme de communication sécurisée qui combine la cryptographie post-quantique (Kyber, Dilithium) avec le protocole Double Ratchet pour garantir une confidentialité totale des échanges, même face aux ordinateurs quantiques de demain.

---

## ✨ Fonctionnalités

- 🔐 **Chiffrement E2EE** — Les messages sont chiffrés côté client, le serveur ne voit jamais le contenu
- ⚛️ **Post-quantique** — Kyber (KEM) + Dilithium (signatures) résistants aux attaques quantiques
- 🔄 **Double Ratchet** — Perfect Forward Secrecy & Break-in Recovery sur chaque message
- 🔑 **Hybride X25519 + Kyber** — Sécurité classique et post-quantique combinées
- ⚡ **Temps réel** — WebSocket dédié pour la livraison instantanée des messages
- 💣 **Messages éphémères** — TTL configurable, suppression automatique après livraison
- 🌐 **Architecture monorepo** — API, WebSocket, Worker et Web découplés

---

## 🏗️ Architecture

```
AegisQuantum/
├── apps/
│   ├── api/          # NestJS REST API
│   ├── web/          # Frontend Next.js
│   ├── websocket/    # Serveur WebSocket temps réel
│   └── worker/       # Jobs background (BullMQ)
├── packages/
│   ├── crypto-core/  # Librairie crypto (Kyber, Dilithium, Double Ratchet)
│   ├── protocol/     # Schémas partagés (DTOs, events)
│   └── shared-types/ # Types TypeScript communs
└── infra/
    ├── docker/       # Dockerfiles & docker-compose
    ├── k8s/          # Manifests Kubernetes
    └── terraform/    # Infrastructure as Code
```

### Stack technique

| Couche | Technologie |
|---|---|
| API | NestJS + Prisma + PostgreSQL |
| Cache / Sessions | Redis |
| WebSocket | NestJS Gateway (Socket.io) |
| Jobs | BullMQ |
| Crypto | Kyber, Dilithium, X25519, ChaCha20, AES-GCM |
| Frontend | Next.js + TypeScript |
| Infra | Docker + Kubernetes + Terraform |

---

## 🔐 Protocole cryptographique

### Établissement de session (X3DH post-quantique)
1. Alice récupère le **key bundle** de Bob (identity key, signed prekey, one-time prekey)
2. Échange de clés hybride **X25519 + Kyber** pour dériver un secret partagé
3. Dérivation via **HKDF** d'une clé de session initiale
4. Initialisation du **Double Ratchet**

### Double Ratchet
- Chaque message dérive une nouvelle clé via le **Symmetric Ratchet**
- Chaque échange de messages fait avancer le **Diffie-Hellman Ratchet**
- Garantit le **Perfect Forward Secrecy** et la résistance à la compromission

### Algorithmes utilisés
- **KEM** : Kyber-1024 (NIST PQC standard)
- **Signatures** : Dilithium3 (NIST PQC standard)
- **Échange classique** : X25519
- **Chiffrement symétrique** : ChaCha20-Poly1305 / AES-256-GCM
- **Dérivation** : HKDF-SHA256

---

## 🚀 Démarrage rapide

### Prérequis
- Node.js 20+
- pnpm 9+
- Docker & Docker Compose

### Installation

```bash
# Cloner le repo
git clone https://github.com/Auuxencee/AegisQuantum.git
cd AegisQuantum

# Installer les dépendances
pnpm install

# Lancer l'infrastructure (PostgreSQL + Redis)
docker compose -f infra/docker/docker-compose.yml up -d

# Migrations Prisma
pnpm --filter api prisma migrate dev

# Lancer tous les services en dev
pnpm dev
```

### Variables d'environnement

```env
# apps/api/.env
DATABASE_URL=postgresql://user:password@localhost:5432/aegisquantum
REDIS_URL=redis://localhost:6379
JWT_SECRET=your_jwt_secret
JWT_REFRESH_SECRET=your_refresh_secret
```

---

## 📡 API Reference

### Auth
| Méthode | Route | Description |
|---|---|---|
| POST | `/auth/register` | Créer un compte + upload identity key |
| POST | `/auth/login` | Connexion, retourne JWT |
| POST | `/auth/refresh` | Renouveler le token |
| POST | `/auth/logout` | Invalider le refresh token |

### Keys
| Méthode | Route | Description |
|---|---|---|
| POST | `/keys/bundle` | Upload prekeys (one-time + signed) |
| GET | `/keys/:userId/bundle` | Récupérer le key bundle d'un utilisateur |

### Messages
| Méthode | Route | Description |
|---|---|---|
| POST | `/messages` | Envoyer un message chiffré |
| GET | `/messages/:conversationId` | Récupérer les messages en attente |
| DELETE | `/messages/:id` | Supprimer un message |

### Users
| Méthode | Route | Description |
|---|---|---|
| GET | `/users/:id` | Profil public + clé d'identité |
| GET | `/users/search` | Recherche par username |

---

## 🔌 WebSocket Events

```typescript
// Client → Serveur
'message:send'       // Envoyer un message
'message:delivered'  // Accusé de réception

// Serveur → Client
'message:new'        // Nouveau message entrant
'user:online'        // Un contact passe en ligne
'user:offline'       // Un contact se déconnecte
```

---

## 🗺️ Plan de développement

### Phase 1 — Fondations crypto `packages/crypto-core`

C'est le socle de tout le projet. Sans ça, rien ne peut fonctionner.

**1.1 Post-quantique**
- `pq/kyber.ts` — Encapsulation/décapsulation de clés (KEM)
- `pq/dilithium.ts` — Signatures post-quantiques

**1.2 Identité**
- `identity/generateIdentity.ts` — Génération identity key pair (Ed25519 + Dilithium)
- `identity/signPrekey.ts` — Signature des prekeys

**1.3 Échange de clés hybride**
- `hybrid/keyExchange.ts` — X25519 + Kyber combinés
- `hybrid/kdf.ts` — Dérivation HKDF

**1.4 Chiffrement symétrique**
- `symmetric/aes.ts` — AES-256-GCM
- `symmetric/chacha.ts` — ChaCha20-Poly1305

**1.5 Double Ratchet**
- `ratchet/chain.ts` — Chain key / message key
- `ratchet/doubleRatchet.ts` — Algorithme complet
- `ratchet/session.ts` — Gestion de session

> ✅ Livrable : package crypto-core testé et exporté, utilisable par l'API et le web

---

### Phase 2 — Schéma BDD & infrastructure `apps/api`

**2.1 Prisma schema**
- `User` — id, username, publicIdentityKey, createdAt
- `PreKey` — id, userId, keyId, publicKey, signature, used
- `SignedPreKey` — rotation périodique
- `Message` — id, senderId, recipientId, ciphertext, nonce, timestamp, expiresAt
- `Session` — ratchet state sérialisé par paire d'users

**2.2 Infrastructure**
- `infrastructure/database` — PrismaService
- `infrastructure/redis` — RedisService (sessions, rate limit, présence)
- `infrastructure/logger` — Logger structuré (Pino)

> ✅ Livrable : migrations Prisma propres, services injectables dans NestJS

---

### Phase 3 — API Core `apps/api/modules`

**3.1 Auth module**
- Register — génération identity, stockage clé publique
- Login — JWT access token + refresh token
- Guards JWT + Refresh
- 2FA optionnel

**3.2 Keys module**
- Upload bundle de prekeys (one-time + signed)
- Fetch key bundle d'un user (pour initier une session)
- Rotation automatique des signed prekeys

**3.3 Users module**
- `GET /users/:id` — profil public + clé publique
- Recherche par username
- Gestion du compte

**3.4 Messages module**
- `POST /messages` — envoyer un message chiffré (stockage temporaire serveur)
- `GET /messages/:conversationId` — récupérer les messages en attente
- Suppression après livraison (ou TTL)

**3.5 Health module**
- `/health` — check DB, Redis, services

> ✅ Livrable : API REST complète, documentée Swagger, testée

---

### Phase 4 — WebSocket `apps/websocket`

**4.1 Gateway**
- Connexion authentifiée (JWT à la handshake)
- Events : `message:send`, `message:delivered`, `message:read`

**4.2 Presence service**
- Suivi online/offline via Redis
- `user:online`, `user:offline` events

**4.3 Delivery service**
- Accusé de réception
- File d'attente si destinataire offline → stockage temporaire

**4.4 Rate limit**
- Anti-spam sur les events WebSocket

> ✅ Livrable : temps réel fonctionnel, résilient aux déconnexions

---

### Phase 5 — Worker `apps/worker`

**5.1 Jobs background**
- `rotate-prekeys.ts` — alerter/forcer rotation si stock de prekeys bas
- `cleanup-expired-messages.ts` — purge TTL des messages livrés
- `push-notifications.ts` — notifs push si user offline

> ✅ Livrable : jobs planifiés, fiables, loggés

---

### Phase 6 — Frontend `apps/web`

**6.1 Auth**
- Register/Login
- Génération des clés côté client
- Stockage sécurisé (IndexedDB chiffré)

**6.2 Crypto client**
- Intégration crypto-core dans le browser (WASM si besoin)
- Chiffrement/déchiffrement local transparent

**6.3 Chat**
- UI de messagerie temps réel
- Intégration WebSocket
- Indicateurs de livraison et de présence

**6.4 Settings**
- Gestion des clés et sessions actives
- Sécurité et préférences

> ✅ Livrable : application web E2EE fonctionnelle

---

### Phase 7 — Infra & Deploy

- Docker Compose pour dev local
- Kubernetes pour la production (déjà scaffoldé)
- Secrets management (Vault ou K8s secrets)
- CI/CD GitHub Actions (lint, test, build, deploy)

---

### Ordre de priorité

```
crypto-core → Prisma schema → Infrastructure → Auth → Keys → Messages → WebSocket → Worker → Web → Infra
```

---

## 🧪 Tests

```bash
# Tests unitaires
pnpm test

# Tests e2e
pnpm test:e2e

# Coverage
pnpm test:cov
```

---

## 📄 Licence

MIT © Auxence Massieux et Chloe Larroze — 2026