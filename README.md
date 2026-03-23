# AegisQuantum

**Post-Quantum End-to-End Encrypted Messenger**

AegisQuantum is a web-based messaging application with **post-quantum cryptography** (ML-KEM-768 + ML-DSA-65). All encryption runs in the browser — the server never sees plaintext messages or private keys.

> **Open source engine.** You deploy your own Firebase backend. No central server. You own your data.

---

## Features

- **Post-quantum E2EE** — ML-KEM-768 (CRYSTALS-Kyber) + ML-DSA-65 (CRYSTALS-Dilithium), NIST level 3
- **Double Ratchet** — per-message keys, forward secrecy, break-in recovery
- **Zero-knowledge server** — Firebase stores only ciphertexts
- **Message signing** — every message carries an ML-DSA-65 signature
- **Safety Numbers** — out-of-band MITM verification (60-digit fingerprint)
- **Image & file sharing** — client-side AES-256-GCM encrypted before upload
- **Encrypted backup** — `.aqbackup` files protected by Argon2id
- **Multi-device session export** — `.aqsession` + 10-word mnemonic
- **Presence & typing indicators** — real-time via Firestore
- **Read receipts** — double checkmarks
- **Admin provisioning** — no self-registration, admin-only account creation

---

## Quick Start (Deploy your own instance)

### Prerequisites

- [Node.js](https://nodejs.org) >= 18
- [Firebase CLI](https://firebase.google.com/docs/cli): `npm install -g firebase-tools`
- A [Firebase project](https://console.firebase.google.com) with **Authentication** (Email/Password) and **Firestore** enabled

### One-command setup

```bash
git clone https://github.com/AegisQuantum/aegisquantum.git
cd aegisquantum
bash setup.sh
```

The script will:
1. Verify all dependencies (Node, npm, Firebase CLI)
2. Log you into Firebase
3. Ask for your Firebase project credentials (API keys, project ID)
4. Generate `frontend/.env` automatically
5. Install all npm dependencies (frontend + admin CLI)
6. Deploy Firestore security rules and indexes
7. Build the frontend
8. Deploy to Firebase Hosting (optional)

**That's it.** After setup, create your first user:

```bash
cd admin/
node create-user.js alice
```

---

## Architecture

```
frontend/src/
├── crypto/       Post-quantum crypto layer (KEM, DSA, AES-GCM, HKDF, Argon2, Double Ratchet)
├── services/     Business logic (auth, messaging, key registry, backup, presence)
├── ui/           Frontend views (chat, login, fingerprint, settings)
└── types/        TypeScript interfaces

admin/            Node.js CLI for account management (Firebase Admin SDK)
docs/             Full documentation
firestore.rules   Firestore security rules
```

→ Full architecture: [docs/architecture.md](docs/architecture.md)

---

## Documentation

| Document | Description |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Project structure, tech stack, startup flow, Firestore collections |
| [docs/crypto-protocol.md](docs/crypto-protocol.md) | All cryptographic primitives: ML-KEM-768, ML-DSA-65, AES-256-GCM, HKDF, Argon2id, mnemonic |
| [docs/double-ratchet-design.md](docs/double-ratchet-design.md) | Double Ratchet protocol design, bootstrap, ratchet reset, comparison with Signal |
| [docs/firestore-rules.md](docs/firestore-rules.md) | Firestore security rules explained rule-by-rule with rationale |
| [docs/security-analysis.md](docs/security-analysis.md) | Threat model, security guarantees, attack vector analysis, known limitations |
| [docs/features.md](docs/features.md) | Every feature explained: how it works, what it's for, implementation details |
| [docs/services.md](docs/services.md) | Services layer: auth, messaging, key-store, backup, presence, session-keys |
| [docs/ui.md](docs/ui.md) | UI layer: chat, login, fingerprint, change-password, main.ts |
| [docs/admin-guide.md](docs/admin-guide.md) | **Admin guide**: create, list, delete users — full provisioning workflow |

---

## Admin Guide

AegisQuantum uses **admin-only provisioning** — users cannot self-register.

```bash
# Create a user
cd admin/
node create-user.js alice

# List all users
node list-users.js

# Delete a user
node delete-user.js alice

# Reset a password
node reset-password.js alice
```

→ Full admin guide: [docs/admin-guide.md](docs/admin-guide.md)

---

## Development

```bash
# Start dev server (hot reload)
cd frontend/
npm run dev

# Run all tests
npm test

# Run security/pentest tests
npm run test:sec
npm run test:pentest
```

---

## Cryptographic Stack

| Primitive | Algorithm | Purpose |
|---|---|---|
| KEM | ML-KEM-768 (CRYSTALS-Kyber) | Key encapsulation, Double Ratchet |
| DSA | ML-DSA-65 (CRYSTALS-Dilithium) | Message signing & verification |
| Symmetric | AES-256-GCM | Message & vault encryption |
| KDF | HKDF-SHA-256 | Key derivation from KEM shared secret |
| Password hash | Argon2id | Vault key derivation from password |
| Mnemonic | 10-word phrase | Session export protection |
| Protocol | Double Ratchet (PQ) | Forward secrecy + break-in recovery |

All algorithms are NIST-standardized (PQC Round 3 / FIPS 203/204).

→ Full protocol details: [docs/crypto-protocol.md](docs/crypto-protocol.md)

---

## Security Model

- **Zero-knowledge server**: Firebase stores only ciphertexts — even full Firebase compromise doesn't expose messages
- **Post-quantum resistant**: ML-KEM-768 and ML-DSA-65 resist Shor's algorithm
- **Forward secrecy**: Double Ratchet — compromising one key doesn't expose past messages
- **Private keys never leave the browser**: stored AES-GCM encrypted in IndexedDB, never transmitted
- **MITM detection**: Safety Numbers (SHA-256 fingerprint of all 4 public keys)

→ Full security analysis: [docs/security-analysis.md](docs/security-analysis.md)

---

## Firebase Setup (Manual)

If you prefer manual configuration instead of `setup.sh`:

1. **Create Firebase project** at https://console.firebase.google.com
2. **Enable Authentication** → Sign-in method → Email/Password
3. **Enable Firestore** → Create database → Start in production mode
4. **Enable Hosting** → Build → Hosting
5. Copy `frontend/.env.example` → `frontend/.env` and fill in your config
6. Deploy rules: `firebase deploy --only firestore`
7. Build: `cd frontend && npm run build`
8. Deploy: `firebase deploy --only hosting`

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Contributing

Contributions welcome. Please read [docs/security-analysis.md](docs/security-analysis.md) before submitting cryptographic changes — security regressions are taken seriously.

For bug reports and security disclosures, open a GitHub issue.
