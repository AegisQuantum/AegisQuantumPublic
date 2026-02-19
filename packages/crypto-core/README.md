# crypto-core

Package de cryptographie post-quantique pour AegisQuantum.  
Implémente les phases 1.1 → 1.5 du protocole AegisQuantum.

---

## Installation des dépendances

### 1. Prérequis système

```bash
# macOS
brew install cmake openssl git

# Ubuntu / Debian
sudo apt install cmake gcc libssl-dev python3-dev git
```

### 2. Compiler et installer liboqs (lib C native)

```bash
git clone https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
cd /tmp/liboqs
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX=$HOME/_oqs ..
make -j4
make install

# Vérifier l'installation
ls $HOME/_oqs/lib/
# → doit afficher liboqs.dylib (macOS) ou liboqs.so (Linux)
```

### 3. Installer les dépendances Python

```bash
# macOS — utiliser Python 3.11
/Library/Frameworks/Python.framework/Versions/3.11/bin/pip3.11 install -r requirements.txt

# Linux
pip install -r requirements.txt
```

### 4. Créer le conftest.py (une seule fois)

```bash
# Depuis packages/crypto-core
cat > conftest.py << 'EOF'
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
EOF
```

### 5. Créer les `__init__.py` (une seule fois)

```bash
touch src/__init__.py
touch src/pq/__init__.py
touch src/identity/__init__.py
touch src/hybrid/__init__.py
touch src/symmetric/__init__.py
touch src/ratchet/__init__.py
```

---

## Lancer les tests

```bash
# macOS
/Library/Frameworks/Python.framework/Versions/3.11/bin/python3.11 -m pytest test/ -v

# Linux
python3 -m pytest test/ -v

# Avec coverage
/Library/Frameworks/Python.framework/Versions/3.11/bin/python3.11 -m pytest test/ -v --cov=src --cov-report=term-missing
```

---

## Structure

```
crypto-core/
├── src/
│   ├── pq/
│   │   ├── kyber.py          # ML-KEM-1024 (FIPS 203) — KEM post-quantique
│   │   └── dilithium.py      # ML-DSA (FIPS 204) — Signatures post-quantiques
│   ├── identity/
│   │   ├── generateIdentity.py  # Génération identité Ed25519 + ML-DSA + ML-KEM
│   │   └── signPrekey.py        # Génération et vérification des prekeys
│   ├── hybrid/
│   │   ├── keyExchange.py    # Échange hybride X25519 + ML-KEM
│   │   └── kdf.py            # HKDF-SHA256 + dérivation clés ratchet
│   ├── symmetric/
│   │   ├── aes.py            # AES-256-GCM (AEAD)
│   │   └── chacha.py         # ChaCha20-Poly1305 (AEAD)
│   └── ratchet/
│       ├── chain.py          # Symmetric-Key Ratchet (chain key → message key)
│       ├── doubleRatchet.py  # Algorithme Double Ratchet complet
│       └── session.py        # Couche session (haut niveau)
├── test/
│   └── test_crypto_core.py  # Suite de tests complète
├── conftest.py               # Config pytest (path vers src/)
└── requirements.txt
```

---

## Algorithmes — conformité ANSSI / NIST

| Fonction | Algorithme | Standard | Niveau |
|---|---|---|---|
| KEM post-quantique | ML-KEM-1024 | FIPS 203 | NIST 5 |
| Signature post-quantique | ML-DSA (Dilithium3) | FIPS 204 | NIST 3 |
| Échange classique | X25519 | RFC 7748 | — |
| Signature classique | Ed25519 | RFC 8032 | — |
| Chiffrement symétrique | ChaCha20-Poly1305 | RFC 8439 | — |
| Chiffrement symétrique | AES-256-GCM | NIST FIPS 197 | — |
| Dérivation de clés | HKDF-SHA256 | RFC 5869 | — |

---

## Sécurité

- Les clés secrètes ne quittent **jamais** le client
- Le nonce est généré aléatoirement via `os.urandom()` à chaque chiffrement
- La chain key est écrasée après chaque dérivation (Perfect Forward Secrecy)
- `MAX_SKIP = 1000` protège contre les attaques DoS par messages hors ordre