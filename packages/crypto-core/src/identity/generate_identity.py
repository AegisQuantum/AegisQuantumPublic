"""
identity/generate_identity.py — Génération d'identité cryptographique

Chaque utilisateur possède une identité composite :
  - Clé Ed25519        : échange classique (X3DH classique)
  - Clé ML-DSA         : signature post-quantique (résistance quantique)
  - Clé ML-KEM         : échange de clés post-quantique

Dépendances :
  pip install cryptography liboqs-python
"""

from __future__ import annotations
from dataclasses import dataclass, field
import json
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

from pq.kyber import generate_keypair as kyber_keygen, KyberKeyPair
from pq.dilithium import generate_keypair as dilithium_keygen, DilithiumKeyPair


@dataclass
class IdentityPublicBundle:
    """Clés publiques partagées avec le serveur et les pairs."""
    ed25519_public: bytes        # 32 bytes — clé publique classique
    dilithium_public: bytes      # 1952 bytes — clé publique ML-DSA
    kyber_public: bytes          # 1568 bytes — clé publique ML-KEM

    def to_dict(self) -> dict:
        return {
            "ed25519_public": base64.b64encode(self.ed25519_public).decode(),
            "dilithium_public": base64.b64encode(self.dilithium_public).decode(),
            "kyber_public": base64.b64encode(self.kyber_public).decode(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class IdentitySecretBundle:
    """Clés secrètes — ne quittent JAMAIS le client."""
    ed25519_private: bytes       # clé privée Ed25519
    dilithium_secret: bytes      # clé secrète ML-DSA
    kyber_secret: bytes          # clé secrète ML-KEM

    def to_dict(self) -> dict:
        return {
            "ed25519_private": base64.b64encode(self.ed25519_private).decode(),
            "dilithium_secret": base64.b64encode(self.dilithium_secret).decode(),
            "kyber_secret": base64.b64encode(self.kyber_secret).decode(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class Identity:
    """Identité complète d'un utilisateur (public + secret)."""
    public: IdentityPublicBundle
    secret: IdentitySecretBundle


def generate_identity() -> Identity:
    """
    Génère une identité cryptographique complète.

    Crée :
      - 1 paire Ed25519   (clé d'identité classique)
      - 1 paire ML-DSA    (signature post-quantique)
      - 1 paire ML-KEM    (échange de clés post-quantique)

    Returns:
        Identity contenant les bundles public et secret.

    Usage:
        identity = generate_identity()
        # Envoyer identity.public au serveur
        # Stocker identity.secret en local (IndexedDB chiffré)
    """
    # Ed25519 — clé d'identité classique
    ed_private = Ed25519PrivateKey.generate()
    ed_public_bytes = ed_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ed_private_bytes = ed_private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    # ML-DSA (Dilithium3) — signature post-quantique
    dilithium_kp: DilithiumKeyPair = dilithium_keygen()

    # ML-KEM (Kyber-1024) — KEM post-quantique
    kyber_kp: KyberKeyPair = kyber_keygen()

    public = IdentityPublicBundle(
        ed25519_public=ed_public_bytes,
        dilithium_public=dilithium_kp.public_key,
        kyber_public=kyber_kp.public_key,
    )

    secret = IdentitySecretBundle(
        ed25519_private=ed_private_bytes,
        dilithium_secret=dilithium_kp.secret_key,
        kyber_secret=kyber_kp.secret_key,
    )

    return Identity(public=public, secret=secret)