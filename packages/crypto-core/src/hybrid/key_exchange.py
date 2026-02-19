"""
hybrid/key_exchange.py — Échange de clés hybride X25519 + ML-KEM-1024

Combine la sécurité classique (X25519) et post-quantique (Kyber-1024)
pour résister aux attaques classiques ET quantiques.

Principe : le secret final est dérivé des DEUX échanges combinés.
Si l'un des deux est compromis, la sécurité de l'autre tient.

Schéma (Alice initie, Bob répond) :
  1. Alice génère une clé X25519 éphémère
  2. Alice encapsule avec la clé ML-KEM de Bob → (ct_kyber, ss_kyber)
  3. Alice envoie : {x25519_ephemeral_pub, ct_kyber}
  4. Bob effectue X25519(bob_x25519_priv, alice_x25519_pub) → dh_secret
  5. Bob décapsule ct_kyber avec kyber_secret → ss_kyber
  6. Les deux dérivent le secret final via HKDF(dh_secret || ss_kyber)

Dépendances :
  pip install cryptography liboqs-python
"""

from __future__ import annotations
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

from pq.kyber import encapsulate as kyber_encap, decapsulate as kyber_decap
from hybrid.kdf import hkdf_derive


@dataclass
class HybridInitMessage:
    """Message d'initiation envoyé par Alice à Bob."""
    x25519_ephemeral_public: bytes   # 32 bytes
    kyber_ciphertext: bytes          # 1568 bytes

    # Gardé localement par Alice pour compléter l'échange
    _x25519_ephemeral_private: bytes = None
    _kyber_shared_secret: bytes = None


@dataclass
class HybridSharedSecret:
    """Secret partagé final dérivé de l'échange hybride."""
    shared_secret: bytes             # 32 bytes — clé de session


def initiator_start(
    bob_x25519_public: bytes,
    bob_kyber_public: bytes,
    info: bytes = b"AegisQuantum-v1-hybrid-kex",
    salt: bytes | None = None,
) -> tuple[HybridInitMessage, HybridSharedSecret]:
    """
    Étape 1 (Alice / initiateur) — Lance l'échange hybride.

    Args:
        bob_x25519_public : clé X25519 publique de Bob (32 bytes)
        bob_kyber_public  : clé ML-KEM publique de Bob (1568 bytes)
        info              : contexte HKDF (bind à l'application)
        salt              : sel HKDF optionnel

    Returns:
        (HybridInitMessage, HybridSharedSecret)
        - HybridInitMessage  → à envoyer à Bob
        - HybridSharedSecret → secret partagé côté Alice
    """
    # Générer clé X25519 éphémère
    eph_private = X25519PrivateKey.generate()
    eph_public_bytes = eph_private.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    eph_private_bytes = eph_private.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )

    # DH classique : X25519(alice_eph_priv, bob_x25519_pub)
    bob_x25519_key = X25519PublicKey.from_public_bytes(bob_x25519_public)
    dh_secret = eph_private.exchange(bob_x25519_key)

    # KEM post-quantique : encapsuler avec la clé ML-KEM de Bob
    kyber_result = kyber_encap(bob_kyber_public)

    # Dériver le secret final : HKDF(dh_secret || kyber_shared_secret)
    combined = dh_secret + kyber_result.shared_secret
    shared_secret = hkdf_derive(combined, length=32, info=info, salt=salt)

    init_msg = HybridInitMessage(
        x25519_ephemeral_public=eph_public_bytes,
        kyber_ciphertext=kyber_result.ciphertext,
        _x25519_ephemeral_private=eph_private_bytes,
        _kyber_shared_secret=kyber_result.shared_secret,
    )

    return init_msg, HybridSharedSecret(shared_secret=shared_secret)


def responder_finish(
    init_msg: HybridInitMessage,
    bob_x25519_private: bytes,
    bob_kyber_secret: bytes,
    info: bytes = b"AegisQuantum-v1-hybrid-kex",
    salt: bytes | None = None,
) -> HybridSharedSecret:
    """
    Étape 2 (Bob / répondeur) — Complète l'échange et dérive le même secret.

    Args:
        init_msg          : message reçu d'Alice
        bob_x25519_private: clé X25519 secrète de Bob (32 bytes)
        bob_kyber_secret  : clé ML-KEM secrète de Bob (3168 bytes)
        info              : même contexte HKDF qu'à l'initiation
        salt              : même sel HKDF qu'à l'initiation

    Returns:
        HybridSharedSecret — identique à celui d'Alice si l'échange est correct
    """
    # DH classique : X25519(bob_x25519_priv, alice_eph_pub)
    bob_x25519_key = X25519PrivateKey.from_private_bytes(bob_x25519_private)
    alice_eph_pub = X25519PublicKey.from_public_bytes(init_msg.x25519_ephemeral_public)
    dh_secret = bob_x25519_key.exchange(alice_eph_pub)

    # KEM post-quantique : décapsuler le ciphertext de Kyber
    kyber_shared_secret = kyber_decap(init_msg.kyber_ciphertext, bob_kyber_secret)

    # Dériver le secret final — même procédé qu'Alice
    combined = dh_secret + kyber_shared_secret
    shared_secret = hkdf_derive(combined, length=32, info=info, salt=salt)

    return HybridSharedSecret(shared_secret=shared_secret)