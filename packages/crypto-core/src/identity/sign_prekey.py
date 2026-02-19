"""
identity/sign_prekey.py — Signature des prekeys

Les prekeys sont des clés éphémères pré-générées permettant l'établissement
de session asynchrone (X3DH). Chaque prekey doit être signée par la clé
d'identité pour prouver son authenticité.

Types de prekeys :
  - SignedPreKey  : une seule active à la fois, rotation périodique (~7 jours)
  - OneTimePreKey : stock de clés à usage unique (~100 à la fois)

Dépendances :
  pip install cryptography liboqs-python
"""

from __future__ import annotations
from dataclasses import dataclass
import os
import base64
import json
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

from pq.dilithium import sign as dilithium_sign, verify as dilithium_verify
from pq.kyber import generate_keypair as kyber_keygen


@dataclass
class SignedPreKey:
    """
    Prekey signée — une par utilisateur, rotation ~7 jours.
    Contient une clé X25519 + une clé ML-KEM pour l'hybride.
    """
    key_id: int
    x25519_public: bytes          # 32 bytes
    x25519_private: bytes         # 32 bytes (secret, stocké localement)
    kyber_public: bytes           # 1568 bytes
    kyber_secret: bytes           # 3168 bytes (secret, stocké localement)
    signature_ed25519: bytes      # Signature Ed25519 sur les clés publiques
    signature_dilithium: bytes    # Signature ML-DSA sur les clés publiques
    created_at: int               # timestamp UNIX

    def public_payload(self) -> dict:
        """Payload à envoyer au serveur (sans les clés secrètes)."""
        return {
            "key_id": self.key_id,
            "x25519_public": base64.b64encode(self.x25519_public).decode(),
            "kyber_public": base64.b64encode(self.kyber_public).decode(),
            "signature_ed25519": base64.b64encode(self.signature_ed25519).decode(),
            "signature_dilithium": base64.b64encode(self.signature_dilithium).decode(),
            "created_at": self.created_at,
        }


@dataclass
class OneTimePreKey:
    """
    Prekey à usage unique — consommée lors de chaque établissement de session.
    """
    key_id: int
    x25519_public: bytes
    x25519_private: bytes         # secret, stocké localement
    kyber_public: bytes
    kyber_secret: bytes           # secret, stocké localement

    def public_payload(self) -> dict:
        return {
            "key_id": self.key_id,
            "x25519_public": base64.b64encode(self.x25519_public).decode(),
            "kyber_public": base64.b64encode(self.kyber_public).decode(),
        }


def _generate_x25519_pair() -> tuple[bytes, bytes]:
    """Retourne (public_bytes, private_bytes) pour X25519."""
    priv = X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return pub_bytes, priv_bytes


def _sign_prekey_material(
    x25519_public: bytes,
    kyber_public: bytes,
    key_id: int,
    ed25519_private: bytes,
    dilithium_secret: bytes,
) -> tuple[bytes, bytes]:
    """
    Signe le matériel de prekey avec Ed25519 ET ML-DSA.
    Le message signé = key_id (4 bytes) || x25519_public || kyber_public
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

    message = key_id.to_bytes(4, "big") + x25519_public + kyber_public

    # Signature Ed25519
    ed_key = Ed25519PrivateKey.from_private_bytes(ed25519_private)
    sig_ed = ed_key.sign(message)

    # Signature ML-DSA
    sig_dil = dilithium_sign(message, dilithium_secret)

    return sig_ed, sig_dil


def generate_signed_prekey(
    key_id: int,
    ed25519_private: bytes,
    dilithium_secret: bytes,
) -> SignedPreKey:
    """
    Génère et signe une SignedPreKey.

    Args:
        key_id           : identifiant unique de la prekey
        ed25519_private  : clé privée Ed25519 de l'identité
        dilithium_secret : clé secrète ML-DSA de l'identité

    Returns:
        SignedPreKey complète (public + secret + signatures)
    """
    x25519_pub, x25519_priv = _generate_x25519_pair()
    kyber_kp = kyber_keygen()

    sig_ed, sig_dil = _sign_prekey_material(
        x25519_pub,
        kyber_kp.public_key,
        key_id,
        ed25519_private,
        dilithium_secret,
    )

    return SignedPreKey(
        key_id=key_id,
        x25519_public=x25519_pub,
        x25519_private=x25519_priv,
        kyber_public=kyber_kp.public_key,
        kyber_secret=kyber_kp.secret_key,
        signature_ed25519=sig_ed,
        signature_dilithium=sig_dil,
        created_at=int(time.time()),
    )


def generate_one_time_prekeys(count: int = 100) -> list[OneTimePreKey]:
    """
    Génère un stock de prekeys à usage unique.

    Args:
        count : nombre de prekeys à générer (défaut 100)

    Returns:
        Liste de OneTimePreKey (les public_payload seront uploadés au serveur)
    """
    prekeys = []
    for i in range(count):
        x25519_pub, x25519_priv = _generate_x25519_pair()
        kyber_kp = kyber_keygen()
        prekeys.append(OneTimePreKey(
            key_id=i,
            x25519_public=x25519_pub,
            x25519_private=x25519_priv,
            kyber_public=kyber_kp.public_key,
            kyber_secret=kyber_kp.secret_key,
        ))
    return prekeys


def verify_signed_prekey(
    prekey: dict,
    ed25519_public: bytes,
    dilithium_public: bytes,
) -> bool:
    """
    Vérifie les signatures d'une SignedPreKey reçue du serveur.

    Args:
        prekey           : dict issu de public_payload()
        ed25519_public   : clé publique Ed25519 du propriétaire
        dilithium_public : clé publique ML-DSA du propriétaire

    Returns:
        True si les deux signatures sont valides
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    key_id = prekey["key_id"]
    x25519_pub = base64.b64decode(prekey["x25519_public"])
    kyber_pub = base64.b64decode(prekey["kyber_public"])
    sig_ed = base64.b64decode(prekey["signature_ed25519"])
    sig_dil = base64.b64decode(prekey["signature_dilithium"])

    message = key_id.to_bytes(4, "big") + x25519_pub + kyber_pub

    # Vérif Ed25519
    try:
        ed_key = Ed25519PublicKey.from_public_bytes(ed25519_public)
        ed_key.verify(sig_ed, message)
    except Exception:
        return False

    # Vérif ML-DSA
    return dilithium_verify(message, sig_dil, dilithium_public)