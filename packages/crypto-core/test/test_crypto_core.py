"""
tests/test_crypto_core.py — Suite de tests pour le crypto-core

Lance avec :
  pip install pytest
  pytest tests/ -v

Chaque test est conçu pour être indépendant et reproductible.
Les tests vérifient la correction cryptographique (pas les perfs).
"""

import pytest
import os


# ================================================================== #
#  1. ML-KEM (Kyber-1024)                                             #
# ================================================================== #

class TestKyber:
    def test_keypair_sizes(self):
        from pq.kyber import generate_keypair
        kp = generate_keypair()
        assert len(kp.public_key) == 1568, "Clé publique ML-KEM-1024 doit être 1568 bytes"
        assert len(kp.secret_key) == 3168, "Clé secrète ML-KEM-1024 doit être 3168 bytes"

    def test_encapsulate_decapsulate(self):
        from pq.kyber import generate_keypair, encapsulate, decapsulate
        kp = generate_keypair()
        enc = encapsulate(kp.public_key)

        assert len(enc.ciphertext) == 1568
        assert len(enc.shared_secret) == 32

        recovered = decapsulate(enc.ciphertext, kp.secret_key)
        assert recovered == enc.shared_secret, "Les shared secrets doivent être identiques"

    def test_wrong_key_gives_different_secret(self):
        from pq.kyber import generate_keypair, encapsulate, decapsulate
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        enc = encapsulate(kp1.public_key)

        recovered = decapsulate(enc.ciphertext, kp2.secret_key)
        assert recovered != enc.shared_secret, "Mauvaise clé → secret différent"


# ================================================================== #
#  2. ML-DSA (Dilithium3)                                             #
# ================================================================== #

class TestDilithium:
    def test_sign_verify(self):
        from pq.dilithium import generate_keypair, sign, verify
        kp = generate_keypair()
        message = b"AegisQuantum test message"
        sig = sign(message, kp.secret_key)

        assert verify(message, sig, kp.public_key), "Signature valide doit passer"

    def test_tampered_message_fails(self):
        from pq.dilithium import generate_keypair, sign, verify
        kp = generate_keypair()
        message = b"Message original"
        sig = sign(message, kp.secret_key)

        assert not verify(b"Message modifie", sig, kp.public_key), \
            "Message altéré → signature invalide"

    def test_wrong_key_fails(self):
        from pq.dilithium import generate_keypair, sign, verify
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        message = b"Test"
        sig = sign(message, kp1.secret_key)

        assert not verify(message, sig, kp2.public_key), \
            "Mauvaise clé publique → signature invalide"


# ================================================================== #
#  3. Identité                                                         #
# ================================================================== #

class TestIdentity:
    def test_generate_identity_structure(self):
        from identity.generate_identity import generate_identity
        identity = generate_identity()

        assert len(identity.public.ed25519_public) == 32
        assert len(identity.public.dilithium_public) == 1952
        assert len(identity.public.kyber_public) == 1568

        assert len(identity.secret.ed25519_private) == 32
        assert len(identity.secret.dilithium_secret) == 4032
        assert len(identity.secret.kyber_secret) == 3168

    def test_identity_serialization(self):
        from identity.generate_identity import generate_identity
        import json
        identity = generate_identity()
        d = identity.public.to_dict()
        assert "ed25519_public" in d
        assert "dilithium_public" in d
        assert "kyber_public" in d

        # Vérifier que c'est du JSON valide
        json.loads(identity.public.to_json())


# ================================================================== #
#  4. Sign Prekey                                                      #
# ================================================================== #

class TestSignPrekey:
    def test_signed_prekey_generation_and_verification(self):
        from identity.generate_identity import generate_identity
        from identity.sign_prekey import generate_signed_prekey, verify_signed_prekey

        identity = generate_identity()
        prekey = generate_signed_prekey(
            key_id=1,
            ed25519_private=identity.secret.ed25519_private,
            dilithium_secret=identity.secret.dilithium_secret,
        )

        assert prekey.key_id == 1
        assert len(prekey.x25519_public) == 32
        assert len(prekey.kyber_public) == 1568

        valid = verify_signed_prekey(
            prekey.public_payload(),
            identity.public.ed25519_public,
            identity.public.dilithium_public,
        )
        assert valid, "La prekey signée doit être vérifiable"

    def test_tampered_prekey_fails_verification(self):
        from identity.generate_identity import generate_identity
        from identity.sign_prekey import generate_signed_prekey, verify_signed_prekey
        import base64

        identity = generate_identity()
        prekey = generate_signed_prekey(1, identity.secret.ed25519_private, identity.secret.dilithium_secret)
        payload = prekey.public_payload()

        # Altérer la clé publique
        payload["x25519_public"] = base64.b64encode(os.urandom(32)).decode()

        valid = verify_signed_prekey(payload, identity.public.ed25519_public, identity.public.dilithium_public)
        assert not valid, "Prekey altérée doit échouer la vérification"

    def test_one_time_prekeys_generation(self):
        from identity.sign_prekey import generate_one_time_prekeys
        prekeys = generate_one_time_prekeys(count=10)
        assert len(prekeys) == 10
        assert all(len(pk.x25519_public) == 32 for pk in prekeys)
        assert all(len(pk.kyber_public) == 1568 for pk in prekeys)


# ================================================================== #
#  5. HKDF                                                             #
# ================================================================== #

class TestHKDF:
    def test_deterministic(self):
        from hybrid.kdf import hkdf_derive
        ikm = b"test input key material"
        k1 = hkdf_derive(ikm, info=b"test")
        k2 = hkdf_derive(ikm, info=b"test")
        assert k1 == k2, "HKDF doit être déterministe"

    def test_different_info_different_key(self):
        from hybrid.kdf import hkdf_derive
        ikm = b"same ikm"
        k1 = hkdf_derive(ikm, info=b"context-A")
        k2 = hkdf_derive(ikm, info=b"context-B")
        assert k1 != k2, "Contextes différents → clés différentes"

    def test_output_length(self):
        from hybrid.kdf import hkdf_derive
        for length in [16, 32, 64]:
            key = hkdf_derive(b"ikm", length=length)
            assert len(key) == length

    def test_derive_message_keys(self):
        from hybrid.kdf import derive_message_keys
        chain_key = os.urandom(32)
        next_ck, msg_key = derive_message_keys(chain_key)
        assert len(next_ck) == 32
        assert len(msg_key) == 32
        assert next_ck != msg_key
        assert next_ck != chain_key


# ================================================================== #
#  6. Échange hybride X25519 + ML-KEM                                  #
# ================================================================== #

class TestHybridKeyExchange:
    def test_shared_secret_matches(self):
        from hybrid.key_exchange import initiator_start, responder_finish
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
        from pq.kyber import generate_keypair

        # Générer de vraies clés X25519 pour Bob
        bob_x25519_priv = X25519PrivateKey.generate()
        bob_x25519_pub = bob_x25519_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        bob_x25519_priv_bytes = bob_x25519_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        bob_kyber_kp = generate_keypair()

        init_msg, alice_secret = initiator_start(
            bob_x25519_public=bob_x25519_pub,
            bob_kyber_public=bob_kyber_kp.public_key,
        )

        bob_secret = responder_finish(
            init_msg=init_msg,
            bob_x25519_private=bob_x25519_priv_bytes,
            bob_kyber_secret=bob_kyber_kp.secret_key,
        )

        assert alice_secret.shared_secret == bob_secret.shared_secret, \
            "Les deux parties doivent dériver le même secret"

    def test_shared_secret_is_32_bytes(self):
        from hybrid.key_exchange import initiator_start
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from pq.kyber import generate_keypair

        bob_x25519_pub = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        bob_kyber_kp = generate_keypair()
        _, secret = initiator_start(bob_x25519_pub, bob_kyber_kp.public_key)
        assert len(secret.shared_secret) == 32


# ================================================================== #
#  7. AES-256-GCM                                                      #
# ================================================================== #

class TestAES:
    def test_encrypt_decrypt(self):
        from symmetric.aes import generate_key, encrypt, decrypt
        key = generate_key()
        plaintext = b"Message secret AegisQuantum"
        ct = encrypt(plaintext, key)
        recovered = decrypt(ct, key)
        assert recovered == plaintext

    def test_with_associated_data(self):
        from symmetric.aes import generate_key, encrypt, decrypt
        key = generate_key()
        plaintext = b"Hello"
        aad = b"conversation:alice:bob"
        ct = encrypt(plaintext, key, associated_data=aad)
        recovered = decrypt(ct, key, associated_data=aad)
        assert recovered == plaintext

    def test_tampered_fails(self):
        from symmetric.aes import generate_key, encrypt, AESCiphertext
        from cryptography.exceptions import InvalidTag
        key = generate_key()
        ct = encrypt(b"secret", key)
        # Altérer le ciphertext
        tampered = AESCiphertext(nonce=ct.nonce, ciphertext=ct.ciphertext[:-1] + bytes([ct.ciphertext[-1] ^ 0xFF]))
        with pytest.raises(InvalidTag):
            from symmetric.aes import decrypt
            decrypt(tampered, key)

    def test_wrong_aad_fails(self):
        from symmetric.aes import generate_key, encrypt, decrypt
        from cryptography.exceptions import InvalidTag
        key = generate_key()
        ct = encrypt(b"secret", key, associated_data=b"aad-original")
        with pytest.raises(InvalidTag):
            decrypt(ct, key, associated_data=b"aad-modifie")

    def test_serialization(self):
        from symmetric.aes import generate_key, encrypt, AESCiphertext
        key = generate_key()
        ct = encrypt(b"test", key)
        raw = ct.to_bytes()
        restored = AESCiphertext.from_bytes(raw)
        assert restored.nonce == ct.nonce
        assert restored.ciphertext == ct.ciphertext


# ================================================================== #
#  8. ChaCha20-Poly1305                                                #
# ================================================================== #

class TestChaCha:
    def test_encrypt_decrypt(self):
        from symmetric.chacha import generate_key, encrypt, decrypt
        key = generate_key()
        plaintext = b"Message ChaCha20 AegisQuantum"
        ct = encrypt(plaintext, key)
        recovered = decrypt(ct, key)
        assert recovered == plaintext

    def test_with_associated_data(self):
        from symmetric.chacha import generate_key, encrypt, decrypt
        key = generate_key()
        ct = encrypt(b"Hello", key, associated_data=b"header:v1")
        recovered = decrypt(ct, key, associated_data=b"header:v1")
        assert recovered == b"Hello"

    def test_tampered_fails(self):
        from symmetric.chacha import generate_key, encrypt, ChaCiphertext
        from cryptography.exceptions import InvalidTag
        key = generate_key()
        ct = encrypt(b"secret", key)
        tampered = ChaCiphertext(nonce=ct.nonce, ciphertext=ct.ciphertext[:-1] + bytes([ct.ciphertext[-1] ^ 0xFF]))
        with pytest.raises(InvalidTag):
            from symmetric.chacha import decrypt
            decrypt(tampered, key)


# ================================================================== #
#  9. Chain Key Ratchet                                                #
# ================================================================== #

class TestChainState:
    def test_advance_produces_unique_keys(self):
        from ratchet.chain import ChainState
        state = ChainState(chain_key=os.urandom(32))
        keys = [state.advance().key for _ in range(10)]
        assert len(set(keys)) == 10, "Toutes les message keys doivent être uniques"

    def test_chain_key_changes_after_advance(self):
        from ratchet.chain import ChainState
        initial_ck = os.urandom(32)
        state = ChainState(chain_key=initial_ck)
        state.advance()
        assert state.chain_key != initial_ck, "La chain key doit avoir avancé"

    def test_serialization_roundtrip(self):
        from ratchet.chain import ChainState
        state = ChainState(chain_key=os.urandom(32))
        for _ in range(5):
            state.advance()
        restored = ChainState.from_dict(state.to_dict())
        assert restored.chain_key == state.chain_key
        assert restored.index == state.index


# ================================================================== #
#  10. Double Ratchet End-to-End                                       #
# ================================================================== #

class TestDoubleRatchet:
    def _make_session_pair(self):
        from ratchet.session import Session, RecipientBundle
        from pq.kyber import generate_keypair as kyber_keygen
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

        shared_secret = os.urandom(32)

        bob_x25519_priv = X25519PrivateKey.generate()
        bob_x25519_pub = bob_x25519_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        bob_x25519_priv_bytes = bob_x25519_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        bob_kyber_kp = kyber_keygen()

        alice_session = Session.create_as_sender(
            shared_secret=shared_secret,
            recipient=RecipientBundle(
                dh_public=bob_x25519_pub,
                kyber_public=bob_kyber_kp.public_key,
            )
        )
        bob_session = Session.create_as_receiver(
            shared_secret=shared_secret,
            dh_public=bob_x25519_pub,
            dh_private=bob_x25519_priv_bytes,
            kyber_public=bob_kyber_kp.public_key,
            kyber_secret=bob_kyber_kp.secret_key,
        )
        return alice_session, bob_session

    def test_basic_encrypt_decrypt(self):
        alice, bob = self._make_session_pair()
        msg = alice.encrypt("Bonjour Bob !")
        plaintext = bob.decrypt_text(msg)
        assert plaintext == "Bonjour Bob !"

    def test_multiple_messages(self):
        alice, bob = self._make_session_pair()
        messages = ["Message 1", "Message 2", "Message 3", "Message 4", "Message 5"]
        for text in messages:
            encrypted = alice.encrypt(text)
            recovered = bob.decrypt_text(encrypted)
            assert recovered == text

    def test_bidirectional(self):
        alice, bob = self._make_session_pair()
        # Alice → Bob
        msg1 = alice.encrypt("Alice dit bonjour")
        assert bob.decrypt_text(msg1) == "Alice dit bonjour"
        # Bob → Alice (après avoir reçu un message)
        msg2 = bob.encrypt("Bob répond")
        assert alice.decrypt_text(msg2) == "Bob répond"

    def test_session_serialization(self):
        alice, bob = self._make_session_pair()
        # Envoyer un message, sérialiser, restaurer, continuer
        msg1 = alice.encrypt("Premier message")
        bob.decrypt(msg1)

        serialized = alice.serialize()
        from ratchet.session import Session
        alice_restored = Session.from_json(serialized)

        msg2 = alice_restored.encrypt("Après restauration")
        plaintext = bob.decrypt_text(msg2)
        assert plaintext == "Après restauration"