from __future__ import annotations
from dataclasses import dataclass, field
import os
import base64
import json
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from pq.kyber import generate_keypair as kyber_keygen, encapsulate as kyber_encap, decapsulate as kyber_decap
from hybrid.kdf import hkdf_derive
from symmetric.chacha import encrypt as chacha_encrypt, decrypt as chacha_decrypt, ChaCiphertext
from ratchet.chain import ChainState

ROOT_KEY_INFO = b"AegisQuantum-v1-root-key"

def _derive_root_and_chain(root_key, dh_output):
    from hybrid.kdf import hkdf_derive
    key_material = hkdf_derive(dh_output, length=64, info=ROOT_KEY_INFO, salt=root_key)
    return key_material[:32], key_material[32:]

@dataclass
class RatchetHeader:
    dh_ratchet_public: bytes
    kyber_ciphertext: bytes | None
    message_index: int
    prev_chain_length: int
    def to_bytes(self):
        kyber_ct = self.kyber_ciphertext or b""
        return self.dh_ratchet_public + len(kyber_ct).to_bytes(4,"big") + kyber_ct + self.message_index.to_bytes(4,"big") + self.prev_chain_length.to_bytes(4,"big")

@dataclass
class EncryptedMessage:
    header: RatchetHeader
    ciphertext: bytes

@dataclass
class RatchetState:
    root_key: bytes
    dh_self_public: bytes
    dh_self_private: bytes
    dh_remote_public: bytes | None
    kyber_self_public: bytes
    kyber_self_secret: bytes
    kyber_remote_public: bytes | None
    sending_chain: ChainState | None = None
    receiving_chain: ChainState | None = None
    prev_sending_chain_length: int = 0
    def to_dict(self):
        b64 = lambda b: base64.b64encode(b).decode() if b else None
        return {"root_key":b64(self.root_key),"dh_self_public":b64(self.dh_self_public),"dh_self_private":b64(self.dh_self_private),"dh_remote_public":b64(self.dh_remote_public),"kyber_self_public":b64(self.kyber_self_public),"kyber_self_secret":b64(self.kyber_self_secret),"kyber_remote_public":b64(self.kyber_remote_public),"sending_chain":self.sending_chain.to_dict() if self.sending_chain else None,"receiving_chain":self.receiving_chain.to_dict() if self.receiving_chain else None,"prev_sending_chain_length":self.prev_sending_chain_length}
    def to_json(self): return json.dumps(self.to_dict(), indent=2)
    @classmethod
    def from_dict(cls, data):
        b64d = lambda s: base64.b64decode(s) if s else None
        return cls(root_key=base64.b64decode(data["root_key"]),dh_self_public=base64.b64decode(data["dh_self_public"]),dh_self_private=base64.b64decode(data["dh_self_private"]),dh_remote_public=b64d(data["dh_remote_public"]),kyber_self_public=base64.b64decode(data["kyber_self_public"]),kyber_self_secret=base64.b64decode(data["kyber_self_secret"]),kyber_remote_public=b64d(data["kyber_remote_public"]),sending_chain=ChainState.from_dict(data["sending_chain"]) if data.get("sending_chain") else None,receiving_chain=ChainState.from_dict(data["receiving_chain"]) if data.get("receiving_chain") else None,prev_sending_chain_length=data.get("prev_sending_chain_length",0))

def initialize_sender(shared_secret, recipient_dh_public, recipient_kyber_public):
    dh_priv = X25519PrivateKey.generate()
    dh_pub = dh_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    dh_priv_bytes = dh_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    kyber_kp = kyber_keygen()
    dh_output = dh_priv.exchange(X25519PublicKey.from_public_bytes(recipient_dh_public))
    kyber_enc = kyber_encap(recipient_kyber_public)
    root_key, chain_key = _derive_root_and_chain(shared_secret, dh_output + kyber_enc.shared_secret)
    return RatchetState(root_key=root_key,dh_self_public=dh_pub,dh_self_private=dh_priv_bytes,dh_remote_public=recipient_dh_public,kyber_self_public=kyber_kp.public_key,kyber_self_secret=kyber_kp.secret_key,kyber_remote_public=recipient_kyber_public,sending_chain=ChainState(chain_key=chain_key),receiving_chain=None)

def initialize_receiver(shared_secret, dh_self_public, dh_self_private, kyber_self_public, kyber_self_secret):
    kyber_kp = kyber_keygen()
    return RatchetState(root_key=shared_secret,dh_self_public=dh_self_public,dh_self_private=dh_self_private,dh_remote_public=None,kyber_self_public=kyber_kp.public_key,kyber_self_secret=kyber_self_secret,kyber_remote_public=None,sending_chain=None,receiving_chain=None)

def ratchet_encrypt(state, plaintext):
    if state.sending_chain is None: raise ValueError("Sending chain non initialisée")
    kyber_ct = kyber_encap(state.kyber_remote_public).ciphertext if state.kyber_remote_public else None
    header = RatchetHeader(dh_ratchet_public=state.dh_self_public,kyber_ciphertext=kyber_ct,message_index=state.sending_chain.index,prev_chain_length=state.prev_sending_chain_length)
    msg_key = state.sending_chain.advance()
    cha_ct = chacha_encrypt(plaintext, msg_key.key)
    return EncryptedMessage(header=header, ciphertext=cha_ct.to_bytes()), state

def ratchet_decrypt(state, msg):
    header = msg.header
    if state.dh_remote_public is None or header.dh_ratchet_public != state.dh_remote_public:
        state = _perform_dh_ratchet_step(state, header)
    if state.receiving_chain is None: raise ValueError("Receiving chain non initialisée")
    msg_key = state.receiving_chain.advance_to(header.message_index)
    plaintext = chacha_decrypt(ChaCiphertext.from_bytes(msg.ciphertext), msg_key.key)
    return plaintext, state

def _perform_dh_ratchet_step(state, header):
    dh_output = X25519PrivateKey.from_private_bytes(state.dh_self_private).exchange(X25519PublicKey.from_public_bytes(header.dh_ratchet_public))
    kyber_ss = kyber_decap(header.kyber_ciphertext, state.kyber_self_secret) if header.kyber_ciphertext else b"\x00"*32
    root_key, recv_chain_key = _derive_root_and_chain(state.root_key, dh_output + kyber_ss)
    new_dh_priv = X25519PrivateKey.generate()
    new_dh_pub = new_dh_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    new_dh_priv_bytes = new_dh_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    new_kyber_kp = kyber_keygen()
    new_dh_output = new_dh_priv.exchange(X25519PublicKey.from_public_bytes(header.dh_ratchet_public))
    new_root_key, send_chain_key = _derive_root_and_chain(root_key, new_dh_output)
    prev_length = state.sending_chain.index if state.sending_chain else 0
    return RatchetState(root_key=new_root_key,dh_self_public=new_dh_pub,dh_self_private=new_dh_priv_bytes,dh_remote_public=header.dh_ratchet_public,kyber_self_public=new_kyber_kp.public_key,kyber_self_secret=new_kyber_kp.secret_key,kyber_remote_public=state.kyber_remote_public,sending_chain=ChainState(chain_key=send_chain_key),receiving_chain=ChainState(chain_key=recv_chain_key),prev_sending_chain_length=prev_length)
