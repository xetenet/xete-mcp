"""xete end-to-end crypto — byte-compatible with the concierge desktop client.

Contract (must match concierge/src-tauri/src/crypto/mod.rs):
  shared = x25519_DH(our_secret, their_public)
  key    = SHA256(shared)            # 32 bytes -> AES-256 key
  cipher = AES-256-GCM, 12-byte random nonce
  wire   = (base64(nonce), base64(ciphertext+tag))

Identity is a Solana ed25519 wallet (for auth). Message encryption uses a
SEPARATE x25519 keypair, registered to the server so other agents can look it
up and encrypt to you. This mirrors how concierge separates the two.
"""
from __future__ import annotations
import base64
import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class X25519Keypair:
    public_b64: str   # base64 of 32-byte public key (what you register/share)
    secret_bytes: bytes  # 32-byte secret (keep local)

    @property
    def public_bytes(self) -> bytes:
        return base64.b64decode(self.public_b64)


def generate_x25519() -> X25519Keypair:
    sk = X25519PrivateKey.generate()
    secret = sk.private_bytes_raw()
    public = sk.public_key().public_bytes_raw()
    return X25519Keypair(public_b64=base64.b64encode(public).decode(), secret_bytes=secret)


def x25519_from_secret(secret_bytes: bytes) -> X25519Keypair:
    sk = X25519PrivateKey.from_private_bytes(secret_bytes)
    public = sk.public_key().public_bytes_raw()
    return X25519Keypair(public_b64=base64.b64encode(public).decode(), secret_bytes=secret_bytes)


def _shared_key(our_secret: bytes, their_public: bytes) -> bytes:
    sk = X25519PrivateKey.from_private_bytes(our_secret)
    pk = X25519PublicKey.from_public_bytes(their_public)
    shared = sk.exchange(pk)               # 32-byte DH output
    return hashlib.sha256(shared).digest()  # -> AES-256 key (matches concierge)


def encrypt(our_secret: bytes, their_public: bytes, plaintext: str) -> tuple[str, str]:
    """Returns (nonce_b64, ciphertext_b64)."""
    key = _shared_key(our_secret, their_public)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce).decode(), base64.b64encode(ct).decode()


def decrypt(our_secret: bytes, their_public: bytes, nonce_b64: str, ct_b64: str) -> str:
    key = _shared_key(our_secret, their_public)
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ct_b64)
    pt = AESGCM(key).decrypt(nonce, ct, None)
    return pt.decode("utf-8")


def content_hash(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
