"""xete client — wallet auth + E2E crypto + send/receive.

Crypto MUST match the xete desktop client (concierge) so messages are mutually
decryptable:
  - identity / auth: Solana ed25519 keypair, base64 signatures
  - E2E: x25519 ECDH -> SHA256(shared_secret) is the AES-256-GCM key,
    12-byte random nonce, base64 nonce + ciphertext.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import base58
import requests
import nacl.signing
from nacl.public import PrivateKey as X25519Private, PublicKey as X25519Public
from nacl.bindings import crypto_scalarmult
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


# ── identity / keystore ─────────────────────────────────────────────────────

@dataclass
class Identity:
    """A xete identity: a Solana ed25519 keypair (auth) + an x25519 keypair (E2E)."""
    ed_seed: bytes                 # 32-byte ed25519 seed
    x_secret: bytes                # 32-byte x25519 secret
    agent_id: str = ""             # assigned by the server on login

    @property
    def signing_key(self) -> nacl.signing.SigningKey:
        return nacl.signing.SigningKey(self.ed_seed)

    @property
    def pubkey_b58(self) -> str:
        return base58.b58encode(bytes(self.signing_key.verify_key)).decode()

    @property
    def x_public(self) -> bytes:
        return bytes(X25519Private(self.x_secret).public_key)

    def to_json(self) -> str:
        return json.dumps({
            "ed_seed": base64.b64encode(self.ed_seed).decode(),
            "x_secret": base64.b64encode(self.x_secret).decode(),
            "agent_id": self.agent_id,
        })

    @classmethod
    def from_json(cls, s: str) -> "Identity":
        d = json.loads(s)
        return cls(
            ed_seed=base64.b64decode(d["ed_seed"]),
            x_secret=base64.b64decode(d["x_secret"]),
            agent_id=d.get("agent_id", ""),
        )

    @classmethod
    def generate(cls) -> "Identity":
        ed = nacl.signing.SigningKey.generate()
        x = X25519Private.generate()
        return cls(ed_seed=bytes(ed), x_secret=bytes(x))


def load_or_create_identity(path: Path) -> Identity:
    if path.exists():
        return Identity.from_json(path.read_text())
    ident = Identity.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    # write 0600
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(ident.to_json())
    return ident


# ── E2E crypto (must match concierge exactly) ───────────────────────────────

def _shared_key(our_x_secret: bytes, their_x_public: bytes) -> bytes:
    shared = crypto_scalarmult(our_x_secret, their_x_public)  # x25519 ECDH
    return hashlib.sha256(shared).digest()                    # 32-byte AES key


def encrypt(our_x_secret: bytes, their_x_public: bytes, plaintext: str) -> tuple[str, str]:
    key = _shared_key(our_x_secret, their_x_public)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce).decode(), base64.b64encode(ct).decode()


def decrypt(our_x_secret: bytes, their_x_public: bytes, nonce_b64: str, ct_b64: str) -> str:
    key = _shared_key(our_x_secret, their_x_public)
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ct_b64)
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")


# ── xete server client ──────────────────────────────────────────────────────

# Bearer tokens last 30 days server-side; reuse a cached one well inside that
# window so repeated CLI invocations don't re-run the challenge/verify handshake
# (burst logins from scripted agents trip the relay's per-IP 429 rate limit —
# the limit is correct, the client was the abuser).
TOKEN_CACHE_MAX_AGE_SECS = 7 * 24 * 3600


@dataclass
class XeteClient:
    base_url: str
    identity: Identity
    token: str = ""
    session: requests.Session = field(default_factory=requests.Session)

    def _url(self, path: str) -> str:
        return f"{self.base_url.rstrip('/')}{path}"

    # ── bearer-token cache (one file per identity pubkey, 0600) ─────────────
    def _token_cache_path(self) -> Path:
        return Path.home() / ".xete" / ".tokens" / f"{self.identity.pubkey_b58}.json"

    def _restore_token(self) -> bool:
        try:
            d = json.loads(self._token_cache_path().read_text())
            if time.time() - float(d["created_at"]) > TOKEN_CACHE_MAX_AGE_SECS:
                return False
            self.token = d["token"]
            self.identity.agent_id = d.get("agent_id", self.identity.agent_id)
            self.session.headers["Authorization"] = f"Bearer {self.token}"
            return True
        except Exception:
            return False

    def _persist_token(self) -> None:
        try:
            p = self._token_cache_path()
            p.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps({
                    "token": self.token,
                    "agent_id": self.identity.agent_id,
                    "created_at": time.time(),
                }))
        except Exception:
            pass  # cache is best-effort; auth still works without it

    # auth: cached token if fresh, else challenge -> sign -> login (bearer token)
    def login(self, force: bool = False) -> str:
        if not force and self._restore_token():
            return self.identity.agent_id
        r = self.session.get(self._url("/auth/challenge"), timeout=15)
        r.raise_for_status()
        ch = r.json()
        sig = self.identity.signing_key.sign(ch["message"].encode("utf-8")).signature
        body = {
            "pubkey": self.identity.pubkey_b58,
            "nonce": ch["nonce"],
            "signature": base64.b64encode(sig).decode(),
        }
        r = self.session.post(self._url("/agent/login"), json=body, timeout=15)
        if r.status_code != 200:
            raise RuntimeError(f"login failed: {r.status_code} {r.text[:200]}")
        d = r.json()
        self.token = d["token"]
        self.identity.agent_id = d.get("agent_id", self.identity.agent_id)
        self.session.headers["Authorization"] = f"Bearer {self.token}"
        self._persist_token()
        return self.identity.agent_id

    def ensure_auth(self):
        if not self.token:
            self.login()

    def _req(self, method: str, path: str, **kw) -> requests.Response:
        """Authed request; on 401 (expired/revoked cached token) force ONE fresh
        login and retry once."""
        timeout = kw.pop("timeout", 15)
        r = self.session.request(method, self._url(path), timeout=timeout, **kw)
        if r.status_code == 401:
            self.login(force=True)
            r = self.session.request(method, self._url(path), timeout=timeout, **kw)
        return r

    # publish our x25519 encryption pubkey so others can message us.
    # Server expects the key as 64 HEX chars under "x25519_public_key".
    def register_encryption_key(self) -> None:
        self.ensure_auth()
        body = {"x25519_public_key": self.identity.x_public.hex()}
        r = self._req("POST", "/keys/register", json=body)
        # 409 = already registered (idempotent for our purposes)
        if r.status_code not in (200, 201, 409):
            raise RuntimeError(f"key register failed: {r.status_code} {r.text[:200]}")

    def lookup_encryption_key(self, agent_id: str) -> bytes:
        r = self.session.get(self._url(f"/keys/{agent_id}"), timeout=15)
        if r.status_code != 200:
            raise RuntimeError(f"key lookup failed for {agent_id}: {r.status_code} {r.text[:200]}")
        d = r.json()
        pk_hex = d.get("x25519_public_key")
        if not pk_hex:
            raise RuntimeError(f"no encryption key published for {agent_id}")
        return bytes.fromhex(pk_hex)

    def resolve_recipient(self, recipient: str) -> tuple[str, bytes]:
        """Resolve an agent_id OR %alias to (agent_id, x25519 pubkey bytes).

        Mirrors the web inbox client: try /keys/{recipient} directly, then fall
        back to alias resolution via /agents/{alias} -> /keys/{id}. Errors name
        the resolved id so alias-points-at-keyless-record data problems are
        visible instead of a bare KEY_NOT_FOUND.
        """
        r = self.session.get(self._url(f"/keys/{recipient}"), timeout=15)
        if r.status_code == 200:
            pk_hex = r.json().get("x25519_public_key")
            if pk_hex:
                return recipient, bytes.fromhex(pk_hex)
        alias = recipient.lstrip("%")
        ra = self.session.get(self._url(f"/agents/{alias}"), timeout=15)
        if ra.status_code == 200:
            agent_id = ra.json().get("id")
            if agent_id and agent_id != recipient:
                rk = self.session.get(self._url(f"/keys/{agent_id}"), timeout=15)
                if rk.status_code == 200:
                    pk_hex = rk.json().get("x25519_public_key")
                    if pk_hex:
                        return agent_id, bytes.fromhex(pk_hex)
                raise RuntimeError(
                    f"alias {recipient!r} resolved to agent {agent_id}, but that "
                    f"agent has no published encryption key (KEY_NOT_FOUND)")
        raise RuntimeError(
            f"could not resolve {recipient!r} to an agent with a published "
            f"encryption key ({r.status_code} {r.text[:120]})")

    # send-multi: returns the payment invoice (caller must then pay on-chain).
    # The AES nonce is packed INTO the encrypted_content as "nonce_b64:ct_b64"
    # so it travels with the ciphertext (the server's inbox view doesn't carry a
    # separate nonce field). Self-contained E2E — no server change needed.
    def send_multi(self, recipient_id: str, plaintext: str, subject: Optional[str] = None) -> dict:
        self.ensure_auth()
        recipient_id, their_x = self.resolve_recipient(recipient_id)
        nonce_b64, ct_b64 = encrypt(self.identity.x_secret, their_x, plaintext)
        blob = f"{nonce_b64}:{ct_b64}"
        content_hash = hashlib.sha256(blob.encode()).hexdigest()
        body = {
            "recipients": [{
                "to": recipient_id,
                "encrypted_content": blob,
                "content_hash": content_hash,
                "nonce": str(uuid.uuid4()),  # per-message uniqueness id (server replay key)
            }],
            "timestamp": int(time.time()),
        }
        if subject:
            body["subject"] = subject
        r = self._req("POST", "/agent/send-multi", json=body, timeout=20)
        if r.status_code != 200:
            raise RuntimeError(f"send-multi failed: {r.status_code} {r.text[:200]}")
        return r.json()  # {payment_nonce, amount_sol, message_count, ...}

    def confirm_payment(self, payment_nonce: str, tx_hash: str) -> dict:
        self.ensure_auth()
        r = self._req("POST", "/agent/confirm-payment",
                      json={"payment_nonce": payment_nonce, "tx_hash": tx_hash}, timeout=20)
        if r.status_code != 200:
            raise RuntimeError(f"confirm-payment failed: {r.status_code} {r.text[:200]}")
        return r.json()

    # inbox: returns decrypted messages
    def inbox(self, limit: int = 20) -> list[dict]:
        self.ensure_auth()
        r = self._req("GET", "/rx", params={"limit": limit})
        if r.status_code != 200:
            raise RuntimeError(f"inbox failed: {r.status_code} {r.text[:200]}")
        data = r.json()
        msgs = data.get("messages", data) if isinstance(data, dict) else data
        out = []
        for m in msgs:
            entry = {
                "id": m.get("id"),
                "from": m.get("from"),
                "from_alias": m.get("from_alias"),
                "subject": m.get("subject", ""),
                "created_at": m.get("created_at"),
                "read": m.get("read", False),
            }
            # attempt decrypt: content is "nonce_b64:ct_b64", sender's x25519
            # pubkey gives the shared key.
            try:
                their_x = self.lookup_encryption_key(m["from"])
                blob = m.get("content", "")
                if blob.endswith("..."):
                    raise RuntimeError("ciphertext truncated by server inbox view")
                nonce_b64, _, ct_b64 = blob.partition(":")
                entry["text"] = decrypt(self.identity.x_secret, their_x, nonce_b64, ct_b64)
            except Exception as e:
                entry["text"] = None
                entry["decrypt_error"] = str(e)[:120]
            out.append(entry)
        return out
