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
import os
import secrets
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

from .signguard import (
    MESSAGING_KEY_DERIVATION_MESSAGE,
    GuardedSigningKey,
    validate_relay_auth_challenge,
)


# ── identity / keystore ─────────────────────────────────────────────────────

# The canonical message EVERY xete interface signs with the WALLET key to derive
# the shared messaging x25519 identity. MUST stay byte-identical to House Elf
# (crypto/mod.rs::MESSAGING_SIG_MESSAGE) and the web inbox. A wallet SIGNATURE is
# the only input a browser wallet (Phantom signMessage) can reproduce — it never
# exposes the seed — so signing this, not hashing the seed, is what lets desktop,
# MCP, and browser all land on the SAME key. Changing it rotates everyone's key.
#
# It is DEFINED in signguard so the guard that refuses to sign it on request and the
# derivation that legitimately signs it can never drift apart.
MESSAGING_SIG_MESSAGE = MESSAGING_KEY_DERIVATION_MESSAGE


def derive_x25519_secret(ed_seed: bytes) -> bytes:
    """Derive the messaging x25519 secret from the wallet's 32-byte ed25519 seed:
        sig          = ed25519_sign(ed_seed, MESSAGING_SIG_MESSAGE)
        x25519_secret = SHA256(sig)

    ed25519 is deterministic (RFC 8032), so this is byte-stable and identical
    across House Elf (ed25519-dalek), here (nacl), and the browser (tweetnacl /
    Phantom). One wallet -> one messaging key in every interface.

    THIS IS THE ONLY PLACE THAT SIGNATURE IS EVER PRODUCED. It calls nacl directly,
    deliberately bypassing `Identity.signing_key`, because that property returns a
    GuardedSigningKey which refuses this exact constant: the signature is the
    messaging secret, so handing it to a caller hands over the whole mailbox. The
    derivation stays (browser wallets can only reproduce the key this way); what is
    removed is the ability to ask for the signature itself. The result never leaves
    this process — only SHA256 of it, as an x25519 secret, does.
    """
    sig = nacl.signing.SigningKey(ed_seed).sign(MESSAGING_SIG_MESSAGE).signature
    return hashlib.sha256(sig).digest()


def _b64d(value) -> bytes:
    """base64 -> bytes, or b"" for anything that is not decodable base64.

    Used only for OPTIONAL keystore fields. A corrupt legacy field must not brick a
    keystore whose primary key is derived and therefore always recoverable.
    """
    if not isinstance(value, str) or not value:
        return b""
    try:
        return base64.b64decode(value, validate=False)
    except Exception:
        return b""


@dataclass
class Identity:
    """A xete identity: a Solana ed25519 keypair (auth) + an x25519 keypair (E2E).

    The x25519 messaging secret used to SEND is always a pure function of `ed_seed`
    (see __post_init__), so the messaging key can never drift from the wallet and one
    wallet lands on the same key in House Elf, the browser, and here.

    LEGACY KEYS ARE KEPT, NOT DISCARDED. Every keystore written before that
    unification (xete-mcp 0.1.4 and earlier) carries a RANDOM `x_secret` with no
    relation to `ed_seed`, and every message already sitting in that agent's mailbox
    is encrypted to it. Re-deriving alone silently turns the whole pre-upgrade mailbox
    into ciphertext nobody can open. So the stored secret is retained here as a
    decryption-only key: `x_secret` is what we encrypt and publish with,
    `legacy_x_secrets` is tried per message when the derived key fails, and both are
    persisted (see `to_json` / `load_or_create_identity`). Nothing is ever SENT with a
    legacy key — the fallback is one-directional, so the unification still holds for
    everything new.
    """
    ed_seed: bytes                 # 32-byte ed25519 seed
    x_secret: bytes = b""          # derived from ed_seed in __post_init__ (never trusted from input)
    agent_id: str = ""             # assigned by the server on login
    # Decryption-only. Pre-unification messaging secrets this identity used to own,
    # newest first. Never used to encrypt, never published to the relay.
    legacy_x_secrets: list[bytes] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Enforce the invariant: the SENDING messaging key = f(wallet seed). An
        # x_secret passed in (e.g. the random one from a 0.1.4 keystore) does not get
        # to be the sending key — but it is not thrown away either, it is demoted to a
        # legacy decryption key so the mailbox it opens stays readable.
        supplied = bytes(self.x_secret or b"")
        self.x_secret = derive_x25519_secret(self.ed_seed)

        candidates = [supplied] + [bytes(s or b"") for s in (self.legacy_x_secrets or [])]
        kept: list[bytes] = []
        for sec in candidates:
            # 32 bytes or it is not an x25519 secret; equal to the derived key or it is
            # not legacy; already kept or it is a duplicate.
            if len(sec) != 32 or sec == self.x_secret or sec in kept:
                continue
            kept.append(sec)
        self.legacy_x_secrets = kept

    @property
    def decryption_secrets(self) -> list[bytes]:
        """Every secret this identity may try when OPENING a message, best first.

        The derived key is always first: it is the one the relay publishes and the one
        every message sent after the upgrade is encrypted to, so the legacy keys are
        only ever reached for genuinely old ciphertext.
        """
        return [self.x_secret, *self.legacy_x_secrets]

    @property
    def signing_key(self) -> GuardedSigningKey:
        """The identity key, wrapped so it cannot be used as a blind signing oracle.

        Callers use it exactly as before (`.sign(msg)`, `.verify_key`); the wrapper
        refuses payloads that are not plausible challenges — anything binary (a
        serialized transaction message), anything oversized, and above all the
        messaging-key derivation constant.
        """
        return GuardedSigningKey(nacl.signing.SigningKey(self.ed_seed),
                                 context="xete identity key")

    @property
    def pubkey_b58(self) -> str:
        return base58.b58encode(bytes(self.signing_key.verify_key)).decode()

    @property
    def x_public(self) -> bytes:
        return bytes(X25519Private(self.x_secret).public_key)

    @property
    def legacy_x_publics(self) -> list[bytes]:
        """Public halves of the legacy secrets — what the relay published BEFORE the
        upgrade, and therefore what senders who have not refreshed still encrypt to."""
        return [bytes(X25519Private(s).public_key) for s in self.legacy_x_secrets]

    def to_json(self) -> str:
        d = {
            "ed_seed": base64.b64encode(self.ed_seed).decode(),
            # Written for compatibility with readers that expect the field; it is the
            # DERIVED key, and __post_init__ re-derives it on load regardless.
            "x_secret": base64.b64encode(self.x_secret).decode(),
            "agent_id": self.agent_id,
        }
        if self.legacy_x_secrets:
            d["legacy_x_secrets"] = [base64.b64encode(s).decode() for s in self.legacy_x_secrets]
        return json.dumps(d)

    @classmethod
    def from_json(cls, s: str) -> "Identity":
        d = json.loads(s)
        # The stored x_secret is not trusted as the SENDING key — __post_init__
        # re-derives that from ed_seed — but it is read, because on a 0.1.4 keystore it
        # is the only copy of the key that opens the existing mailbox.
        return cls(
            ed_seed=base64.b64decode(d["ed_seed"]),
            x_secret=_b64d(d.get("x_secret")),
            agent_id=d.get("agent_id", ""),
            legacy_x_secrets=[b for b in (_b64d(v) for v in (d.get("legacy_x_secrets") or []))
                              if b],
        )

    @classmethod
    def generate(cls) -> "Identity":
        ed = nacl.signing.SigningKey.generate()
        return cls(ed_seed=bytes(ed))  # x_secret derived from ed_seed


LEGACY_KEYSTORE_BACKUP_SUFFIX = ".pre-derived-key.bak"


def _write_0600(path: Path, text: str) -> None:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def _write_0600_atomic(path: Path, text: str) -> None:
    """Write 0600 so the destination is either absent or complete, never partial.

    The temp name carries a random suffix rather than a fixed one. With a fixed name,
    two processes (or two threads) migrating the same keystore share the temp file: the
    second truncates it while the first is mid-write, and the first's `os.replace` then
    publishes a truncated prefix as the keystore. That interleave is narrow but the
    thing it corrupts is the account, so it gets a unique name instead of an argument
    about how unlikely it is.
    """
    tmp = path.with_name(f"{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        _write_0600(tmp, text)
        os.replace(str(tmp), str(path))
    except BaseException:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise


def _migrate_keystore(path: Path, raw: str, ident: Identity) -> None:
    """Rewrite a pre-unification keystore so its old messaging secret survives.

    On a 0.1.4 keystore the only copy of the pre-upgrade messaging key is the
    `x_secret` field, and the new format overwrites that field with the DERIVED key.
    Loading such a keystore and then writing it back — which `to_json` is used for —
    would destroy the one thing that can still open the existing mailbox. So the file
    is rewritten once, up front, into the two-field form.

    Deliberately narrow:
      * it only runs when there is actually a legacy secret to preserve, so keystores
        that never had one are never touched;
      * the original file is copied to `<name>.pre-derived-key.bak` first, and an
        existing backup is never overwritten — losing key material to a botched
        migration is the exact failure being prevented;
      * BOTH writes are atomic (temp file with a unique name, then rename), so neither
        the keystore nor the backup can be left as a truncated prefix by a crash. The
        backup guard is `exists()`, which only means anything because the write is
        atomic — a non-atomic backup could be left permanently empty and never retried,
        a safety net that silently isn't one;
      * every failure is swallowed. The in-memory Identity already carries both keys,
        so a read-only home directory costs durability, not access.
    """
    if not ident.legacy_x_secrets:
        return
    try:
        on_disk = json.loads(raw)
    except Exception:
        return
    want = json.loads(ident.to_json())
    if (on_disk.get("x_secret") == want.get("x_secret")
            and list(on_disk.get("legacy_x_secrets") or []) == want.get("legacy_x_secrets", [])):
        return
    try:
        backup = path.with_name(path.name + LEGACY_KEYSTORE_BACKUP_SUFFIX)
        if not backup.exists():
            _write_0600_atomic(backup, raw)
        _write_0600_atomic(path, ident.to_json())
    except Exception:
        pass  # durability is best-effort; the loaded identity is already correct


def load_or_create_identity(path: Path) -> Identity:
    if path.exists():
        raw = path.read_text()
        ident = Identity.from_json(raw)
        _migrate_keystore(path, raw, ident)
        return ident
    ident = Identity.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_0600(path, ident.to_json())  # 0600
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


def _why(e: BaseException) -> str:
    """A non-empty reason string for an exception.

    `cryptography`'s InvalidTag stringifies to the empty string, which is how a failed
    decrypt reached the agent as `"decrypt_error": ""` — a silent failure dressed as a
    reported one. The class name is always there, so lead with it.
    """
    text = str(e).strip()
    return f"{type(e).__name__}: {text}" if text else type(e).__name__


def decrypt_with_any(secrets: list[bytes], their_x_public: bytes,
                     nonce_b64: str, ct_b64: str) -> tuple[str, int]:
    """Decrypt with the first secret in `secrets` that works.

    Returns (plaintext, index) so the caller can tell the agent WHICH key opened it —
    index 0 is the current derived key, anything higher is a retained pre-upgrade key
    and worth reporting, because it means the sender is still using a stale published
    key for this agent.

    AES-GCM authenticates, so a wrong key cannot produce a wrong plaintext: it raises.
    Trying keys in turn is therefore a correctness fallback, not a guess.
    """
    if not secrets:
        raise RuntimeError("no messaging key available to decrypt with")
    last: BaseException | None = None
    for i, sec in enumerate(secrets):
        try:
            return decrypt(sec, their_x_public, nonce_b64, ct_b64), i
        except Exception as e:  # noqa: BLE001 - try the next key
            last = e
    extra = ("" if len(secrets) == 1
             else f" (tried the derived messaging key and {len(secrets) - 1} retained "
                  "pre-upgrade key(s))")
    raise RuntimeError(f"{_why(last)}{extra}") from last


# ── xete server client ──────────────────────────────────────────────────────

# Bearer tokens last 30 days server-side; reuse a cached one well inside that
# window so repeated CLI invocations don't re-run the challenge/verify handshake
# (burst logins from scripted agents trip the relay's per-IP 429 rate limit —
# the limit is correct, the client was the abuser).
TOKEN_CACHE_MAX_AGE_SECS = 7 * 24 * 3600


class MessagingKeyConflict(RuntimeError):
    """The relay publishes a DIFFERENT x25519 key for us than the one we encrypt with.

    Not a warning. While this holds, anything this agent sends is unreadable by the
    recipient — they look our key up from the relay, get the other one, and every
    decrypt fails — so a send that reports "sent" is reporting a delivery that cannot
    be opened. The send path refuses rather than produce that.
    """


@dataclass
class XeteClient:
    base_url: str
    identity: Identity
    token: str = ""
    session: requests.Session = field(default_factory=requests.Session)
    # Set by register_encryption_key(). Read by the tools so the state of the messaging
    # key is something an agent can SEE, instead of a swallowed exception.
    messaging_key_registered: bool = False
    # Only ever set on POSITIVE PROOF that the relay publishes a different key for us.
    # An unconfirmed 409 sets `messaging_key_unconfirmed` instead — see
    # `_published_key_verdict`. A latch that can be tripped by one flaky GET at startup
    # would block every send for the life of the process, which is its own outage.
    messaging_key_conflict: bool = False
    messaging_key_unconfirmed: bool = False
    messaging_key_error: str = ""

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
        """Authenticate to the relay.

        The identity key does NOT sign whatever string the relay sends. The challenge
        is parsed against the exact xete authentication template and refused if it is
        anything else — see signguard.validate_relay_auth_challenge for what that does
        and does not close.

        A client-generated nonce is sent with the challenge request. The live relay
        ignores unknown query parameters, so this is compatible today; the moment the
        relay echoes it back inside the message, the validator requires it to be ours
        and the challenge becomes half client-composed with no further client release.
        """
        if not force and self._restore_token():
            return self.identity.agent_id
        client_nonce = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
        r = self.session.get(self._url("/auth/challenge"),
                             params={"client_nonce": client_nonce}, timeout=15)
        r.raise_for_status()
        ch = r.json()
        # Refuses before any signature exists if the relay sent anything but the
        # template. Raises signguard.RefusedToSign.
        validate_relay_auth_challenge(ch.get("message"), ch.get("nonce"),
                                      client_nonce=client_nonce)
        sig = self.identity.signing_key.sign(ch["message"].encode("utf-8")).signature
        body = {
            "pubkey": self.identity.pubkey_b58,
            "nonce": ch["nonce"],
            "signature": base64.b64encode(sig).decode(),
        }
        # Invite gate (live): first-time registration of a NEW agent requires an invite
        # code. Existing agents log in without one. Pass XETE_INVITE_CODE if set.
        invite = os.environ.get("XETE_INVITE_CODE", "").strip()
        if invite:
            body["invite_code"] = invite
        r = self.session.post(self._url("/agent/login"), json=body, timeout=15)
        if r.status_code != 200:
            txt = r.text[:200]
            if r.status_code == 403 and "invite" in txt.lower():
                # The hint is ADDED to the relay's answer, never substituted for it.
                # Keying off the substring "invite" is a guess about what a 403 means;
                # "your invite was revoked" and "you need an invite" both match it and
                # only one is fixed by setting an env var. Replacing the server's text
                # with the guess threw away the only accurate half of the message.
                raise RuntimeError(
                    f"login failed: 403 {txt}\n"
                    "HINT (from this client, not the relay): registering a NEW xete "
                    "account requires an invite code — set the XETE_INVITE_CODE "
                    "environment variable and retry. Existing accounts log in without "
                    "one, so if this account already exists the relay's own text above "
                    "is the real reason."
                )
            raise RuntimeError(f"login failed: {r.status_code} {txt}")
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
        """Publish our x25519 key, and refuse to pretend a rejected publish succeeded.

        409 USED TO BE TREATED AS SUCCESS. That was sound only while the key never
        changed: re-registering the same key is genuinely idempotent. It stopped being
        sound the moment the messaging key started being derived from the wallet,
        because then a 409 is the relay saying "I already hold a DIFFERENT key for
        you" — and a relay holding a different key means nobody can read our mail.
        Shrugging at that produces a permanent, silent identity split.

        So 409 is now resolved rather than assumed: read back what the relay actually
        publishes for us. Same key -> genuinely idempotent, carry on. Different key ->
        MessagingKeyConflict, and the send path stops. COULD NOT TELL -> recorded as
        unconfirmed and re-checked before the next send, never latched. This runs
        exactly once per process (`_get_client`'s singleton), so latching a conflict on
        one transient GET failure at startup would block every send for the life of the
        server over a state that was fine all along.
        """
        self.ensure_auth()
        ours = self.identity.x_public.hex()
        r = self._req("POST", "/keys/register", json={"x25519_public_key": ours})

        if r.status_code in (200, 201):
            self._note_key_ok()
            return

        if r.status_code == 409:
            verdict, published = self._published_key_verdict()
            if verdict == "match":
                # The relay already holds exactly our key. The original idempotent case.
                self._note_key_ok()
                return
            self.messaging_key_registered = False
            if verdict == "differs":
                self.messaging_key_conflict = True
                self.messaging_key_unconfirmed = False
                self.messaging_key_error = (
                    "MESSAGING KEY CONFLICT: the relay refused to publish this agent's "
                    f"encryption key (HTTP 409) and publishes {published[:16]}… instead, "
                    f"while this client encrypts with {ours[:16]}…. Anyone messaging this "
                    "agent looks the relay's copy up, so sending is refused rather than "
                    "produce mail the recipient cannot open. The relay must rotate this "
                    "agent's registered x25519 key before messaging works again. Reading "
                    "the existing inbox is unaffected."
                )
                raise MessagingKeyConflict(self.messaging_key_error)
            self.messaging_key_conflict = False
            self.messaging_key_unconfirmed = True
            self.messaging_key_error = (
                "the relay refused to publish this agent's encryption key (HTTP 409) and "
                "its current copy could not be read back to check whether it matches. If "
                "it does not, mail sent from here would be unreadable — so the check is "
                "retried before the next send rather than assumed either way."
            )
            raise RuntimeError(self.messaging_key_error)

        self.messaging_key_registered = False
        self.messaging_key_conflict = False
        self.messaging_key_error = f"key register failed: {r.status_code} {r.text[:200]}"
        raise RuntimeError(self.messaging_key_error)

    def _note_key_ok(self) -> None:
        self.messaging_key_registered = True
        self.messaging_key_conflict = False
        self.messaging_key_unconfirmed = False
        self.messaging_key_error = ""

    def _published_key_verdict(self) -> tuple[str, str]:
        """What the relay publishes for US: ("match" | "differs" | "unknown", hex).

        "unknown" is a first-class answer and never collapses into "differs". Proving a
        conflict means reading a key that is not ours; failing to read anything proves
        nothing, and treating the two alike turns one network blip into a self-inflicted
        send outage that lasts until the server is restarted.
        """
        if not self.identity.agent_id:
            return "unknown", ""
        try:
            published = self.lookup_encryption_key(self.identity.agent_id).hex()
        except Exception:
            return "unknown", ""
        if not published:
            return "unknown", ""
        ours = self.identity.x_public.hex()
        return ("match" if published.lower() == ours.lower() else "differs"), published

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
        # A PROVEN key conflict means the recipient CANNOT open what we would encrypt.
        # Refuse here, at the client, so every caller is covered and no path can report
        # "sent" for a message that is undecryptable by construction.
        if self.messaging_key_conflict:
            raise MessagingKeyConflict(self.messaging_key_error or "messaging key conflict")
        self.ensure_auth()
        if self.messaging_key_unconfirmed:
            # Startup could not tell whether the relay's copy is ours. Ask again now,
            # rather than either blocking sends forever on an unproven suspicion or
            # ignoring a 409 that may be real. Only a positive "differs" stops the send.
            verdict, published = self._published_key_verdict()
            if verdict == "match":
                self._note_key_ok()
            elif verdict == "differs":
                self.messaging_key_conflict = True
                self.messaging_key_unconfirmed = False
                self.messaging_key_error = (
                    "MESSAGING KEY CONFLICT: the relay publishes "
                    f"{published[:16]}… for this agent, not the "
                    f"{self.identity.x_public.hex()[:16]}… this client encrypts with. The "
                    "recipient would look up the relay's copy and fail to decrypt, so "
                    "sending is refused. Reading the inbox is unaffected."
                )
                raise MessagingKeyConflict(self.messaging_key_error)
            # "unknown" again: still no proof of harm. Send, and keep the warning.
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
                # Per message, not per mailbox: a mailbox upgraded from 0.1.4 holds old
                # messages encrypted to the retained key and new ones encrypted to the
                # derived key, interleaved. Whichever opens this one wins.
                text, used = decrypt_with_any(
                    self.identity.decryption_secrets, their_x, nonce_b64, ct_b64)
                entry["text"] = text
                if used > 0:
                    entry["decrypted_with_legacy_key"] = True
                    entry["note"] = (
                        "opened with a messaging key retained from before this agent's "
                        "keystore was upgraded. Replies are encrypted with the current "
                        "key; if the sender cannot read them, they are looking up a "
                        "stale key for this agent.")
            except Exception as e:
                entry["text"] = None
                entry["decrypt_error"] = _why(e)[:200]
            out.append(entry)
        return out
