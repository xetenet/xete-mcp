"""SIGNING GUARD — what this agent's identity key is allowed to put a signature on.

The identity ed25519 key in ~/.xete/identity.json is used for three different jobs:
authenticating to the relay, signing Solana transactions, and deriving the x25519
messaging secret. One key, three jobs, means a signature obtained for one job is
usable for the others. Anything that will sign an arbitrary server-supplied string
with that key is therefore a signing ORACLE, and the two most valuable things to
extract from it are:

  1. a signature over a Solana transaction message  -> spends money;
  2. the signature over MESSAGING_KEY_DERIVATION_MESSAGE -> SHA256 of it IS the
     x25519 messaging secret, so whoever holds it decrypts every message this
     agent has ever received or sent.

This module is the choke point. Nothing in this package signs a server-supplied
byte string without going through `assert_signable` first, and every challenge
format the product actually uses is parsed against an exact template rather than
signed as opaque text.

FAIL CLOSED. A payload that cannot be positively identified is refused. That
deliberately means a relay that changes its challenge wording breaks logins until
this file is updated — which is the correct trade against a blind signing oracle
on the key that holds the money and the mail.

WHAT THIS DOES NOT CLOSE
The relay's /auth/challenge message is composed entirely by the relay and is not
bound to the client. `login()` sends a client nonce and this module will REQUIRE
it once the relay echoes it back (see `validate_relay_auth_challenge`), but today
the live relay ignores it, so the strongest available constraint is the exact
template + a fresh nonce + a timestamp inside a sane skew. See the report.
"""
from __future__ import annotations

import re
import time

# The canonical message every xete interface signs with the WALLET key to derive the
# shared messaging x25519 identity. It lives HERE, not next to the derivation, so the
# guard and the derivation can never drift apart: `client.MESSAGING_SIG_MESSAGE` is
# re-exported from this constant.
MESSAGING_KEY_DERIVATION_MESSAGE = b"xete messaging key derivation v1"

# Byte strings this key must NEVER sign on behalf of a caller, no matter who asks or
# how the request is dressed up. Substring containment, not equality: a payload that
# merely embeds one of these is refused too, because there is no legitimate challenge
# format that would.
RESERVED_PAYLOADS: tuple[bytes, ...] = (
    MESSAGING_KEY_DERIVATION_MESSAGE,
)

# A challenge is a short human-readable line-oriented string. Anything longer than
# this, or containing a byte outside printable ASCII + newline, is not a challenge.
# The byte restriction is load-bearing: a serialized Solana message begins with a
# header byte < 0x20 and carries raw 32-byte pubkeys, so it cannot survive this
# filter, which is what stops the auth endpoint from being used to sign a transaction.
MAX_CHALLENGE_BYTES = 512
_ALLOWED_BYTES = frozenset(range(0x20, 0x7F)) | {0x0A}

# Server nonces observed in production: 64 lowercase hex (relay) and 22 base58
# (permit server). Bounded and alphabet-restricted so a "nonce" cannot itself smuggle
# structure into the signed bytes.
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")

# Clock skew allowed on a challenge timestamp, in BOTH directions. The relay expires
# challenges at 300s against its own clock; this window is wider, and symmetric,
# because it is measured against the CLIENT's clock and the client's clock is not a
# security input. An asymmetric window (900s past, 300s future) meant a laptop resumed
# from sleep with a clock five minutes SLOW saw every relay timestamp as "in the
# future" and failed every login — a new hard failure on the already-published login
# path, where none of the four shipped tools works without login().
#
# Widening the future side costs nothing: a timestamp in the future cannot be a replay
# of a past challenge. What actually stops replay here is the nonce, which must match
# the nonce the server returned in a separate field, plus the relay's own 300s expiry
# against its own clock. This bound exists only to refuse a "challenge" pinned to a
# fixed moment, which is what a hand-crafted oracle payload looks like.
MAX_CHALLENGE_AGE_SECONDS = 900
MAX_CHALLENGE_FUTURE_SECONDS = 900


class RefusedToSign(RuntimeError):
    """The identity key was asked to sign something it must never sign.

    Raised BEFORE any signing happens: when this is raised, no signature exists.
    """


def _b(payload) -> bytes:
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, bytearray):
        return bytes(payload)
    if isinstance(payload, str):
        return payload.encode("utf-8")
    raise RefusedToSign(
        f"REFUSED TO SIGN: payload is {type(payload).__name__}, not bytes or str. "
        "Nothing was signed."
    )


def assert_signable(payload, *, context: str) -> bytes:
    """Raise RefusedToSign unless `payload` is a plausible challenge string.

    This is the last line of defence, applied to every byte string the identity key
    is asked to sign. It does not know what a valid challenge SAYS — the per-endpoint
    validators below do that — it knows what a challenge can never be.
    """
    data = _b(payload)

    if not data:
        raise RefusedToSign(
            f"REFUSED TO SIGN ({context}): the payload is empty. A signature over an "
            "empty message proves nothing and is refused. Nothing was signed."
        )
    if len(data) > MAX_CHALLENGE_BYTES:
        raise RefusedToSign(
            f"REFUSED TO SIGN ({context}): the payload is {len(data)} bytes, over the "
            f"{MAX_CHALLENGE_BYTES}-byte limit for a challenge. Nothing was signed."
        )
    for reserved in RESERVED_PAYLOADS:
        if reserved in data:
            raise RefusedToSign(
                f"REFUSED TO SIGN ({context}): the payload contains the reserved xete "
                f"domain constant {reserved!r}. The signature over that constant IS the "
                "x25519 messaging secret (its SHA256), so producing it on request would "
                "hand the caller every message this agent can read. It is never signed "
                "for anyone. Nothing was signed."
            )
    bad = sorted({byte for byte in data if byte not in _ALLOWED_BYTES})
    if bad:
        raise RefusedToSign(
            f"REFUSED TO SIGN ({context}): the payload contains non-printable byte(s) "
            f"{['0x%02x' % b for b in bad[:8]]}. A xete challenge is printable ASCII; "
            "raw binary here is what a serialized Solana transaction message looks "
            "like, and signing one would move money. Nothing was signed."
        )
    return data


class GuardedSigningKey:
    """A nacl SigningKey that refuses to sign anything `assert_signable` rejects.

    `Identity.signing_key` returns one of these, so every present and future caller
    that reaches for the identity key inherits the guard instead of having to
    remember it. The raw key is still reachable for the ONE legitimate use of the
    reserved constant — deriving the messaging secret — which calls nacl directly
    and never routes through here.
    """

    __slots__ = ("_key", "_context")

    def __init__(self, key, context: str = "identity key"):
        self._key = key
        self._context = context

    @property
    def verify_key(self):
        return self._key.verify_key

    def __bytes__(self) -> bytes:
        return bytes(self._key)

    def sign(self, message, encoder=None):
        assert_signable(message, context=self._context)
        if encoder is None:
            return self._key.sign(message)
        return self._key.sign(message, encoder)


# ── per-endpoint challenge templates ────────────────────────────────────────────────
# Each validator reconstructs the message it EXPECTS from independently known values
# (our own pubkey, the nonce the server also returned in a separate field, the current
# time) and compares. Nothing is signed on the strength of the server's prose.

def _check_nonce(nonce, *, where: str) -> str:
    if not isinstance(nonce, str) or not _NONCE_RE.match(nonce):
        raise RefusedToSign(
            f"REFUSED TO SIGN ({where}): the server's nonce {nonce!r} is not a plain "
            "8-128 character alphanumeric token. Nothing was signed."
        )
    return nonce


def _check_timestamp(raw: str, *, where: str, now: float | None = None) -> int:
    now = time.time() if now is None else now
    if not re.fullmatch(r"[0-9]{1,19}", raw):
        raise RefusedToSign(
            f"REFUSED TO SIGN ({where}): timestamp {raw!r} is not a unix timestamp. "
            "Nothing was signed."
        )
    ts = int(raw)
    skew_hint = (
        f"This is measured against THIS MACHINE's clock, which currently reads "
        f"{int(now)} — if the two disagree by more than the allowed window the cause "
        "is usually a wrong local clock (a resumed laptop, a container with no NTP), "
        "not an attack. Check the system time before assuming the server is at fault."
    )
    if ts < now - MAX_CHALLENGE_AGE_SECONDS:
        raise RefusedToSign(
            f"REFUSED TO SIGN ({where}): the challenge is dated {ts}, which is more "
            f"than {MAX_CHALLENGE_AGE_SECONDS}s in the past. A stale challenge is a "
            f"replayed one. {skew_hint} Nothing was signed."
        )
    if ts > now + MAX_CHALLENGE_FUTURE_SECONDS:
        raise RefusedToSign(
            f"REFUSED TO SIGN ({where}): the challenge is dated {ts}, which is more "
            f"than {MAX_CHALLENGE_FUTURE_SECONDS}s in the future. {skew_hint} "
            "Nothing was signed."
        )
    return ts


def _lines(message, *, where: str) -> list[str]:
    if not isinstance(message, str):
        raise RefusedToSign(
            f"REFUSED TO SIGN ({where}): the server sent no challenge message "
            f"(got {type(message).__name__}). Nothing was signed."
        )
    assert_signable(message, context=where)
    return message.split("\n")


def validate_relay_auth_challenge(message, nonce, *, client_nonce: str | None = None,
                                  now: float | None = None) -> dict:
    """Constrain the relay's /auth/challenge message before the identity key signs it.

    The live relay composes:

        XETE authentication
        Nonce: <nonce>
        Timestamp: <unix seconds>

    and nothing else. Requiring exactly that leaves the server no freedom beyond
    choosing a nonce and a timestamp, which is what turns a blind signing oracle into
    a signature over a value the server could have obtained anyway.

    FORWARD PATH TO A CLIENT-COMPOSED CHALLENGE: `login()` sends a client-generated
    nonce with the challenge request. The live relay ignores it, so an absent
    Client-Nonce line is accepted and reported as `client_nonce_bound: False`. The
    moment the relay starts echoing it as a fourth line, this function REQUIRES it to
    equal ours — the client half of the upgrade is already shipped and needs no
    further release. If the relay echoes a DIFFERENT value, that is refused today.
    """
    where = "relay auth challenge"
    lines = _lines(message, where=where)
    nonce = _check_nonce(nonce, where=where)

    if len(lines) not in (3, 4):
        raise RefusedToSign(
            f"REFUSED TO SIGN ({where}): expected a 3-line challenge, got {len(lines)} "
            f"line(s). This client only signs the exact xete authentication template; "
            "an unrecognised challenge is refused rather than signed blind. "
            f"Nothing was signed. Received: {message!r:.200}"
        )
    if lines[0] != "XETE authentication":
        raise RefusedToSign(
            f"REFUSED TO SIGN ({where}): first line is {lines[0]!r}, not "
            "'XETE authentication'. Nothing was signed."
        )
    if lines[1] != f"Nonce: {nonce}":
        raise RefusedToSign(
            f"REFUSED TO SIGN ({where}): the nonce inside the message does not match "
            f"the nonce field the server returned alongside it ({nonce!r}). The bytes "
            "signed must be bound to the nonce echoed back at login. Nothing was signed."
        )
    if not lines[2].startswith("Timestamp: "):
        raise RefusedToSign(
            f"REFUSED TO SIGN ({where}): third line is {lines[2]!r}, not a "
            "'Timestamp: <unix>' line. Nothing was signed."
        )
    ts = _check_timestamp(lines[2][len("Timestamp: "):], where=where, now=now)

    bound = False
    if len(lines) == 4:
        if lines[3] == "":
            # A trailing newline. Still refused — the signed bytes must be the exact
            # template — but it is a formatting difference, not a smuggled fourth line,
            # and saying "a fourth line '' that is not this client's own nonce" sends
            # whoever debugs it looking for a nonce bug that does not exist.
            raise RefusedToSign(
                f"REFUSED TO SIGN ({where}): the challenge is the correct three lines "
                "followed by a TRAILING NEWLINE, so the bytes are not the exact xete "
                "authentication template and are refused rather than signed. This is a "
                "server formatting change, not an attack signature: the relay must emit "
                "the three lines with no trailing newline. Nothing was signed."
            )
        if client_nonce and lines[3] == f"Client-Nonce: {client_nonce}":
            bound = True
        else:
            raise RefusedToSign(
                f"REFUSED TO SIGN ({where}): the challenge carries a fourth line "
                f"{lines[3]!r} that is not this client's own nonce. Nothing was signed."
            )

    return {"nonce": nonce, "timestamp": ts, "client_nonce_bound": bound}


def validate_alias_claim_challenge(message, nonce, pubkey: str, *,
                                   now: float | None = None) -> dict:
    """Constrain the permit server's /alias/claim/challenge message before signing it.

        xete alias claim
        pubkey:<our wallet>
        nonce:<nonce>
        ts:<unix seconds>

    Unlike the relay challenge this one names the wallet, so the signed bytes are
    bound to US as well as to the nonce.
    """
    where = "alias claim challenge"
    lines = _lines(message, where=where)
    nonce = _check_nonce(nonce, where=where)

    if len(lines) != 4:
        raise RefusedToSign(
            f"REFUSED TO SIGN ({where}): expected a 4-line challenge, got {len(lines)} "
            f"line(s). Nothing was signed. Received: {message!r:.200}"
        )
    if lines[0] != "xete alias claim":
        raise RefusedToSign(
            f"REFUSED TO SIGN ({where}): first line is {lines[0]!r}, not "
            "'xete alias claim'. Nothing was signed."
        )
    if lines[1] != f"pubkey:{pubkey}":
        raise RefusedToSign(
            f"REFUSED TO SIGN ({where}): the challenge is addressed to {lines[1]!r}, "
            f"not to this agent's wallet {pubkey}. Nothing was signed."
        )
    if lines[2] != f"nonce:{nonce}":
        raise RefusedToSign(
            f"REFUSED TO SIGN ({where}): the nonce inside the message does not match "
            f"the nonce field returned alongside it ({nonce!r}). Nothing was signed."
        )
    if not lines[3].startswith("ts:"):
        raise RefusedToSign(
            f"REFUSED TO SIGN ({where}): fourth line is {lines[3]!r}, not a "
            "'ts:<unix>' line. Nothing was signed."
        )
    ts = _check_timestamp(lines[3][len("ts:"):], where=where, now=now)
    return {"nonce": nonce, "timestamp": ts, "pubkey": pubkey}
