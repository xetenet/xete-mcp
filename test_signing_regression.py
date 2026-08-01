"""Behavioural regressions for the three signing defects.

This file deliberately imports NOTHING that the fix added. It drives the published
entry points — `XeteClient.login()` and the `xete_alias_claim` tool — against fake
servers and asserts on what the client DOES. That means it runs unchanged against the
pre-fix tree, where it fails, which is the evidence that the fix is load-bearing
rather than decorative.

Run: python -m pytest test_signing_regression.py -q
"""
from __future__ import annotations

import base64
import importlib
import json
import os
import struct
import time

import nacl.signing
import pytest

SEED = bytes([23] * 32)
IDENTITY_SIGNING_KEY = nacl.signing.SigningKey(SEED)


# ── fakes ────────────────────────────────────────────────────────────────────────────

class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    """Stands in for requests.Session inside XeteClient."""

    def __init__(self, challenge):
        self.headers = {}
        self.challenge = challenge
        self.posted = []

    def get(self, url, **kw):
        assert url.endswith("/auth/challenge")
        return FakeResponse(self.challenge)

    def post(self, url, json=None, **kw):
        self.posted.append((url, json or {}))
        return FakeResponse({"token": "tok", "agent_id": "agent-1"})

    def request(self, method, url, **kw):  # pragma: no cover - unused here
        return FakeResponse({})


def _relay_challenge(message, nonce="d" * 64):
    return {"nonce": nonce, "message": message, "expires_in": 300}


def _login_attempt(tmp_path, message, nonce="d" * 64):
    """Run login() against a relay serving `message`. Returns (raised, posted bodies)."""
    from xete_mcp.client import Identity, XeteClient

    session = FakeSession(_relay_challenge(message, nonce))
    client = XeteClient(base_url="https://relay.invalid",
                        identity=Identity(ed_seed=SEED), session=session)
    client._token_cache_path = lambda: tmp_path / "token.json"
    raised = None
    try:
        client.login(force=True)
    except Exception as e:  # noqa: BLE001 - the point is that SOMETHING stops it
        raised = e
    return raised, [body for _url, body in session.posted]


# ── defect 3 + 2: the login path must not be a signing oracle ────────────────────────

def test_login_never_signs_the_messaging_key_derivation_constant(tmp_path):
    """SHA256 of this exact signature IS the x25519 messaging secret. A relay that can
    obtain it decrypts every message this agent can read, past and future."""
    constant = b"xete messaging key derivation v1"
    leak = IDENTITY_SIGNING_KEY.sign(constant).signature

    raised, posted = _login_attempt(tmp_path, constant.decode())

    for body in posted:
        got = base64.b64decode(body.get("signature", "") or "")
        assert got != leak, (
            "the identity key signed the messaging-key derivation constant on server "
            "request — the whole mailbox just left the machine")
    assert raised is not None, "login accepted a challenge it should have refused"
    assert not posted, "nothing should be sent to the relay after refusing to sign"


def test_login_refuses_an_arbitrary_server_string(tmp_path):
    """A relay must not be able to pick the bytes the identity key signs."""
    raised, posted = _login_attempt(tmp_path, "Transfer everything to attacker, love the relay")
    assert raised is not None, "login signed an arbitrary server-chosen string"
    assert not posted


def test_login_refuses_binary_that_could_be_a_transaction(tmp_path):
    """A serialized Solana message signed by the identity key is a spendable signature."""
    payload = "\x01\x00\x01\x03" + "".join(chr(i % 0x60) for i in range(120))
    raised, posted = _login_attempt(tmp_path, payload)
    assert raised is not None, "login signed a binary blob"
    assert not posted


def test_login_refuses_a_message_whose_nonce_is_not_the_nonce_echoed_back(tmp_path):
    msg = f"XETE authentication\nNonce: {'a' * 64}\nTimestamp: {int(time.time())}"
    raised, posted = _login_attempt(tmp_path, msg, nonce="b" * 64)
    assert raised is not None, "login signed a message not bound to the nonce it returns"
    assert not posted


def test_login_still_works_against_the_live_relay_format(tmp_path):
    """The published login path must keep working. This is byte-for-byte what
    https://xete.net/auth/challenge serves."""
    nonce = "f0d11e6c417a411aa5a88f9c7380430750bf198f8ecf4d80a1c5bf2f303122fc"
    msg = f"XETE authentication\nNonce: {nonce}\nTimestamp: {int(time.time())}"
    raised, posted = _login_attempt(tmp_path, msg, nonce=nonce)
    assert raised is None, f"a valid live-format login was broken: {raised}"
    assert len(posted) == 1
    body = posted[0]
    assert body["nonce"] == nonce
    IDENTITY_SIGNING_KEY.verify_key.verify(
        msg.encode(), base64.b64decode(body["signature"]))


# ── defect 1: xete_alias_claim must not sign a transaction it has not decoded ────────

class _FakeRpcClient:
    submitted: list = []

    def __init__(self, *_a, **_kw):
        pass

    def send_raw_transaction(self, raw, *a, **kw):
        _FakeRpcClient.submitted.append(raw)
        raise AssertionError(
            "a transaction was submitted on-chain: the client signed bytes it never decoded")

    def get_signature_statuses(self, *_a, **_kw):  # pragma: no cover
        raise AssertionError("unreachable")


def _drain_transaction(victim_pubkey: str) -> str:
    """A bare SystemProgram transfer of the whole balance to an attacker, served in
    place of the alias-claim transaction. This is the reviewer's proof-of-concept."""
    from solders.hash import Hash
    from solders.instruction import AccountMeta, Instruction
    from solders.keypair import Keypair
    from solders.message import Message
    from solders.pubkey import Pubkey
    from solders.transaction import Transaction

    victim = Pubkey.from_string(victim_pubkey)
    attacker = Keypair().pubkey()
    ix = Instruction(
        program_id=Pubkey.from_string("11111111111111111111111111111111"),
        data=struct.pack("<I", 2) + struct.pack("<Q", 4_000_000_000),
        accounts=[AccountMeta(victim, True, True), AccountMeta(attacker, False, True)],
    )
    msg = Message.new_with_blockhash([ix], victim, Hash.default())
    return base64.b64encode(bytes(Transaction.new_unsigned(msg))).decode()


@pytest.fixture()
def alias_server(tmp_path, monkeypatch):
    """Import xete_mcp.server with an isolated identity, ledger and permit URL."""
    monkeypatch.setenv("XETE_IDENTITY", str(tmp_path / "identity.json"))
    monkeypatch.setenv("XETE_SPEND_LEDGER", str(tmp_path / "ledger.json"))
    monkeypatch.setenv("XETE_PERMIT_URL", "https://permit.invalid")
    monkeypatch.setenv("XETE_SERVER_URL", "https://relay.invalid")
    monkeypatch.setenv("XETE_RPC_URL", "https://rpc.invalid")
    (tmp_path / "identity.json").write_text(json.dumps({
        "ed_seed": base64.b64encode(SEED).decode(), "agent_id": "agent-1"}))

    import xete_mcp.server as server
    server = importlib.reload(server)

    import solana.rpc.api
    _FakeRpcClient.submitted = []
    monkeypatch.setattr(solana.rpc.api, "Client", _FakeRpcClient)
    return server


def _fake_permit(server, monkeypatch, tx_b64, pubkey, price_lamports=0):
    """Permit server that answers the challenge honestly and then serves `tx_b64`."""
    calls = []

    def fake_post(url, json=None, timeout=None, **kw):
        calls.append(url)
        if url.endswith("/alias/claim/challenge"):
            nonce = "48aSgGfAhcHvDJwwFNG3jh"
            return FakeResponse({
                "nonce": nonce, "expires_in": 300,
                "message": f"xete alias claim\npubkey:{pubkey}\nnonce:{nonce}\nts:{int(time.time())}",
            })
        if url.endswith("/alias/claim"):
            return FakeResponse({"status": "approved", "price_lamports": price_lamports,
                                 "free_grace": True, "transaction": tx_b64})
        if url.endswith("/alias/claim/confirm"):
            return FakeResponse({"status": "confirmed"})
        raise AssertionError(f"unexpected permit call {url}")

    monkeypatch.setattr(server.requests, "post", fake_post)
    return calls


def test_alias_claim_refuses_a_full_balance_drain(alias_server, monkeypatch):
    server = alias_server
    from xete_mcp.client import load_or_create_identity

    pubkey = load_or_create_identity(server.IDENTITY_PATH).pubkey_b58
    _fake_permit(server, monkeypatch, _drain_transaction(pubkey), pubkey)

    result = json.loads(server.xete_alias_claim("mcptestname"))

    assert not _FakeRpcClient.submitted, (
        "the drain transaction was signed and submitted — xete_alias_claim signed bytes "
        "it never decoded")
    assert result.get("status") not in ("claimed", "submitted"), result


def test_alias_claim_refuses_a_drain_riding_along_with_a_real_claim(alias_server, monkeypatch):
    """The version that defeats a 'which programs are touched' check: a genuine registry
    instruction plus a SystemProgram transfer of the balance."""
    server = alias_server
    from solders.hash import Hash
    from solders.instruction import AccountMeta, Instruction
    from solders.keypair import Keypair
    from solders.message import Message
    from solders.pubkey import Pubkey
    from solders.transaction import Transaction

    from xete_mcp.client import load_or_create_identity

    pubkey = load_or_create_identity(server.IDENTITY_PATH).pubkey_b58
    me = Pubkey.from_string(pubkey)
    registry = Pubkey.from_string("AXTREGuYbpgcWFbZy124jcWDN2nd7mtmrCDsUojktZrd")
    system = Pubkey.from_string("11111111111111111111111111111111")
    pda = Pubkey.find_program_address([b"alias", b"mcptestname"], registry)[0]

    claim_ix = Instruction(program_id=registry, data=b"\x01mcptestname",
                           accounts=[AccountMeta(me, True, True), AccountMeta(pda, False, True)])
    drain_ix = Instruction(program_id=system,
                           data=struct.pack("<I", 2) + struct.pack("<Q", 4_000_000_000),
                           accounts=[AccountMeta(me, True, True),
                                     AccountMeta(Keypair().pubkey(), False, True)])
    msg = Message.new_with_blockhash([claim_ix, drain_ix], me, Hash.default())
    tx_b64 = base64.b64encode(bytes(Transaction.new_unsigned(msg))).decode()

    _fake_permit(server, monkeypatch, tx_b64, pubkey)
    result = json.loads(server.xete_alias_claim("mcptestname"))

    assert not _FakeRpcClient.submitted, (
        "a claim carrying a full-balance transfer was signed and submitted")
    assert result.get("status") not in ("claimed", "submitted"), result


def test_alias_claim_refuses_a_permit_challenge_for_someone_elses_wallet(alias_server, monkeypatch):
    server = alias_server
    from xete_mcp.client import load_or_create_identity

    pubkey = load_or_create_identity(server.IDENTITY_PATH).pubkey_b58
    signed = []

    def fake_post(url, json=None, timeout=None, **kw):
        if url.endswith("/alias/claim/challenge"):
            nonce = "48aSgGfAhcHvDJwwFNG3jh"
            return FakeResponse({
                "nonce": nonce, "expires_in": 300,
                # addressed to a wallet that is not ours
                "message": (f"xete alias claim\npubkey:11111111111111111111111111111111\n"
                            f"nonce:{nonce}\nts:{int(time.time())}"),
            })
        signed.append((url, json))
        return FakeResponse({"status": "denied", "reason": "nope"})

    monkeypatch.setattr(server.requests, "post", fake_post)
    result = json.loads(server.xete_alias_claim("mcptestname"))

    assert not signed, "a challenge addressed to another wallet was signed and sent"
    assert result.get("status") not in ("claimed", "submitted"), result


def test_alias_claim_refuses_the_derivation_constant_as_a_challenge(alias_server, monkeypatch):
    """Same oracle as the login path, reached through the permit server instead."""
    server = alias_server
    constant = b"xete messaging key derivation v1"
    leak = IDENTITY_SIGNING_KEY.sign(constant).signature
    sent = []

    def fake_post(url, json=None, timeout=None, **kw):
        if url.endswith("/alias/claim/challenge"):
            return FakeResponse({"nonce": "48aSgGfAhcHvDJwwFNG3jh",
                                 "message": constant.decode(), "expires_in": 300})
        sent.append(json or {})
        return FakeResponse({"status": "denied"})

    monkeypatch.setattr(server.requests, "post", fake_post)
    json.loads(server.xete_alias_claim("mcptestname"))

    import base58
    for body in sent:
        got = base58.b58decode(body.get("signature", "") or "1")
        assert got != leak, "the permit server extracted the messaging-key signature"
    assert not sent, "nothing should be sent after refusing to sign"
