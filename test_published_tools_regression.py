"""Regressions for the four ALREADY-PUBLISHED tools (G1-G7).

xete_my_identity, xete_lookup_agent, xete_send_message and xete_check_inbox shipped in
0.1.4 and are running on other people's machines today. Nothing in the 467-test suite
touched them, which is why an upgrade that destroys every existing mailbox was invisible.

Every test here drives a PUBLISHED entry point — `load_or_create_identity`,
`XeteClient.inbox/login/register_encryption_key/send_multi`, `payment.pay_herd`, and the
four tool functions themselves — against fakes. Each one fails on the pre-fix tree.

Run: PYTHONPATH=src python -m pytest test_published_tools_regression.py -q
"""
from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from nacl.public import PrivateKey as X25519Private

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "src"))

from xete_mcp import payment, signguard, spendguard          # noqa: E402
from xete_mcp.client import (                                # noqa: E402
    Identity, MessagingKeyConflict, XeteClient, derive_x25519_secret, encrypt,
    load_or_create_identity,
)

BASE = "https://relay.invalid"
AGENT_ID = "agent-under-upgrade"
SENDER_ID = "agent-sender"
SEED = bytes([0x11] * 32)
SENDER_SEED = bytes([0x22] * 32)

# The random x25519 secret a 0.1.4 keystore carries. Unrelated to SEED, exactly as
# `Identity.generate()` produced it before the messaging key became derived.
OLD_X_SECRET = bytes(X25519Private(bytes(range(1, 33))))
OLD_X_PUBLIC = bytes(X25519Private(OLD_X_SECRET).public_key)

PRE_UPGRADE_TEXT = "the wire transfer is approved — José ✅"
POST_UPGRADE_TEXT = "and here is one sent after the upgrade"


# ── fake relay ───────────────────────────────────────────────────────────────────────

class FakeResponse:
    def __init__(self, payload, status_code=200, text=None):
        self._payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload) if text is None else text

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeRelay:
    """Stands in for requests.Session. Speaks the byte-exact live challenge template."""

    def __init__(self):
        self.headers: dict = {}
        self.keys: dict[str, str] = {}      # agent_id -> x25519 public hex
        self.messages: list[dict] = []
        self.register_status = 200
        self.register_bodies: list[dict] = []
        self.login_status = 200
        self.login_body = {"token": "tok", "agent_id": AGENT_ID}
        self.login_text: str | None = None
        self.sent: list[dict] = []

    # -- handlers ----------------------------------------------------------------
    def _challenge(self) -> dict:
        nonce = "n" * 32
        return {"nonce": nonce, "expires_in": 300,
                "message": f"XETE authentication\nNonce: {nonce}\nTimestamp: {int(time.time())}"}

    def get(self, url, params=None, timeout=None, **kw):
        path = urlsplit(url).path
        if path == "/auth/challenge":
            return FakeResponse(self._challenge())
        if path.startswith("/keys/"):
            agent = path[len("/keys/"):]
            if agent in self.keys:
                return FakeResponse({"x25519_public_key": self.keys[agent]})
            return FakeResponse({"error": "KEY_NOT_FOUND"}, 404)
        if path == "/rx":
            return FakeResponse({"messages": self.messages})
        if path.startswith("/agents/"):
            return FakeResponse({"error": "no such alias"}, 404)
        raise AssertionError(f"unexpected GET {url}")

    def post(self, url, json=None, timeout=None, **kw):
        path = urlsplit(url).path
        if path == "/agent/login":
            return FakeResponse(self.login_body, self.login_status, text=self.login_text)
        if path == "/keys/register":
            self.register_bodies.append(json or {})
            if self.register_status in (200, 201):
                self.keys[AGENT_ID] = (json or {})["x25519_public_key"]
            return FakeResponse({"status": "ok"}, self.register_status)
        if path == "/agent/send-multi":
            self.sent.append(json or {})
            return FakeResponse({"free_alpha": True, "message_count": 1})
        raise AssertionError(f"unexpected POST {url}")

    def request(self, method, url, **kw):
        if method.upper() == "GET":
            return self.get(url, **kw)
        return self.post(url, **kw)


def _client(tmp_path, ident: Identity, relay: FakeRelay) -> XeteClient:
    c = XeteClient(base_url=BASE, identity=ident, session=relay)
    c._token_cache_path = lambda: tmp_path / "token.json"
    return c


def _keystore_0114(path: Path, *, x_secret: bytes = OLD_X_SECRET) -> None:
    """Exactly the shape `git show 4413c2c:src/xete_mcp/client.py`'s to_json wrote."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "ed_seed": base64.b64encode(SEED).decode(),
        "x_secret": base64.b64encode(x_secret).decode(),
        "agent_id": AGENT_ID,
    }))


def _mailbox_row(sender: Identity, to_public: bytes, text: str, mid: str = "m1") -> dict:
    nonce_b64, ct_b64 = encrypt(sender.x_secret, to_public, text)
    return {"id": mid, "from": SENDER_ID, "from_alias": "%sender", "subject": "re: payment",
            "created_at": "2026-07-01T00:00:00Z", "read": False,
            "content": f"{nonce_b64}:{ct_b64}"}


# ══ G1 — an existing 0.1.4 mailbox must survive the upgrade ══════════════════════════

def test_the_0114_keystore_keeps_its_old_secret_as_a_legacy_decryption_key(tmp_path):
    path = tmp_path / "identity.json"
    _keystore_0114(path)

    ident = load_or_create_identity(path)

    assert ident.x_secret == derive_x25519_secret(SEED), "sending key must be derived"
    assert OLD_X_SECRET != ident.x_secret, "fixture is not exercising the change at all"
    assert OLD_X_SECRET in ident.legacy_x_secrets, (
        "the 0.1.4 messaging secret was dropped on load — it is the ONLY key that opens "
        "every message already in this agent's mailbox")
    assert ident.decryption_secrets[0] == ident.x_secret, "derived key must be tried first"


def test_a_message_encrypted_to_the_pre_upgrade_key_is_still_readable(tmp_path):
    """THE deliverable. Start from a 0.1.4-shaped keystore, upgrade, and read mail that
    was encrypted to the OLD key — the mailbox every published install already holds."""
    path = tmp_path / "identity.json"
    _keystore_0114(path)
    ident = load_or_create_identity(path)

    sender = Identity(ed_seed=SENDER_SEED)
    relay = FakeRelay()
    relay.keys[SENDER_ID] = sender.x_public.hex()
    # Encrypted to OLD_X_PUBLIC: what the relay published for this agent under 0.1.4.
    relay.messages = [_mailbox_row(sender, OLD_X_PUBLIC, PRE_UPGRADE_TEXT)]

    msgs = _client(tmp_path, ident, relay).inbox()

    assert msgs[0]["text"] == PRE_UPGRADE_TEXT, (
        f"pre-upgrade mail is unreadable after the upgrade: {msgs[0].get('decrypt_error')!r}")
    assert msgs[0]["decrypted_with_legacy_key"] is True


def test_old_and_new_mail_decrypt_side_by_side_in_one_inbox(tmp_path):
    """A real upgraded mailbox is interleaved, so the fallback has to be per message."""
    path = tmp_path / "identity.json"
    _keystore_0114(path)
    ident = load_or_create_identity(path)

    sender = Identity(ed_seed=SENDER_SEED)
    relay = FakeRelay()
    relay.keys[SENDER_ID] = sender.x_public.hex()
    relay.messages = [
        _mailbox_row(sender, OLD_X_PUBLIC, PRE_UPGRADE_TEXT, mid="old"),
        _mailbox_row(sender, ident.x_public, POST_UPGRADE_TEXT, mid="new"),
    ]

    msgs = {m["id"]: m for m in _client(tmp_path, ident, relay).inbox()}

    assert msgs["old"]["text"] == PRE_UPGRADE_TEXT
    assert msgs["old"]["decrypted_with_legacy_key"] is True
    assert msgs["new"]["text"] == POST_UPGRADE_TEXT
    assert "decrypted_with_legacy_key" not in msgs["new"], (
        "current mail must open on the derived key, not fall through to a legacy one")


def test_the_migrated_keystore_persists_both_keys_and_backs_the_original_up(tmp_path):
    path = tmp_path / "identity.json"
    _keystore_0114(path)
    original = path.read_text()

    load_or_create_identity(path)

    on_disk = json.loads(path.read_text())
    assert base64.b64decode(on_disk["x_secret"]) == derive_x25519_secret(SEED)
    assert base64.b64encode(OLD_X_SECRET).decode() in on_disk["legacy_x_secrets"], (
        "the rewritten keystore dropped the pre-upgrade secret — the mailbox is now "
        "unrecoverable even though the in-memory load worked")

    backup = path.with_name(path.name + ".pre-derived-key.bak")
    assert backup.exists() and backup.read_text() == original
    assert backup.stat().st_mode & 0o777 == 0o600

    # ...and re-loading the migrated file still opens pre-upgrade mail.
    reloaded = load_or_create_identity(path)
    assert OLD_X_SECRET in reloaded.legacy_x_secrets
    assert reloaded.x_secret == derive_x25519_secret(SEED)


def test_migration_leaves_a_current_keystore_completely_alone(tmp_path):
    path = tmp_path / "identity.json"
    ident = Identity(ed_seed=SEED, agent_id=AGENT_ID)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(ident.to_json())
    before = path.read_text()

    load_or_create_identity(path)

    assert path.read_text() == before
    assert not path.with_name(path.name + ".pre-derived-key.bak").exists()


def test_a_failed_decrypt_never_reports_an_empty_reason(tmp_path):
    """InvalidTag stringifies to "", so a broken decrypt reached the agent as
    `"decrypt_error": ""` — a silent failure wearing the costume of a reported one."""
    ident = Identity(ed_seed=SEED, agent_id=AGENT_ID)
    stranger = Identity(ed_seed=bytes([0x33] * 32))
    relay = FakeRelay()
    relay.keys[SENDER_ID] = stranger.x_public.hex()
    # Encrypted to a key this agent has never held: undecryptable by design.
    relay.messages = [_mailbox_row(stranger, Identity(ed_seed=bytes([0x44] * 32)).x_public,
                                   "not for you")]

    msgs = _client(tmp_path, ident, relay).inbox()

    assert msgs[0]["text"] is None
    assert msgs[0]["decrypt_error"].strip(), "a failure was reported with no reason at all"


# ══ G1 — a relay that will not take the new key is a hard error, not a shrug ═════════

def test_a_409_that_leaves_a_different_key_published_is_a_hard_error(tmp_path):
    """409 was accepted as "already registered". Once the key started CHANGING, a 409
    means the relay publishes someone else's answer for us and our mail is unreadable."""
    ident = Identity(ed_seed=SEED, agent_id=AGENT_ID)
    relay = FakeRelay()
    relay.register_status = 409
    relay.keys[AGENT_ID] = OLD_X_PUBLIC.hex()      # the relay kept the pre-upgrade key
    c = _client(tmp_path, ident, relay)

    with pytest.raises(MessagingKeyConflict):
        c.register_encryption_key()
    assert c.messaging_key_conflict is True
    assert c.messaging_key_registered is False


def test_a_409_that_already_holds_our_exact_key_is_still_idempotent(tmp_path):
    """The genuine idempotent case must not become a false alarm."""
    ident = Identity(ed_seed=SEED, agent_id=AGENT_ID)
    relay = FakeRelay()
    relay.register_status = 409
    relay.keys[AGENT_ID] = ident.x_public.hex()
    c = _client(tmp_path, ident, relay)

    c.register_encryption_key()

    assert c.messaging_key_registered is True
    assert c.messaging_key_conflict is False


def test_a_transient_readback_failure_does_not_latch_a_conflict(tmp_path):
    """Found by the fresh-context reviewer. register_encryption_key runs ONCE per
    process, so collapsing "could not check" into "conflict" turned one flaky GET at
    startup into a send outage lasting the whole life of the MCP server."""
    ident = Identity(ed_seed=SEED, agent_id=AGENT_ID)
    relay = FakeRelay()
    relay.register_status = 409
    relay.keys[AGENT_ID] = ident.x_public.hex()      # the relay HAS our key all along
    relay.keys["recipient"] = Identity(ed_seed=bytes([0x55] * 32)).x_public.hex()
    c = _client(tmp_path, ident, relay)

    real_get = relay.get
    def flaky(url, **kw):
        if urlsplit(url).path == f"/keys/{AGENT_ID}":
            relay.get = real_get                      # one blip, then healthy
            raise ConnectionError("connection reset by peer")
        return real_get(url, **kw)
    relay.get = flaky

    with pytest.raises(RuntimeError) as ex:
        c.register_encryption_key()
    assert not isinstance(ex.value, MessagingKeyConflict), (
        "an unreadable key was reported as a proven conflict")
    assert c.messaging_key_conflict is False, "one flaky GET latched the send path shut"

    # The next send re-checks, finds the relay holds our key, and goes through.
    c.send_multi("recipient", "hello")
    assert relay.sent, "sending stayed blocked on a suspicion that was never confirmed"
    assert c.messaging_key_registered is True


def test_an_unconfirmed_409_still_refuses_once_the_conflict_becomes_readable(tmp_path):
    """The other half: not latching must not mean never checking again."""
    ident = Identity(ed_seed=SEED, agent_id=AGENT_ID)
    relay = FakeRelay()
    relay.register_status = 409
    relay.keys["recipient"] = Identity(ed_seed=bytes([0x55] * 32)).x_public.hex()
    c = _client(tmp_path, ident, relay)

    with pytest.raises(RuntimeError):        # no key published yet -> "unknown"
        c.register_encryption_key()
    assert c.messaging_key_unconfirmed is True

    relay.keys[AGENT_ID] = OLD_X_PUBLIC.hex()        # now the conflict is visible
    with pytest.raises(MessagingKeyConflict):
        c.send_multi("recipient", "PAY INVOICE 4471 NOW")
    assert relay.sent == []


def test_sending_under_a_key_conflict_is_refused_not_reported_as_sent(tmp_path):
    ident = Identity(ed_seed=SEED, agent_id=AGENT_ID)
    relay = FakeRelay()
    relay.register_status = 409
    relay.keys[AGENT_ID] = OLD_X_PUBLIC.hex()
    relay.keys["recipient"] = Identity(ed_seed=bytes([0x55] * 32)).x_public.hex()
    c = _client(tmp_path, ident, relay)
    with pytest.raises(MessagingKeyConflict):
        c.register_encryption_key()

    with pytest.raises(MessagingKeyConflict):
        c.send_multi("recipient", "PAY INVOICE 4471 NOW")
    assert relay.sent == [], "a message the recipient cannot decrypt was still delivered"


# ══ the tools themselves ═════════════════════════════════════════════════════════════

@pytest.fixture()
def tools(tmp_path, monkeypatch):
    """The four published tools, with the module's cached client under our control."""
    import xete_mcp.server as server

    monkeypatch.setattr(server, "_client", None)
    monkeypatch.setattr(server, "IDENTITY_PATH", tmp_path / "identity.json")
    monkeypatch.setenv(spendguard.ENV_LEDGER, str(tmp_path / "spend-ledger.json"))
    yield server
    server._client = None


def test_check_inbox_returns_pre_upgrade_plaintext_end_to_end(tools, tmp_path, monkeypatch):
    """The reviewer's exact scenario, through the published tool: 0.1.4 keystore in,
    plaintext out."""
    path = tmp_path / "identity.json"
    _keystore_0114(path)
    ident = load_or_create_identity(path)
    sender = Identity(ed_seed=SENDER_SEED)
    relay = FakeRelay()
    relay.keys[SENDER_ID] = sender.x_public.hex()
    relay.messages = [_mailbox_row(sender, OLD_X_PUBLIC, PRE_UPGRADE_TEXT)]
    monkeypatch.setattr(tools, "_client", _client(tmp_path, ident, relay))

    out = json.loads(tools.xete_check_inbox())

    assert out["messages"][0]["text"] == PRE_UPGRADE_TEXT


def test_send_message_reports_failed_when_the_relay_holds_a_different_key(tools, tmp_path,
                                                                          monkeypatch):
    ident = Identity(ed_seed=SEED, agent_id=AGENT_ID)
    relay = FakeRelay()
    relay.register_status = 409
    relay.keys[AGENT_ID] = OLD_X_PUBLIC.hex()
    relay.keys["recipient"] = Identity(ed_seed=bytes([0x55] * 32)).x_public.hex()
    c = _client(tmp_path, ident, relay)
    with pytest.raises(MessagingKeyConflict):
        c.register_encryption_key()
    monkeypatch.setattr(tools, "_client", c)

    out = json.loads(tools.xete_send_message("recipient", "PAY INVOICE 4471 NOW"))

    assert out["status"] == "failed", (
        'the tool reported "sent" for a message no recipient can decrypt')


def test_my_identity_shows_the_messaging_key_and_its_registration_state(tools, tmp_path,
                                                                        monkeypatch):
    path = tmp_path / "identity.json"
    _keystore_0114(path)
    ident = load_or_create_identity(path)
    relay = FakeRelay()
    c = _client(tmp_path, ident, relay)
    c.identity.agent_id = AGENT_ID
    c.token = "tok"
    c.register_encryption_key()
    monkeypatch.setattr(tools, "_client", c)

    out = json.loads(tools.xete_my_identity())

    key = out["messaging_key"]
    assert key["x25519_public_key"] == ident.x_public.hex()
    assert key["registered_with_relay"] is True
    assert key["legacy_keys_retained"] == 1
    assert OLD_X_PUBLIC.hex() in key["legacy_x25519_public_keys"]


# ══ G2 — a send that never reached the RPC must not burn the spend window ════════════

class FakeRpc:
    """Enough of solana.rpc.api.Client for pay_herd, with scripted failures."""
    blockhash_error: Exception | None = None
    send_error: Exception | None = None
    submitted: list = []

    def __init__(self, url):
        self.url = url

    def get_latest_blockhash(self):
        if FakeRpc.blockhash_error:
            raise FakeRpc.blockhash_error
        from solders.hash import Hash
        return SimpleNamespace(value=SimpleNamespace(blockhash=Hash.default()))

    def send_transaction(self, tx, opts=None):
        FakeRpc.submitted.append(tx)
        if FakeRpc.send_error:
            raise FakeRpc.send_error
        return SimpleNamespace(value=tx.signatures[0])

    def get_signature_statuses(self, sigs):
        # A REAL status object: `err` present, and a durable enum variant -- not the
        # string "confirmed". pay_herd now requires both (it used to accept any truthy
        # confirmation_status and never looked at err, so a transaction that landed and
        # FAILED read as a successful payment). A stub that omits them can only pass
        # against the lenient version.
        from solders.transaction_status import TransactionConfirmationStatus
        return SimpleNamespace(value=[SimpleNamespace(
            confirmation_status=TransactionConfirmationStatus.Confirmed, err=None)])


@pytest.fixture()
def paying(tmp_path, monkeypatch):
    """pay_herd wired to a fake RPC and an isolated, generous-but-finite ledger."""
    from solders.keypair import Keypair

    for name in (spendguard.ENV_MAX, spendguard.ENV_WINDOW, spendguard.ENV_WINDOW_SECONDS,
                 spendguard.ENV_FLOOR, spendguard.ENV_LEDGER):
        monkeypatch.delenv(name, raising=False)
    ledger = tmp_path / "spend-ledger.json"
    monkeypatch.setenv(spendguard.ENV_LEDGER, str(ledger))
    monkeypatch.setenv(spendguard.ENV_FLOOR, "0")
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW, "3000000")
    FakeRpc.blockhash_error = None
    FakeRpc.send_error = None
    FakeRpc.submitted = []
    monkeypatch.setattr(payment, "Client", FakeRpc)
    return SimpleNamespace(ledger=ledger, payer=Keypair())


def _entries(ledger: Path) -> list:
    return json.loads(ledger.read_text())["entries"] if ledger.exists() else []


def test_an_unreachable_rpc_does_not_consume_the_spend_window(paying):
    """25 attempts against a dead RPC used to fill a 24h window having spent nothing,
    locking the agent out for a day. Nothing was built, signed, or submitted."""
    FakeRpc.blockhash_error = ConnectionError("connection refused")

    for _ in range(5):
        with pytest.raises(ConnectionError):
            payment.pay_herd("https://rpc.invalid", paying.payer, "nonce-1", 1)

    assert _entries(paying.ledger) == [], (
        f"{len(_entries(paying.ledger))} failed attempts were charged against the "
        "24h window despite never reaching the network")
    assert FakeRpc.submitted == []


def test_a_successful_send_is_still_recorded_against_the_window(paying):
    sig = payment.pay_herd("https://rpc.invalid", paying.payer, "nonce-2", 1)

    assert sig
    entries = _entries(paying.ledger)
    assert len(entries) == 1 and entries[0]["lamports"] == payment.LAMPORTS_PER_BLOB
    assert len(FakeRpc.submitted) == 1


def test_the_gate_still_refuses_before_anything_is_submitted(paying):
    """The reorder must not have turned the gate into an after-the-fact audit log."""
    payment.pay_herd("https://rpc.invalid", paying.payer, "nonce-3", 3)   # 3_000_000: full
    FakeRpc.submitted = []

    with pytest.raises(spendguard.SpendRefused):
        payment.pay_herd("https://rpc.invalid", paying.payer, "nonce-4", 1)

    assert FakeRpc.submitted == [], "a transaction was submitted after the gate refused it"


def test_released_budget_is_actually_re_spendable(paying):
    """The point of the release: a dead RPC must not cost the agent its day."""
    FakeRpc.blockhash_error = ConnectionError("connection refused")
    for _ in range(10):                       # 10 x 1_000_000 into a 3_000_000 window
        with pytest.raises(ConnectionError):
            payment.pay_herd("https://rpc.invalid", paying.payer, "dead", 1)
    FakeRpc.blockhash_error = None

    assert payment.pay_herd("https://rpc.invalid", paying.payer, "alive", 1), (
        "the window was locked out by attempts that never reached the network")


def test_the_release_gives_back_only_this_attempts_entry(paying):
    """A rollback that trimmed anything else would be a hole in the ceiling."""
    payment.pay_herd("https://rpc.invalid", paying.payer, "landed", 1)   # a real spend
    spendguard.authorize(500_000, "xete_alias_claim", detail="someone else's")
    FakeRpc.blockhash_error = ConnectionError("connection refused")

    with pytest.raises(ConnectionError):
        payment.pay_herd("https://rpc.invalid", paying.payer, "dead", 1)

    kept = [(e["path"], e["detail"]) for e in _entries(paying.ledger)]
    assert len(kept) == 2, f"the release trimmed something it did not add: {kept}"
    assert kept[0][0] == "xete_send_message" and kept[0][1].endswith("blobs=1 nonce=landed")
    assert kept[1] == ("xete_alias_claim", "someone else's")


def test_two_attempts_with_the_same_relay_nonce_get_distinct_ledger_identities(paying):
    """The relay chooses payment_nonce and may repeat it. If two attempts land the same
    ledger `detail`, a release cannot tell whose entry it is deleting."""
    payment.pay_herd("https://rpc.invalid", paying.payer, "SAME", 1)
    payment.pay_herd("https://rpc.invalid", paying.payer, "SAME", 1)

    details = [e["detail"] for e in _entries(paying.ledger)]
    assert len(set(details)) == 2, f"two attempts share one ledger identity: {details}"
    assert all(d.endswith("blobs=1 nonce=SAME") for d in details), (
        "the nonce and blob count must still be visible to a human reading the ledger")


def test_a_release_cannot_take_a_concurrent_calls_entry(paying):
    """Found by the fresh-context reviewer. Two concurrent sends with the same
    relay-chosen nonce produced byte-identical entries; when the FAILING one authorized
    first, its release deleted the entry belonging to the call that had already reached
    send_transaction — the one case that must never be released.

    The interleaving is forced, not raced: the failing call authorizes first, then the
    submitting call runs to completion, then the failing call releases."""
    import threading

    loser_authorized = threading.Event()
    winner_go = threading.Event()
    submitted = threading.Event()
    release_now = threading.Event()

    class Racing(FakeRpc):
        def __init__(self, url):
            super().__init__(url)
            if threading.current_thread().name == "loser":
                loser_authorized.set()          # authorize() has already run

        def get_latest_blockhash(self):
            if threading.current_thread().name == "loser":
                submitted.wait(10)              # let the winner submit first
                raise ConnectionError("connection refused")
            return super().get_latest_blockhash()

        def send_transaction(self, tx, opts=None):
            out = super().send_transaction(tx, opts)
            submitted.set()
            release_now.wait(10)
            return out

    monkey = payment.Client
    payment.Client = Racing
    try:
        result = {}

        def winner():
            winner_go.wait(10)
            result["sig"] = payment.pay_herd("https://rpc.invalid", paying.payer, "N", 1)

        def loser():
            try:
                payment.pay_herd("https://rpc.invalid", paying.payer, "N", 1)
            except ConnectionError:
                result["loser_failed"] = True

        tl = threading.Thread(target=loser, name="loser")
        tw = threading.Thread(target=winner, name="winner")
        tl.start()
        assert loser_authorized.wait(10)
        loser_ts = _entries(paying.ledger)[0]["ts"]     # the failing call's own entry
        tw.start()
        winner_go.set()
        tl.join(15)
        release_now.set()
        tw.join(15)
    finally:
        payment.Client = monkey
        release_now.set()

    assert result.get("loser_failed") and result.get("sig")
    entries = _entries(paying.ledger)
    assert len(entries) == 1, f"expected exactly one surviving entry, got {entries}"
    assert entries[0]["ts"] > loser_ts, (
        "the release deleted the SUBMITTED call's entry and kept the failed one — a "
        "transaction that may be on the cluster was refunded")


def test_a_submitted_transaction_that_errors_still_counts(paying):
    """The other direction: once it is on the wire it may have landed, so it is charged.

    THE EXPECTED EXCEPTION TYPE CHANGED HERE AND THE PROPERTY DID NOT. This asserted a
    bare `TimeoutError` escaping `pay_herd`, which was the defect it was sitting next to:
    the raw transport error carried NO signature, so a caller who caught it could not tell
    whether they had paid, and `send_multi` mints a fresh nonce per call — the obvious
    retry pays twice. `TimeoutError` is now wrapped into `PaymentUnconfirmed`, which
    carries the signature computed before submission.

    Recorded explicitly because "changed a test so my fix passes" is the move a reviewer
    flagged in another lane today: the original property — the spend is NOT released once
    the transaction may be live — is asserted below exactly as it was, and the assertions
    added around it are strictly stronger than what they replace. Nothing here got easier.
    """
    FakeRpc.send_error = TimeoutError("read timeout waiting for the RPC's answer")

    with pytest.raises(payment.PaymentUnconfirmed) as ei:
        payment.pay_herd("https://rpc.invalid", paying.payer, "nonce-5", 1)

    assert ei.value.signature, "the signature must survive; it is the whole recovery path"
    assert isinstance(ei.value.__cause__, TimeoutError), (
        "the underlying transport error must stay reachable as __cause__ — wrapping it "
        "must not throw away what actually went wrong")

    # UNCHANGED, and the reason this test exists: submitted means charged.
    assert len(_entries(paying.ledger)) == 1
    assert len(FakeRpc.submitted) == 1


# ══ G3 — a refusal to sign must arrive as JSON, from all four tools ══════════════════

SKEW_ERROR = signguard.RefusedToSign(
    "REFUSED TO SIGN (relay auth challenge): the challenge is dated 1785000000, which is "
    "more than 900s in the future. This is measured against THIS MACHINE's clock, which "
    "currently reads 1784998000 — if the two disagree by more than the allowed window the "
    "cause is usually a wrong local clock (a resumed laptop, a container with no NTP), not "
    "an attack. Check the system time before assuming the server is at fault. Nothing was "
    "signed.")


@pytest.mark.parametrize("call", [
    lambda s: s.xete_my_identity(),
    lambda s: s.xete_lookup_agent("someone"),
    lambda s: s.xete_send_message("someone", "hi"),
    lambda s: s.xete_check_inbox(),
])
def test_a_skewed_clock_returns_json_from_every_published_tool(tools, monkeypatch, call):
    def boom():
        raise SKEW_ERROR
    monkeypatch.setattr(tools, "_get_client", boom)

    out = json.loads(call(tools))       # must not raise out of the tool at all

    assert "REFUSED TO SIGN" in out["error"]
    assert "Check the system time" in out["error"], (
        "the actionable half of the diagnostic was truncated away")


# ══ G4 — a trailing newline is a formatting change, and should say so ════════════════

def test_a_trailing_newline_is_named_as_such_not_as_a_bogus_fourth_line():
    nonce = "n" * 32
    msg = f"XETE authentication\nNonce: {nonce}\nTimestamp: {int(time.time())}"

    signguard.validate_relay_auth_challenge(msg, nonce)          # baseline: accepted

    with pytest.raises(signguard.RefusedToSign) as ex:
        signguard.validate_relay_auth_challenge(msg + "\n", nonce)
    text = str(ex.value)
    assert "TRAILING NEWLINE" in text, (
        f"a trailing newline was reported as a smuggled fourth line: {text}")
    assert "Nothing was signed" in text


def test_a_real_fourth_line_is_still_refused_as_a_fourth_line():
    """The special case must not have opened a hole: a fourth line with CONTENT that is
    not our own client nonce is still refused, with the message it always had."""
    nonce = "n" * 32
    msg = (f"XETE authentication\nNonce: {nonce}\nTimestamp: {int(time.time())}\n"
           "Expires: 300")

    with pytest.raises(signguard.RefusedToSign, match="fourth line"):
        signguard.validate_relay_auth_challenge(msg, nonce)


# ══ G6 — a 403's real reason must not be replaced by a guess ═════════════════════════

def test_a_403_keeps_the_relays_own_words(tmp_path):
    real_reason = ("your invite to the closed beta was revoked on 2026-07-20; "
                   "email support@xete.net")
    relay = FakeRelay()
    relay.login_status = 403
    relay.login_body = {"error": real_reason}
    c = _client(tmp_path, Identity(ed_seed=SEED), relay)

    with pytest.raises(RuntimeError) as ex:
        c.login(force=True)

    assert "support@xete.net" in str(ex.value), (
        "the relay's actual reason was discarded and replaced with an env-var hint that "
        "does not apply")
    assert "XETE_INVITE_CODE" in str(ex.value), "the hint is still worth keeping"


# ══ G7 — documentation, and no home path in every answer ═════════════════════════════

def test_a_malformed_payer_keypair_does_not_raise_out_of_my_identity(tools, tmp_path,
                                                                     monkeypatch):
    """Same class as G3: identity must not fail because an OPTIONAL file is broken."""
    bad = tmp_path / "keypair.json"
    bad.write_text("{ this is not a solana keypair")
    monkeypatch.setattr(tools, "SOL_KEYPAIR_PATH", str(bad))
    monkeypatch.setattr(tools, "_client",
                        _client(tmp_path, Identity(ed_seed=SEED, agent_id=AGENT_ID),
                                FakeRelay()))

    out = json.loads(tools.xete_my_identity())      # must not raise

    assert out["wallet_pubkey"]
    assert out["can_send"] is False
    assert out["payer_error"]


def test_my_identity_does_not_disclose_the_ledgers_absolute_path(tools, tmp_path,
                                                                 monkeypatch):
    ident = Identity(ed_seed=SEED, agent_id=AGENT_ID)
    monkeypatch.setattr(tools, "_client", _client(tmp_path, ident, FakeRelay()))
    ledger = tmp_path / "deep" / "spend-ledger.json"
    monkeypatch.setenv(spendguard.ENV_LEDGER, str(ledger))

    raw = tools.xete_my_identity()

    assert str(tmp_path) not in raw, "the answer carries a filesystem path (hence the OS user)"
    limits = json.loads(raw)["spend_limits"]
    assert "ledger" not in limits
    assert limits["ledger_file"] == "spend-ledger.json"
    assert "ledger_writable" in limits


@pytest.mark.parametrize("break_it", ["corrupt", "named-identity-json"])
def test_no_absolute_path_leaks_through_the_spend_limits_error_text(tools, tmp_path,
                                                                    monkeypatch, break_it):
    """Found by the fresh-context reviewer. Popping the `ledger` KEY left every
    spendguard.status() FAILURE branch printing the absolute path in its error prose."""
    monkeypatch.setattr(tools, "_client",
                        _client(tmp_path, Identity(ed_seed=SEED, agent_id=AGENT_ID),
                                FakeRelay()))
    home = tmp_path / "home"
    (home / ".xete").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    if break_it == "corrupt":
        ledger = home / ".xete" / "spend-ledger.json"
        ledger.write_text("{ not json at all")
    else:
        # spendguard refuses outright when the ledger is aimed at an identity keystore.
        ledger = home / ".xete" / "identity.json"
    monkeypatch.setenv(spendguard.ENV_LEDGER, str(ledger))

    raw = tools.xete_my_identity()

    assert json.loads(raw)["spend_limits"].get("error"), "this case must hit an error branch"
    assert str(home) not in raw, f"the home directory leaked into the answer: {raw}"
    assert str(ledger) not in raw


def test_the_env_vars_that_can_refuse_a_published_tool_are_documented():
    readme = (REPO / "README.md").read_text()
    envdoc = (REPO / "src/xete_mcp/server.py").read_text().split('"""')[1]

    assert "XETE_INVITE_CODE" in readme, "read on the login path, documented nowhere"
    assert "XETE_INVITE_CODE" in envdoc

    # The two XETE_RPC_URL shapes that 0.1.4 accepted and this version refuses.
    for doc, where in ((readme, "README"), (envdoc, "server.py env block")):
        assert "credentials in the URL" in doc or "credentials embedded in the URL" in doc, (
            f"{where} does not mention that credentials in XETE_RPC_URL are refused")
        assert "192.168" in doc, (
            f"{where} does not mention that plain http to a private LAN is refused")

    # ...and the keystore migration, which is the one that eats data if unread.
    assert "legacy_x_secrets" in readme and "legacy_x_secrets" in envdoc
