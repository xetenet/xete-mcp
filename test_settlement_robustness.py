"""Tests for the four settlement-robustness defects.

Offline: nothing here touches the network, mainnet, a real wallet, or the real ~/.xete/.
Every test is written to FAIL against the code as audited and pass against the fix.

Run with:  python -m pytest test_settlement_robustness.py -v
"""
from __future__ import annotations

import base64
import json
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from solders.hash import Hash                                              # noqa: E402
from solders.instruction import AccountMeta, Instruction                   # noqa: E402
from solders.keypair import Keypair                                        # noqa: E402
from solders.message import Message                                        # noqa: E402
from solders.system_program import (                                       # noqa: E402
    AdvanceNonceAccountParams, TransferParams, advance_nonce_account, transfer,
)
from solders.transaction import Transaction                                # noqa: E402
from solders.transaction_status import TransactionConfirmationStatus as TCS  # noqa: E402
from solana.rpc.core import RPCException                                   # noqa: E402

from xete_mcp import draft, settlement, spendguard                         # noqa: E402

DEPOSITOR = Keypair.from_seed(bytes([1] * 32))
RECIPIENT = Keypair.from_seed(bytes([2] * 32))
ATTACKER = Keypair.from_seed(bytes([3] * 32))
NONCE_ACCT = Keypair.from_seed(bytes([4] * 32)).pubkey()
ESCROW_ID = bytes(Keypair.from_seed(bytes([9] * 32)).pubkey())
SALT = bytes(range(16))
AMOUNT = 1_000_000_000                      # 1 SOL
DRAIN = 100_000_000_000                     # 100 SOL

OVERLONG_ESCROW_ID = "aa" * 33              # 66 characters — the id that kills the server


# ── helpers ──────────────────────────────────────────────────────────────────────────

def _deposit_ix(escrow_id=ESCROW_ID, amount=AMOUNT, recipient=None, salt=SALT):
    return settlement.deposit_ix(
        settlement.program_id(), DEPOSITOR.pubkey(), escrow_id, amount,
        settlement.commitment(recipient or RECIPIENT.pubkey(), salt))


def _tx_b64(ixs):
    msg = Message.new_with_blockhash(ixs, DEPOSITOR.pubkey(), Hash.default())
    return base64.b64encode(bytes(Transaction.new_unsigned(msg))).decode()


def _honest(extra=(), limit=60_000, price=1_000, first=()):
    return _tx_b64(list(first)
                   + [settlement._cb_limit(limit), settlement._cb_price(price), _deposit_ix()]
                   + list(extra))


def _verify(tx_b64, **kw):
    kw.setdefault("expect_recipient", RECIPIENT.pubkey())
    kw.setdefault("expect_salt_hex", SALT.hex())
    kw.setdefault("expect_amount_lamports", AMOUNT)
    kw.setdefault("expect_depositor", DEPOSITOR.pubkey())
    return draft.verify_draft(tx_b64, **kw)


def _blob(result) -> str:
    return json.dumps(result.checks) + json.dumps(getattr(result, "movements", []))


@pytest.fixture()
def spend_ok(tmp_path, monkeypatch):
    """A clean, generous spend ledger so these tests are about settlement, not the spend gate."""
    monkeypatch.setenv(spendguard.ENV_LEDGER, str(tmp_path / "spend-ledger.json"))
    monkeypatch.setenv(spendguard.ENV_MAX, "1000000000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW, "1000000000000")
    monkeypatch.setenv(spendguard.ENV_FLOOR, "0")


@pytest.fixture()
def server_mod(tmp_path, monkeypatch):
    from xete_mcp import server as server_mod

    monkeypatch.setattr(server_mod, "IDENTITY_PATH", tmp_path / "identity.json")
    monkeypatch.setattr(server_mod, "RPC_URL", "http://127.0.0.1:1")
    return server_mod


# ══ DEFECT 1 — a 66-character escrow_id kills the whole MCP server ═══════════════════
# solders raises pyo3 PanicException, which derives from BaseException. `except Exception`
# does not catch it, so it unwinds out of the tool and takes the stdio session with it.

def test_escrow_pda_rejects_an_overlong_seed_instead_of_panicking():
    with pytest.raises(ValueError):
        settlement.escrow_pda(settlement.program_id(), bytes.fromhex(OVERLONG_ESCROW_ID))


@pytest.mark.parametrize("bad", [
    OVERLONG_ESCROW_ID,          # 66 chars — the reported crash
    "aa" * 64,                   # far too long
    "aa" * 31,                   # too short
    "aa" * 32 + "a",             # odd length
    "",                          # empty
    "zz" * 32,                   # right length, not hex
    "0x" + "aa" * 31,            # right length, not hex
])
def test_parse_escrow_id_rejects_every_malformed_id(bad):
    with pytest.raises(ValueError):
        settlement.parse_escrow_id(bad)


def test_parse_escrow_id_accepts_a_real_one():
    assert settlement.parse_escrow_id(ESCROW_ID.hex()) == ESCROW_ID


@pytest.mark.parametrize("fn,args", [
    ("status", ()),
    ("reclaim", ()),
    ("claim", (SALT.hex(),)),
])
def test_settlement_api_rejects_a_bad_escrow_id_before_any_network_or_solders_call(fn, args, monkeypatch):
    def no_network(*_a, **_k):
        raise AssertionError("validation must happen before an RPC client is built")

    monkeypatch.setattr(settlement, "Client", no_network)
    call = getattr(settlement, fn)
    first = ("http://127.0.0.1:1",) if fn == "status" else ("http://127.0.0.1:1", DEPOSITOR)
    with pytest.raises(ValueError):
        call(*first, OVERLONG_ESCROW_ID, *args)


def test_the_settle_tools_survive_a_malicious_escrow_id(server_mod, tmp_path):
    """The whole point: a hostile string in the inbox must come back as a JSON error, not as a
    dead server. Nothing may be signed, spent, or even keyed on the way."""
    outs = [
        server_mod.xete_settle_status(OVERLONG_ESCROW_ID),
        server_mod.xete_settle_reclaim(OVERLONG_ESCROW_ID),
        server_mod.xete_settle_claim(OVERLONG_ESCROW_ID, SALT.hex()),
        server_mod.xete_settle_claim(ESCROW_ID.hex(), "not-hex-at-all"),
    ]
    for out in outs:
        d = json.loads(out)
        assert d["status"] == "failed"
        assert "invalid" in d["error"]
    assert not (tmp_path / "identity.json").exists(), \
        "the id must be rejected before the identity keystore is opened"


# ══ DEFECT 2 — the verifier green-lights a drain ═════════════════════════════════════

def test_an_honest_draft_still_verifies():
    r = _verify(_honest())
    assert r.ok, r.failures


def test_a_durable_nonce_draft_still_verifies():
    """advance_nonce_account is a legitimate system instruction in this path — the fix must not
    turn the nonce feature off in the name of safety."""
    nonce_ix = advance_nonce_account(AdvanceNonceAccountParams(
        nonce_pubkey=NONCE_ACCT, authorized_pubkey=DEPOSITOR.pubkey()))
    r = _verify(_honest(first=[nonce_ix]))
    assert r.ok, r.failures


def test_a_plain_sol_transfer_to_an_attacker_is_not_waved_through():
    """THE finding: honest deposit + 100 SOL to an attacker returned verified=True, 10/10,
    'SAFE TO REVIEW AND SIGN'. The system program is on the whitelist; nobody read the data."""
    drain = transfer(TransferParams(from_pubkey=DEPOSITOR.pubkey(),
                                    to_pubkey=ATTACKER.pubkey(), lamports=DRAIN))
    r = _verify(_honest(extra=[drain]))
    assert not r.ok, "verifier green-lit a 100 SOL transfer to an attacker"
    blob = _blob(r)
    assert str(ATTACKER.pubkey()) in blob, "the attacker's address was never surfaced"
    assert str(DRAIN) in blob, "the 100 SOL was never surfaced"
    assert r.total_lamports_out == AMOUNT + DRAIN


def test_the_transfer_is_caught_even_when_it_comes_first():
    drain = transfer(TransferParams(from_pubkey=DEPOSITOR.pubkey(),
                                    to_pubkey=ATTACKER.pubkey(), lamports=DRAIN))
    assert not _verify(_honest(first=[drain])).ok


def test_a_compute_budget_fee_bomb_is_caught():
    """No lamport-moving instruction at all: 1_400_000 CU x 700_000_000 micro-lamports/CU is
    0.98 SOL of priority fee, debited from the signer."""
    r = _verify(_honest(limit=1_400_000, price=700_000_000))
    assert not r.ok, "verifier green-lit a ~0.98 SOL compute-budget fee bomb"
    assert r.fee_lamports > 900_000_000
    assert "max_transaction_fee" in r.failures
    assert str(r.fee_lamports) in _blob(r)


def test_a_fee_bomb_with_no_explicit_limit_is_caught():
    """Omitting SetComputeUnitLimit does not make the price free — the runtime applies a default
    of 200k CU per instruction."""
    r = _verify(_tx_b64([settlement._cb_price(700_000_000), _deposit_ix()]))
    assert not r.ok
    assert "max_transaction_fee" in r.failures


def test_a_duplicated_compute_limit_is_priced_at_the_worse_value():
    """Two SetComputeUnitLimit instructions: price the expensive one, never the cheap one."""
    r = _verify(_tx_b64([settlement._cb_limit(1_400_000), settlement._cb_price(700_000_000),
                         _deposit_ix(), settlement._cb_limit(1_000)]))
    assert not r.ok
    assert r.fee_lamports > 900_000_000


def test_an_ordinary_priority_fee_is_still_allowed():
    r = _verify(_honest(limit=200_000, price=50_000))     # 10_000 lamports — real but sane
    assert r.ok, r.failures


def test_a_second_hidden_deposit_to_the_attacker_is_caught():
    """Two tag-0 instructions: the verifier used to match only the first one."""
    sneaky = _deposit_ix(escrow_id=bytes(Keypair.from_seed(bytes([7] * 32)).pubkey()),
                         amount=50 * 10 ** 9, recipient=ATTACKER.pubkey())
    r = _verify(_honest(extra=[sneaky]))
    assert not r.ok
    assert r.total_lamports_out == AMOUNT + 50 * 10 ** 9


def test_a_system_instruction_we_cannot_decode_is_refused_not_ignored():
    weird = Instruction(program_id=settlement.SYS, data=struct.pack("<I", 250) + b"\x00" * 8,
                        accounts=[AccountMeta(DEPOSITOR.pubkey(), True, True)])
    r = _verify(_honest(extra=[weird]))
    assert not r.ok
    assert "every_instruction_decoded" in r.failures


def test_a_compute_budget_instruction_we_cannot_decode_is_refused():
    weird = Instruction(program_id=settlement.CB, data=bytes([99, 0, 0, 0, 0]), accounts=[])
    assert not _verify(_honest(extra=[weird])).ok


def test_a_nonce_withdrawal_bolted_on_is_caught():
    withdraw = Instruction(
        program_id=settlement.SYS,
        data=struct.pack("<I", 5) + struct.pack("<Q", DRAIN),
        accounts=[AccountMeta(NONCE_ACCT, False, True),
                  AccountMeta(ATTACKER.pubkey(), False, True)])
    r = _verify(_honest(extra=[withdraw]))
    assert not r.ok
    assert str(ATTACKER.pubkey()) in _blob(r)


def test_every_movement_is_surfaced_on_an_honest_draft():
    r = _verify(_honest())
    assert r.total_lamports_out == AMOUNT
    kinds = [m["kind"] for m in r.movements]
    assert kinds == ["settlement:deposit"]
    assert {c["name"] for c in r.checks} >= {
        "lamport_movements", "total_lamport_movement", "destinations", "max_transaction_fee"}


def test_a_redirected_beneficiary_still_fails():
    """Regression guard on the check that already worked."""
    bad = _tx_b64([settlement._cb_limit(60_000), settlement._cb_price(1_000),
                   _deposit_ix(recipient=ATTACKER.pubkey())])
    r = _verify(bad)
    assert not r.ok
    assert "recipient_commitment" in r.failures


# ══ DEFECT 3 — settle_status cannot tell your escrow from an attacker's ══════════════

def _state(depositor, amount, commitment_bytes):
    return (bytes(depositor) + struct.pack("<Q", amount) + commitment_bytes
            + struct.pack("<q", 0) + bytes([255]))


def _account_client(data: bytes | None, lamports: int = 2_000_000, owner=None):
    """A fake RPC returning one account.

    `owner` defaults to the settlement program because that is what a REAL escrow account looks
    like — the previous fake omitted the field entirely, which is why an unchecked
    `info.owner` went unnoticed. Pass `owner=` explicitly to model a hostile RPC serving bytes
    from an account the settlement program does not own.
    """
    class _C:
        def __init__(self, *_a, **_k):
            pass

        def get_account_info(self, _pda, commitment=None):
            if data is None:
                return SimpleNamespace(value=None)
            return SimpleNamespace(value=SimpleNamespace(
                data=data, lamports=lamports,
                owner=settlement.program_id() if owner is None else owner))
    return _C


def test_status_reports_the_on_chain_commitment(monkeypatch):
    c = settlement.commitment(RECIPIENT.pubkey(), SALT)
    monkeypatch.setattr(settlement, "Client",
                        _account_client(_state(ATTACKER.pubkey(), AMOUNT, c)))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex())
    assert out["commitment"] == c.hex(), "the commitment is the only field that says who is paid"


def test_status_without_an_expectation_verifies_nothing_and_says_so(monkeypatch):
    c = settlement.commitment(ATTACKER.pubkey(), SALT)
    monkeypatch.setattr(settlement, "Client",
                        _account_client(_state(ATTACKER.pubkey(), AMOUNT, c)))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex())
    assert out["open"] is True
    assert out["beneficiary_verified"] is None
    assert "does not mean" in json.dumps(out).lower()


def test_status_flags_an_escrow_that_pays_someone_else(monkeypatch):
    """The attack: a real, open, well-formed escrow whose hidden beneficiary is the attacker."""
    attacker_escrow = settlement.commitment(ATTACKER.pubkey(), SALT)
    monkeypatch.setattr(settlement, "Client",
                        _account_client(_state(ATTACKER.pubkey(), AMOUNT, attacker_escrow)))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex(),
                            expect_commitment_hex=settlement.commitment(RECIPIENT.pubkey(),
                                                                        SALT).hex())
    assert out["open"] is True
    assert out["beneficiary_verified"] is False
    assert "DOES NOT" in out["verdict"]


def test_status_confirms_an_escrow_that_really_is_yours(monkeypatch):
    """CALIBRATION CHANGE, round 2. This used to assert the verdict starts with "VERIFIED" off a
    SINGLE endpoint. It cannot: every byte behind that word, including the owner field, came out
    of one JSON document from one endpoint. The property being tested — a matching commitment is
    recognised and reported as matching — is unchanged and still asserted; only the unearned
    authenticity claim is gone. `test_two_agreeing_endpoints_earn_the_verified_verdict` covers
    the case where "VERIFIED" is actually warranted."""
    mine = settlement.commitment(RECIPIENT.pubkey(), SALT)
    monkeypatch.setattr(settlement, "Client",
                        _account_client(_state(DEPOSITOR.pubkey(), AMOUNT, mine)))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex(),
                            expect_commitment_hex=mine.hex())
    assert out["beneficiary_verified"] is True
    assert out["open"] is True and out["determinate"] is True
    assert out["verdict"].startswith("ONE ENDPOINT SAYS")
    assert out["corroborated"] is False


def test_status_does_not_call_a_foreign_account_an_open_escrow(monkeypatch):
    monkeypatch.setattr(settlement, "Client", _account_client(b"\x00" * 12))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex())
    assert out["commitment"] is None
    assert "UNKNOWN ACCOUNT" in out["verdict"]


def test_settle_status_tool_says_plainly_when_the_escrow_is_not_yours(server_mod, monkeypatch):
    attacker_escrow = settlement.commitment(ATTACKER.pubkey(), SALT)
    monkeypatch.setattr(settlement, "Client",
                        _account_client(_state(ATTACKER.pubkey(), AMOUNT, attacker_escrow)))
    out = json.loads(server_mod.xete_settle_status(
        ESCROW_ID.hex(), expect_recipient=str(RECIPIENT.pubkey()), salt=SALT.hex()))
    assert out["beneficiary_verified"] is False
    assert "DOES NOT" in out["verdict"]
    assert out["checked_against_wallet"] == str(RECIPIENT.pubkey())


def test_settle_status_tool_warns_when_nothing_was_verified(server_mod, monkeypatch):
    c = settlement.commitment(ATTACKER.pubkey(), SALT)
    monkeypatch.setattr(settlement, "Client", _account_client(_state(ATTACKER.pubkey(), AMOUNT, c)))
    out = json.loads(server_mod.xete_settle_status(ESCROW_ID.hex()))
    assert out["beneficiary_verified"] is None
    assert "how_to_verify" in out


# ══ DEFECT 4 — a congestion spike permanently destroys a settlement ══════════════════

class _Status:
    def __init__(self, cs, err=None):
        self.confirmation_status = cs
        self.err = err


class _SendClient:
    """Fake RPC. `statuses` is consumed one per poll; the last entry repeats forever.

    FIXTURE CALIBRATION (finding [G13]): send_transaction used to answer with the constant
    "SiGnAtUrE" — a string no real endpoint could return, since the signature is ed25519 over the
    message the client just signed and is therefore fixed before submission. Echoing the
    transaction's OWN signature is what a real RPC does, and it is what lets the tests below
    assert the returned value IS the submitted transaction's signature instead of a made-up
    constant. `_ForeignSignature` below is the same fake lying about it.
    """

    def __init__(self, statuses, blockhash_valid=True):
        self.statuses = list(statuses)
        self.blockhash_valid = blockhash_valid
        self.sent = 0
        self.polls = 0
        self.signature = None       # the signature of the transaction actually submitted

    def get_latest_blockhash(self):
        return SimpleNamespace(value=SimpleNamespace(blockhash=Hash.default()))

    def send_transaction(self, _tx, opts=None):
        self.sent += 1
        self.signature = str(_tx.signatures[0])
        return SimpleNamespace(value=_tx.signatures[0])

    def get_signature_statuses(self, _sigs):
        self.polls += 1
        st = self.statuses.pop(0) if len(self.statuses) > 1 else (self.statuses or [None])[0]
        return SimpleNamespace(value=[st])

    def is_blockhash_valid(self, _bh, commitment=None):
        return SimpleNamespace(value=self.blockhash_valid)


class _Clock:
    """A virtual clock swapped in for settlement's `time` module.

    Replaces the old `monkeypatch.setattr(settlement.time, "sleep", ...)`, which reached into the
    real `time` module and made every test blind to how long _send actually waits. Sleeping
    advances the clock, so the confirmation budget is now measured rather than assumed, and
    `latency` lets a test charge the same clock for the RPC round trip — which is the thing the
    old poll-count loop was not counting.
    """

    def __init__(self, start: float = 1_000.0):
        self.t = start
        self.slept = 0.0

    def monotonic(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        s = max(0.0, s)
        self.t += s
        self.slept += s

    def advance(self, s: float) -> None:
        self.t += s


@pytest.fixture()
def instant(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(settlement, "time", clock)
    return clock


def _send(client, **kw):
    return settlement._send(client, [DEPOSITOR], [_deposit_ix()], DEPOSITOR, "deposit", **kw)


def _capture(cls, *a, **k):
    """(factory, made) — a settlement.Client replacement that keeps every instance it builds, so
    a test can read the signature the fake actually submitted."""
    made: list = []

    def factory(*_a, **_k):
        made.append(cls(*a, **k))
        return made[-1]

    return factory, made


def test_send_keeps_watching_through_a_congestion_spike(instant):
    """The old client gave up after 60 polls (18s) while the RPC rebroadcasts for 60-90s."""
    client = _SendClient([None] * 70 + [_Status(TCS.Confirmed)])
    assert _send(client) == client.signature
    assert client.polls > 60


def test_send_does_not_call_processed_confirmed(instant):
    """`if st.confirmation_status:` is true for Processed too — every enum variant is truthy.
    Processed is one validator's opinion and can still be forked away."""
    client = _SendClient([_Status(TCS.Processed)])
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(client)
    assert ei.value.outcome == "unconfirmed"


def test_send_accepts_finalized(instant):
    client = _SendClient([_Status(TCS.Finalized)])
    assert _send(client) == client.signature


def test_a_timeout_hands_back_the_signature_instead_of_a_bare_failure(instant):
    client = _SendClient([None])
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(client)
    assert ei.value.signature == client.signature
    assert ei.value.outcome == "unconfirmed"
    assert "MAY STILL LAND" in str(ei.value)


def test_a_dead_blockhash_with_no_status_is_reported_as_definitely_dropped(instant, monkeypatch):
    """FIXTURE CALIBRATION (finding [G15]): the assertion is unchanged — a dead blockhash with no
    status is still reported as definitely dropped — but it now takes TWO endpoints saying so.
    `dropped` is the one outcome the tools turn into a flat {"status": "failed"}, and both facts
    it rests on are chosen by the same endpoint, so a second, independently-configured endpoint
    has to agree. The single-endpoint case is asserted directly below."""
    monkeypatch.setenv(settlement.ENV_SECOND_RPC, "https://second.example")
    monkeypatch.setattr(settlement, "Client",
                        lambda *_a, **_k: _SendClient([None], blockhash_valid=False))
    client = _SendClient([None], blockhash_valid=False)
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(client, rpc_url="https://primary.example")
    assert ei.value.outcome == "dropped"
    assert ei.value.signature == client.signature
    assert "second" in str(ei.value)


def test_an_on_chain_error_is_still_a_failure(instant):
    client = _SendClient([_Status(TCS.Confirmed, err="InsufficientFundsForRent")])
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(client)
    assert ei.value.outcome == "failed"


def test_an_rpc_without_is_blockhash_valid_still_works(instant):
    class _Old(_SendClient):
        def is_blockhash_valid(self, *_a, **_k):
            raise AttributeError("this RPC does not support it")

    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(_Old([None]))
    assert ei.value.outcome == "unconfirmed"


def test_deposit_hands_over_the_claim_ticket_before_submitting(spend_ok, monkeypatch):
    """The salt exists nowhere else — only sha256(recipient || salt) reaches the chain. If the
    client discards it on timeout the recipient can never claim."""
    seen: list[dict] = []
    submitted: list[str] = []

    def fake_send(_client, _signers, _ixs, _payer, label, ticket=None, rpc_url=None):
        submitted.append(label)
        raise settlement.SettlementSubmitError("timed out", signature="SiG",
                                               outcome="unconfirmed", ticket=ticket)

    monkeypatch.setattr(settlement, "Client", lambda *_a, **_k: object())
    monkeypatch.setattr(settlement, "_send", fake_send)

    def record(t):
        assert not submitted, "the ticket must be handed over BEFORE the transaction is submitted"
        seen.append(t)

    with pytest.raises(settlement.SettlementSubmitError) as ei:
        settlement.deposit("http://127.0.0.1:1", DEPOSITOR, RECIPIENT.pubkey(), AMOUNT,
                           on_ticket=record)

    assert seen, "the caller never received the claim ticket"
    assert len(bytes.fromhex(seen[0]["escrow_id"])) == 32
    assert len(bytes.fromhex(seen[0]["salt"])) == 16
    assert ei.value.ticket == seen[0], "the raised error must carry the ticket too"


def test_settle_create_returns_the_ticket_when_confirmation_times_out(server_mod, monkeypatch):
    monkeypatch.setattr(server_mod, "load_or_create_identity",
                        lambda _p: SimpleNamespace(ed_seed=bytes([1] * 32),
                                                   pubkey_b58=str(DEPOSITOR.pubkey())))
    ticket = {"escrow_id": ESCROW_ID.hex(), "salt": SALT.hex(), "pda": "pda", "program": "prog"}

    def fake_deposit(_url, _dep, _rec, _lam, on_ticket=None):
        on_ticket(dict(ticket))
        raise settlement.SettlementSubmitError("not confirmed within 90s", signature="SiG",
                                               outcome="unconfirmed", ticket=dict(ticket))

    monkeypatch.setattr(settlement, "deposit", fake_deposit)
    out = json.loads(server_mod.xete_settle_create(str(RECIPIENT.pubkey()), 1.0))
    assert out["status"] == "submitted_unconfirmed"
    assert out["ticket"]["escrow_id"] == ESCROW_ID.hex()
    assert out["ticket"]["salt"] == SALT.hex()
    assert out["tx_signature"] == "SiG"
    assert "xete_settle_status" in out["next_step"]


def test_settle_create_returns_the_ticket_even_on_an_unexpected_error(server_mod, monkeypatch):
    monkeypatch.setattr(server_mod, "load_or_create_identity",
                        lambda _p: SimpleNamespace(ed_seed=bytes([1] * 32),
                                                   pubkey_b58=str(DEPOSITOR.pubkey())))

    def fake_deposit(_url, _dep, _rec, _lam, on_ticket=None):
        on_ticket({"escrow_id": ESCROW_ID.hex(), "salt": SALT.hex()})
        raise RuntimeError("connection reset by peer")

    monkeypatch.setattr(settlement, "deposit", fake_deposit)
    out = json.loads(server_mod.xete_settle_create(str(RECIPIENT.pubkey()), 1.0))
    assert out["ticket"]["salt"] == SALT.hex()


# ══════════════════════════════════════════════════════════════════════════════════════
# SECOND ADVERSARIAL PASS — findings [15]-[25]
#
# Everything below was reproduced against the code as it stood before the accompanying
# fix, and each test fails without it. Still offline: no network, no mainnet, no wallet.
# ══════════════════════════════════════════════════════════════════════════════════════

from solders.address_lookup_table_account import AddressLookupTableAccount   # noqa: E402
from solders.instruction import CompiledInstruction                          # noqa: E402
from solders.message import MessageV0                                        # noqa: E402
from solders.transaction import VersionedTransaction                         # noqa: E402

from xete_mcp import alias_chain                                             # noqa: E402

SYSTEM_PROGRAM = settlement.SYS


class _Chain(dict):
    """What each RPC endpoint claims the %alias registry says.

    `chain["bob"] = wallet` is what every endpoint answers. `chain.at(url)["bob"] = other` makes
    ONE endpoint lie while the others stay honest — which is the whole adversary for finding
    [15] round 2 and cannot be expressed at all if the fixture models "the chain" as a single
    dict. `chain.calls` records (name, rpc) so a test can prove WHICH endpoint was asked.
    """

    def __init__(self):
        super().__init__()
        self.per_endpoint: dict[str, dict] = {}
        self.calls: list[tuple[str, str | None]] = []

    def at(self, url: str) -> dict:
        return self.per_endpoint.setdefault(url, {})

    def answer(self, name: str, rpc: str | None):
        self.calls.append((name, rpc))
        table = self.per_endpoint.get(rpc, {})
        return table[name] if name in table else self.get(name)


@pytest.fixture()
def chain(monkeypatch):
    """Control what each endpoint says the %alias registry holds, and fail the test if anything
    reaches the permit server over HTTP — asking a server who owns a name is the bug.

    ROUND-2 REBUILD. The old fixture patched `alias_chain.resolve_owner` with a function that
    ignored its `rpc` argument, so every endpoint agreed by construction and the tests could not
    see the tautology the reviewer demonstrated: draft and verify asking the SAME oracle. It now
    answers per endpoint, so a hostile RPC is expressible.
    """
    from xete_mcp import server as server_mod

    state = _Chain()
    state["bob"] = None

    def fake_resolve(name, rpc=None):
        owner = state.answer(alias_chain.normalize_name(name), rpc)
        if isinstance(owner, Exception):
            raise owner
        return owner

    def no_http(*_a, **_k):
        # A distinctive marker rather than a bare AssertionError: the settlement tools wrap
        # themselves in `except Exception`, so an assertion raised in here is swallowed into a
        # generic "failed" that looks identical to a correct chain-side refusal. Tests assert on
        # the marker's ABSENCE to prove the permit server was genuinely never consulted.
        raise RuntimeError("PERMIT_SERVER_WAS_ASKED — a %alias must be resolved on chain")

    monkeypatch.setattr(alias_chain, "resolve_owner", fake_resolve)
    monkeypatch.setattr(server_mod, "requests", SimpleNamespace(get=no_http, post=no_http))
    return state


ONE_RPC = "https://only-endpoint.example"
RPC_A = "https://endpoint-a.example"
RPC_B = "https://endpoint-b.example"


@pytest.fixture()
def drafting(monkeypatch, server_mod):
    """A configured depositor wallet, an RPC that only ever hands out a blockhash, and — by
    default — exactly ONE %alias endpoint.

    One endpoint is the deliberate default: it is the configuration in which a %name cannot be
    verified independently, and every test that wants an alias-based verification to succeed has
    to say so by asking for `two_endpoints`. The old fixture left this implicit, which is how a
    single-oracle verifier passed its own test suite.
    """
    class _C:
        def __init__(self, *_a, **_k):
            pass

        def get_latest_blockhash(self):
            return SimpleNamespace(value=SimpleNamespace(blockhash=Hash.default()))

    monkeypatch.setattr(server_mod, "DEPOSITOR_WALLET", str(DEPOSITOR.pubkey()))
    monkeypatch.setattr(server_mod, "NONCE_ACCOUNT", "")
    monkeypatch.setattr(server_mod, "NONCE_AUTHORITY", "")
    monkeypatch.setattr(server_mod, "RPC_URL", ONE_RPC)
    monkeypatch.setattr(draft, "Client", _C)
    monkeypatch.setenv("XETE_ALIAS_RPC", ONE_RPC)
    monkeypatch.setattr(alias_chain, "DEFAULT_RPC", ONE_RPC)
    monkeypatch.delenv("XETE_SOLANA_RPC", raising=False)
    monkeypatch.delenv("XETE_RPC_URL", raising=False)
    return server_mod


@pytest.fixture()
def two_endpoints(monkeypatch, drafting):
    """An operator who configured two independently-run Solana endpoints."""
    monkeypatch.setenv("XETE_ALIAS_RPC", f"{RPC_A},{RPC_B}")
    return drafting


# ── [15] a hostile permit server chose the recipient, and the verifier agreed ─────────

def test_a_lying_permit_server_can_no_longer_choose_who_gets_paid(chain, drafting):
    """THE finding, end to end. A permit server returning an attacker pubkey used to make
    xete_draft_settlement_tx build a 1 SOL deposit naming the attacker, and
    xete_verify_settlement_tx then returned verified=true / 'SAFE TO REVIEW AND SIGN' with zero
    failed checks — because the 'independent' recipient it compared against came from the same
    server. The registry is on chain; the server is not asked at all any more."""
    chain["bob"] = str(RECIPIENT.pubkey())        # the truth, on chain
    out = json.loads(drafting.xete_draft_settlement_tx("%bob", 1.0))
    assert out["status"] == "drafted", out
    assert out["recipient_wallet"] == str(RECIPIENT.pubkey())
    assert str(ATTACKER.pubkey()) not in json.dumps(out)


def test_the_draft_does_not_prefill_the_verifier_with_its_own_answer(chain, drafting):
    """`verify_with.expect_recipient` used to be d.recipient — the draft's own resolution copied
    forward, so the verifier re-derived the commitment from the wallet that built it and agreed
    with itself. The commitment check was tautological."""
    chain["bob"] = str(RECIPIENT.pubkey())
    out = json.loads(drafting.xete_draft_settlement_tx("%bob", 1.0))
    prefilled = out["verify_with"]["expect_recipient"]
    assert prefilled != out["recipient_wallet"], "the verifier is being fed the draft's own answer"
    assert prefilled != str(RECIPIENT.pubkey())
    assert "SUPPLY THIS YOURSELF" in prefilled


def test_verification_uses_the_chain_not_the_draft(chain, two_endpoints):
    """An attacker-built draft paying ATTACKER, verified against %bob, must fail — the registry
    says %bob is RECIPIENT and the commitment cannot match.

    Round 2: now runs on `two_endpoints`, because with one endpoint the tool refuses the %name
    outright and this check never gets to fire. The property is unchanged; the configuration it
    needs is now explicit."""
    chain["bob"] = str(RECIPIENT.pubkey())
    evil = _tx_b64([settlement._cb_limit(60_000), settlement._cb_price(1_000),
                    _deposit_ix(recipient=ATTACKER.pubkey())])
    v = json.loads(two_endpoints.xete_verify_settlement_tx(evil, "%bob", SALT.hex(), 1.0))
    assert v["verified"] is False
    assert "recipient_commitment" in v["failed_checks"]
    assert v["recipient_checked"] == str(RECIPIENT.pubkey())
    assert "SAFE TO REVIEW AND SIGN" not in json.dumps(v)


def test_an_unreadable_chain_fails_closed_instead_of_falling_back_to_a_server(chain, two_endpoints):
    """A chain read that fails must refuse, not quietly ask the permit server instead — that
    fallback is how a hostile server gets to answer whenever it can also cause a timeout.

    Round 2: `two_endpoints`, so the verify half genuinely exercises the chain-error path
    instead of being short-circuited by the single-endpoint refusal."""
    chain["bob"] = alias_chain.AliasChainError("RPC timed out")
    out = json.loads(two_endpoints.xete_draft_settlement_tx("%bob", 1.0))
    assert out["status"] == "failed"
    assert "PERMIT_SERVER_WAS_ASKED" not in out["error"]
    assert "RPC timed out" in out["error"]
    v = json.loads(two_endpoints.xete_verify_settlement_tx(_honest(), "%bob", SALT.hex(), 1.0))
    assert v["verified"] is False
    assert "RPC timed out" in json.dumps(v)
    assert "PERMIT_SERVER_WAS_ASKED" not in json.dumps(v)


def test_an_unregistered_name_is_refused_not_guessed(chain, drafting):
    chain["bob"] = None
    out = json.loads(drafting.xete_draft_settlement_tx("%bob", 1.0))
    assert out["status"] == "failed"
    assert "no registration" in out["error"] or "not registered" in out["error"]


def test_a_raw_wallet_recipient_never_touches_the_registry(chain, drafting):
    """Non-regression guard, not a finding: a base58 wallet must keep short-circuiting both the
    registry and the permit server. Passes before and after the fix, by design — it exists so
    routing %alias resolution through the chain cannot quietly start a lookup for raw wallets."""
    out = json.loads(drafting.xete_draft_settlement_tx(str(RECIPIENT.pubkey()), 1.0))
    assert out["status"] == "drafted"
    assert out["recipient_wallet"] == str(RECIPIENT.pubkey())


# ── [16] claim and reclaim assert failure on a transaction that may well land ─────────

def _identity(monkeypatch, server_mod):
    monkeypatch.setattr(server_mod, "load_or_create_identity",
                        lambda _p: SimpleNamespace(ed_seed=bytes([1] * 32),
                                                   pubkey_b58=str(DEPOSITOR.pubkey())))


@pytest.mark.parametrize("tool,fn", [("xete_settle_claim", "claim"),
                                     ("xete_settle_reclaim", "reclaim")])
def test_claim_and_reclaim_do_not_report_failure_on_a_submission_that_may_land(
        server_mod, monkeypatch, tool, fn):
    """D4's whole premise applied to the other two tools. Reporting 'failed' here tells the agent
    it was not paid (claim) or that its funds are still locked (reclaim) for a transaction the
    cluster may still confirm — and throws away the signature needed to find out."""
    _identity(monkeypatch, server_mod)

    def timeout(*_a, **_k):
        raise settlement.SettlementSubmitError(
            f"{fn} not confirmed within 90s — it MAY STILL LAND", signature="SiGnAtUrE",
            outcome="unconfirmed")

    monkeypatch.setattr(settlement, fn, timeout)
    args = (ESCROW_ID.hex(), SALT.hex()) if fn == "claim" else (ESCROW_ID.hex(),)
    out = json.loads(getattr(server_mod, tool)(*args))

    assert out["status"] == "submitted_unconfirmed", "'failed' asserts an outcome we do not know"
    assert out["submit_outcome"] == "unconfirmed"
    assert out["tx_signature"] == "SiGnAtUrE", "the signature is how the agent resolves this"
    assert "xete_settle_status" in out["next_step"]


@pytest.mark.parametrize("tool,fn", [("xete_settle_claim", "claim"),
                                     ("xete_settle_reclaim", "reclaim")])
def test_a_definitely_dropped_claim_is_still_reported_as_failed_with_its_signature(
        server_mod, monkeypatch, tool, fn):
    """'dropped' and 'failed' ARE knowable failures — those must keep saying failed, or the fix
    would just move the lie to the other side."""
    _identity(monkeypatch, server_mod)

    def dropped(*_a, **_k):
        raise settlement.SettlementSubmitError("blockhash expired", signature="SiG",
                                               outcome="dropped")

    monkeypatch.setattr(settlement, fn, dropped)
    args = (ESCROW_ID.hex(), SALT.hex()) if fn == "claim" else (ESCROW_ID.hex(),)
    out = json.loads(getattr(server_mod, tool)(*args))
    assert out["status"] == "failed"
    assert out["submit_outcome"] == "dropped"
    assert out["tx_signature"] == "SiG"


# ── [17] a non-escrow account reported open:true in the field agents branch on ────────

@pytest.mark.parametrize("n", [0, 12, 41, 80, 82, 200])
def test_an_account_that_is_not_an_escrow_is_not_reported_as_open(monkeypatch, n):
    """`open` is the machine-readable answer, and xete_settle_create's own timeout guidance
    names it as the 'did my deposit land' signal. Anyone can pay the rent minimum to create a
    0-data account at a known PDA; before this it read back as {open: true}.

    CALIBRATION CHANGE, round 2: `is False` -> `is not True`. The property this test defends is
    "an account that is not a decodable escrow must not be reported as an open escrow", and that
    is asserted exactly as before. What changed is that the round-1 fix expressed it as
    open=False, which the tools' own guidance reads as "settled — discard your ticket" (finding
    [17], round 2). The answer is now the third state, and `determinate is False` is asserted
    here so the test fails if anything ever collapses it back to a boolean."""
    monkeypatch.setattr(settlement, "Client", _account_client(b"\x00" * n))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex())
    assert out["open"] is not True, f"a {n}-byte account is not an open escrow"
    assert out["determinate"] is False, "nor is it a determinate 'no' — see finding [17]"
    assert out["is_escrow"] is False
    assert out["commitment"] is None
    assert out["beneficiary_verified"] is None


def test_a_real_escrow_is_still_reported_open(monkeypatch):
    mine = settlement.commitment(RECIPIENT.pubkey(), SALT)
    monkeypatch.setattr(settlement, "Client",
                        _account_client(_state(DEPOSITOR.pubkey(), AMOUNT, mine)))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex())
    assert out["open"] is True and out["is_escrow"] is True
    assert out["amount_lamports"] == AMOUNT


# ── [18] the commitment was compared against unauthenticated, unowned bytes ───────────

def test_a_foreign_account_at_the_pda_is_not_a_verified_escrow(monkeypatch):
    """RENAMED, round 2. It was `test_a_hostile_rpc_cannot_forge_a_verified_escrow`, and that
    name claimed something the code cannot do: the only adversary it models is an endpoint that
    volunteers the WRONG owner (SYSTEM_PROGRAM), and a hostile endpoint has no reason to. What
    the owner check really stops is a stale or buggy endpoint, a mis-set XETE_SETTLEMENT_PROGRAM,
    and an unrelated account genuinely squatting the PDA — all real, none hostile. The hostile
    case is `test_an_endpoint_that_forges_the_owner_field_is_caught_by_the_second_endpoint`.

    Perfectly-formed 81 bytes whose commitment matches, at an account the settlement program does
    not own: this used to return beneficiary_verified=True and 'VERIFIED'."""
    mine = settlement.commitment(RECIPIENT.pubkey(), SALT)
    forged = _state(ATTACKER.pubkey(), 5_000_000_000, mine)
    monkeypatch.setattr(settlement, "Client",
                        _account_client(forged, owner=SYSTEM_PROGRAM))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex(),
                            expect_commitment_hex=mine.hex())
    assert out["beneficiary_verified"] is not True
    assert out["open"] is not True and out["is_escrow"] is False
    assert out["determinate"] is False, "an owner we cannot match is not a determinate 'settled'"
    assert "VERIFIED" not in out["verdict"]
    assert "depositor" not in out, "no field may be read out of an account this program does not own"


def test_an_rpc_that_omits_the_owner_fails_closed(monkeypatch):
    """No owner field at all is not a pass. Fail closed — and, since round 2, fail INDETERMINATE
    rather than fail 'settled': an endpoint too old to report an owner tells you nothing about
    whether your money is sitting there."""
    mine = settlement.commitment(RECIPIENT.pubkey(), SALT)

    class _C:
        def __init__(self, *_a, **_k):
            pass

        def get_account_info(self, _pda, commitment=None):
            return SimpleNamespace(value=SimpleNamespace(
                data=_state(DEPOSITOR.pubkey(), AMOUNT, mine), lamports=1))

    monkeypatch.setattr(settlement, "Client", _C)
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex(),
                            expect_commitment_hex=mine.hex())
    assert out["open"] is not True
    assert out["determinate"] is False
    assert out["beneficiary_verified"] is not True


def test_the_owner_field_is_surfaced_as_the_endpoints_claim(monkeypatch):
    """Surfaced so a human can see what answered — but it is the endpoint's own claim about
    itself, and round 2 stopped pretending otherwise anywhere in the output."""
    monkeypatch.setattr(settlement, "Client",
                        _account_client(b"\x00" * 81, owner=SYSTEM_PROGRAM))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex())
    assert out["account_owner"] == str(SYSTEM_PROGRAM)


# ── [25b] the raw, unnormalised escrow_id was echoed back ─────────────────────────────

def test_status_echoes_the_canonical_escrow_id_not_the_raw_input(monkeypatch):
    monkeypatch.setattr(settlement, "Client", _account_client(None))
    out = settlement.status("http://127.0.0.1:1", "  " + ESCROW_ID.hex().upper() + "  ")
    assert out["escrow_id"] == ESCROW_ID.hex(), \
        "a caller string-comparing this against their ticket gets a spurious mismatch"


# ── [19] the confirmation budget was a poll count and the RPC picked the multiplier ───

class _LatentClient(_SendClient):
    """An RPC whose round trip costs real time on the same clock _send is watching."""

    def __init__(self, latency, clock, statuses=(None,)):
        super().__init__(list(statuses))
        self.latency = latency
        self.clock = clock

    def get_signature_statuses(self, sigs):
        self.clock.advance(self.latency)
        return super().get_signature_statuses(sigs)


def test_the_confirmation_budget_is_a_wall_clock_not_a_poll_count(instant, monkeypatch):
    """`for i in range(int(budget / 0.3))` sleeps for `budget` seconds AND pays one RPC round
    trip per iteration, so the untrusted RPC sets the real duration. At the 90s default a 0.5s
    RPC blocked the agent's stdio session for 240s. The budget must bound the total."""
    monkeypatch.setenv(settlement.ENV_CONFIRM_SECONDS, "90")
    client = _LatentClient(0.5, instant)
    start = instant.monotonic()
    with pytest.raises(settlement.SettlementSubmitError):
        _send(client)
    elapsed = instant.monotonic() - start
    assert elapsed <= 90 * 1.05 + 0.5, f"90s budget took {elapsed:.0f}s of wall clock"
    assert client.polls > 5, "it must still actually poll"


def test_a_slow_rpc_costs_polls_not_extra_seconds(instant, monkeypatch):
    monkeypatch.setenv(settlement.ENV_CONFIRM_SECONDS, "10")
    fast, slow = _LatentClient(0.0, _Clock()), _LatentClient(2.0, _Clock())
    for c in (fast, slow):
        monkeypatch.setattr(settlement, "time", c.clock)
        t0 = c.clock.monotonic()
        with pytest.raises(settlement.SettlementSubmitError):
            _send(c)
        c.elapsed = c.clock.monotonic() - t0
    assert fast.elapsed <= 10.5 and slow.elapsed <= 10.5 + 2.0
    assert slow.polls < fast.polls, "a slow RPC must buy fewer polls, not more seconds"


# ── [20] a verified draft could fund a different escrow than the ticket names ─────────

def test_the_escrow_id_actually_funded_is_reported():
    r = _verify(_honest())
    assert r.ok, r.failures
    assert r.escrow_id_hex == ESCROW_ID.hex()
    named = [c for c in r.checks if c["name"] == "escrow_id"]
    assert named and ESCROW_ID.hex() in named[0]["actual"], \
        "the id the transaction funds must be visible to whoever holds the claim ticket"


def test_a_draft_that_funds_a_different_escrow_than_the_ticket_is_caught():
    """Not theft — the commitment still pins the beneficiary — but the recipient can never claim
    it, and the tool used to certify it SAFE."""
    other = bytes(Keypair.from_seed(bytes([11] * 32)).pubkey())
    r = _verify(_tx_b64([settlement._cb_limit(60_000), settlement._cb_price(1_000),
                         _deposit_ix(escrow_id=other)]),
                expect_escrow_id_hex=ESCROW_ID.hex())
    assert not r.ok
    assert "escrow_id" in r.failures


def test_the_matching_escrow_id_passes():
    r = _verify(_honest(), expect_escrow_id_hex=ESCROW_ID.hex().upper() + " ")
    assert r.ok, r.failures


def test_the_verify_tool_reports_and_checks_the_escrow_id(chain, drafting):
    other = bytes(Keypair.from_seed(bytes([11] * 32)).pubkey())
    tx = _tx_b64([settlement._cb_limit(60_000), settlement._cb_price(1_000),
                  _deposit_ix(escrow_id=other)])
    v = json.loads(drafting.xete_verify_settlement_tx(
        tx, str(RECIPIENT.pubkey()), SALT.hex(), 1.0, expect_escrow_id=ESCROW_ID.hex()))
    assert v["verified"] is False
    assert "escrow_id" in v["failed_checks"]
    assert v["escrow_id_funded"] == other.hex()


# ── [21] a v0 transaction is accepted by the legacy parser; only luck stopped it ──────

def _v0_tx_b64(with_alt=True):
    alt = AddressLookupTableAccount(key=Keypair.from_seed(bytes([5] * 32)).pubkey(),
                                    addresses=[ATTACKER.pubkey()])
    m = MessageV0.try_compile(DEPOSITOR.pubkey(), [_deposit_ix()],
                              [alt] if with_alt else [], Hash.default())
    return base64.b64encode(bytes(VersionedTransaction.populate(m, []))).decode()


def test_the_legacy_parser_really_does_accept_a_v0_transaction():
    """Documents the reviewed claim that was WRONG: from_bytes does not reject v0. It misreads
    the 0x80 version byte as num_required_signatures=128, which is the only reason the old code
    refused it — via the unrelated single_signer check."""
    raw = base64.b64decode(_v0_tx_b64())
    tx = Transaction.from_bytes(raw)
    assert tx.message.header.num_required_signatures == 128


def test_a_versioned_transaction_is_refused_on_its_own_terms():
    r = _verify(_v0_tx_b64())
    assert not r.ok
    assert "legacy_transaction" in r.failures


def test_the_versioned_refusal_does_not_lean_on_the_single_signer_check():
    """The load-bearing property: the refusal must come BEFORE, and independently of,
    single_signer — so relaxing single_signer (multisig depositor, separate fee payer) cannot
    silently reopen an address-lookup-table bypass of every program-id check in this module."""
    r = _verify(_v0_tx_b64())
    assert [c["name"] for c in r.checks] == ["legacy_transaction"]
    assert "single_signer" not in r.failures, \
        "the v0 refusal must not be a side effect of the signature-count check"


def test_message_version_reads_legacy_and_v0_correctly():
    assert draft._message_version(base64.b64decode(_honest())) is None
    assert draft._message_version(base64.b64decode(_v0_tx_b64())) == 0


def test_an_honest_legacy_draft_records_the_check_as_passing():
    r = _verify(_honest())
    assert r.ok
    assert any(c["name"] == "legacy_transaction" and c["ok"] for c in r.checks)


def test_a_v0_transaction_without_a_lookup_table_is_refused_too():
    """The refusal is on the version, not on whether an ALT happens to be attached."""
    r = _verify(_v0_tx_b64(with_alt=False))
    assert not r.ok
    assert "legacy_transaction" in r.failures


def test_a_signed_legacy_transaction_is_still_classified_legacy():
    """_message_version has to skip a populated signature array to find the message. If it
    misread a real signature's first byte as the version prefix, every signed transaction would
    be refused as 'versioned' — and the `unsigned` check would never get to fire."""
    msg = Message.new_with_blockhash(
        [settlement._cb_limit(60_000), settlement._cb_price(1_000), _deposit_ix()],
        DEPOSITOR.pubkey(), Hash.default())
    signed = bytes(Transaction([DEPOSITOR], msg, Hash.default()))
    assert draft._message_version(signed) is None
    r = _verify(base64.b64encode(signed).decode())
    assert not r.ok
    assert "unsigned" in r.failures, "a signed draft must fail as SIGNED, not as versioned"


def test_a_non_canonical_length_prefix_cannot_smuggle_a_message_past_the_version_check():
    """Parser-differential probe: `0x80 0x00` encodes a zero signature count in two bytes rather
    than one. If this module and solders disagreed about where the message starts, one of them
    could be reading the version byte from the wrong offset. solders refuses the non-strict
    encoding outright, so the pair fails closed."""
    raw = bytearray(base64.b64decode(_honest()))
    non_canonical = b"\x80\x00" + bytes(raw[1:])
    r = _verify(base64.b64encode(non_canonical).decode())
    assert not r.ok
    assert "deserialize" in r.failures


@pytest.mark.parametrize("blob", [b"", b"\x01", b"\x02", b"\x80"])
def test_truncated_input_returns_a_result_instead_of_raising(blob):
    """_message_version is hand-rolled byte parsing on attacker-supplied input; it must not be a
    new way to throw out of verify_draft."""
    r = _verify(base64.b64encode(blob).decode())
    assert isinstance(r, draft.VerifyResult)
    assert not r.ok
    assert "deserialize" in r.failures


# ── [22] the fee ceiling was a per-signature yield, not a theoretical bound ───────────

def test_the_tuned_fee_bomb_that_used_to_report_safe_is_refused():
    """1_400_000 CU x 710_714 micro-lamports/CU = exactly 1_000_000 lamports, which cleared the
    old 0.001 SOL cap and returned 'SAFE TO REVIEW AND SIGN'. 198x the honest 5_060, extractable
    on every draft a human signs."""
    r = _verify(_honest(limit=1_400_000, price=710_714))
    assert r.fee_lamports == 1_000_000
    assert not r.ok
    assert "max_transaction_fee" in r.failures


def test_the_ceiling_is_within_an_order_of_magnitude_of_the_honest_cost():
    assert draft.HONEST_TX_FEE_LAMPORTS == 5_060
    assert draft.MAX_TX_FEE_LAMPORTS <= draft.HONEST_TX_FEE_LAMPORTS * 10


def test_a_congested_but_honest_priority_fee_still_passes():
    """200_000 CU at 50_000 micro-lamports/CU = 10_000 priority + 5_000 base. Real congestion
    must not be refused by the tightened cap. Passes before and after by design — it is the
    over-tightening guard that stops the [22] fix from being "set the ceiling to zero"."""
    r = _verify(_honest(limit=200_000, price=50_000))
    assert r.ok, r.failures
    assert r.fee_lamports == 15_000


# ── [23] IndexError escaped verify_draft ──────────────────────────────────────────────

def _out_of_range_index_tx() -> str:
    tx = Transaction.from_bytes(base64.b64decode(_honest()))
    keys = list(tx.message.account_keys)
    cixs = []
    for c in tx.message.instructions:
        if keys[c.program_id_index] == settlement.program_id():
            cixs.append(CompiledInstruction(program_id_index=c.program_id_index,
                                            data=bytes(c.data), accounts=bytes([200, 1, 2])))
        else:
            cixs.append(c)
    h = tx.message.header
    m = Message.new_with_compiled_instructions(
        num_required_signatures=h.num_required_signatures,
        num_readonly_signed_accounts=h.num_readonly_signed_accounts,
        num_readonly_unsigned_accounts=h.num_readonly_unsigned_accounts,
        account_keys=keys, recent_blockhash=Hash.default(), instructions=cixs)
    return base64.b64encode(bytes(Transaction.new_unsigned(m))).decode()


def test_from_bytes_does_not_sanitise_account_indices():
    """The premise of the bug, pinned so a solders upgrade that changes it is noticed."""
    tx = Transaction.from_bytes(base64.b64decode(_out_of_range_index_tx()))
    assert any(200 in list(c.accounts) for c in tx.message.instructions)


def test_an_out_of_range_account_index_returns_a_result_instead_of_raising():
    """verify_draft's contract is that it always returns a VerifyResult. An unguarded
    keys[i] broke that for any caller not wrapped in a bare except."""
    r = _verify(_out_of_range_index_tx())
    assert isinstance(r, draft.VerifyResult)
    assert not r.ok


def test_the_out_of_range_index_is_surfaced_not_silently_dropped():
    """Filtering the bad index out would SHIFT every account after it, so `from`/`to` in the
    movement list would name the wrong wallets to the human reading it. Refuse and say why."""
    r = _verify(_out_of_range_index_tx())
    blob = _blob(r)
    assert "200" in blob and "malformed" in blob
    assert "deposit_instruction_present" in r.failures


def test_an_out_of_range_index_on_a_non_deposit_instruction_is_also_refused():
    """The same unguarded shape exists in _lamport_movements, on every OTHER instruction. There
    the old code filtered silently, which is the shift-the-accounts failure above."""
    tx = Transaction.from_bytes(base64.b64decode(_honest()))
    keys = list(tx.message.account_keys)
    cixs = list(tx.message.instructions)
    cixs.append(CompiledInstruction(
        program_id_index=[i for i, k in enumerate(keys) if k == settlement.SYS][0],
        data=struct.pack("<I", 2) + struct.pack("<Q", DRAIN), accounts=bytes([0, 201])))
    h = tx.message.header
    m = Message.new_with_compiled_instructions(
        num_required_signatures=h.num_required_signatures,
        num_readonly_signed_accounts=h.num_readonly_signed_accounts,
        num_readonly_unsigned_accounts=h.num_readonly_unsigned_accounts,
        account_keys=keys, recent_blockhash=Hash.default(), instructions=cixs)
    r = _verify(base64.b64encode(bytes(Transaction.new_unsigned(m))).decode())
    assert isinstance(r, draft.VerifyResult)
    assert not r.ok
    assert "every_instruction_decoded" in r.failures
    assert "out of range" in _blob(r)


# ── [24] the report told a signer the deposit was the whole debit ─────────────────────

def test_the_report_says_rent_and_fees_are_charged_on_top():
    r = _verify(_honest())
    assert r.ok
    total = [c for c in r.checks if c["name"] == "total_lamport_movement"][0]
    assert "NOT the whole debit" in total["expected"]
    extra = [c for c in r.checks if c["name"] == "additional_charges_at_execution"]
    assert extra, "rent and fees must be stated where the signer reads, not only in a review"
    assert str(draft.ESCROW_RENT_LAMPORTS) in extra[0]["actual"]
    assert draft.ESCROW_RENT_LAMPORTS == 1_454_640


# ── [25a] half a claim ticket verified nothing, silently ──────────────────────────────

@pytest.mark.parametrize("kwargs", [
    {"expect_recipient": str(RECIPIENT.pubkey())},
    {"salt": SALT.hex()},
])
def test_half_a_claim_ticket_says_plainly_that_nothing_was_verified(server_mod, monkeypatch,
                                                                    kwargs):
    c = settlement.commitment(ATTACKER.pubkey(), SALT)
    monkeypatch.setattr(settlement, "Client", _account_client(_state(ATTACKER.pubkey(), AMOUNT, c)))
    out = json.loads(server_mod.xete_settle_status(ESCROW_ID.hex(), **kwargs))
    assert out["beneficiary_verified"] is None
    assert "WARNING_NOTHING_WAS_VERIFIED" in out, \
        "a caller who passed their own wallet reads a clean response as confirmation"


# ══════════════════════════════════════════════════════════════════════════════════════
# THIRD ADVERSARIAL PASS — the repair round.
#
# Three reviewers attacked the fixes above and DEMONSTRATED that [15], [17], [18] and
# half of [16] were still open, plus three smaller defects. Every test below was run
# against the code as it stood at dd03750 and fails there. Still offline.
# ══════════════════════════════════════════════════════════════════════════════════════


# ── [15] round 2: the tautology moved to the RPC; the operator could not escape it ────

def test_the_operators_own_endpoint_is_used_for_money_path_resolution(chain, monkeypatch,
                                                                      server_mod):
    """`resolve_owner` was called with no endpoint at all, so alias_chain picked one from
    XETE_SOLANA_RPC or a hard-coded third party. An operator running their own validator — the
    one party with an actual reason to be trusted about where their money goes — had no way to
    put it on the money path. XETE_RPC_URL now counts, and the endpoint is passed explicitly."""
    monkeypatch.setenv("XETE_RPC_URL", "https://my-private-validator.example")
    monkeypatch.delenv("XETE_ALIAS_RPC", raising=False)
    monkeypatch.delenv("XETE_SOLANA_RPC", raising=False)
    chain["bob"] = str(RECIPIENT.pubkey())

    server_mod._resolve_recipient_wallet("%bob")

    asked = [rpc for _n, rpc in chain.calls]
    assert asked == ["https://my-private-validator.example"], \
        f"the operator's endpoint was not the one asked; got {asked}"
    assert server_mod.alias_rpc_endpoints()[0] == "https://my-private-validator.example"


def test_a_single_endpoint_cannot_both_build_and_certify_a_payment(chain, drafting):
    """THE finding, end to end, verbatim from the reviewer's a1.py.

    One hostile endpoint answers %bob -> ATTACKER. The draft builds a 1 SOL deposit to the
    attacker; the human, holding only the payee's NAME (the thing a human actually has, and what
    the tool's own docstring invites), verifies against '%bob'. Before this fix the verifier
    asked that same endpoint, re-derived the same commitment, and returned
    `verified: true / SAFE TO REVIEW AND SIGN / total_sol_out: 1.0` — the original permit-server
    finding, one layer down. The verifier must not accept a name it can only resolve through the
    endpoint that built the draft."""
    chain.at(ONE_RPC)["bob"] = str(ATTACKER.pubkey())

    d = json.loads(drafting.xete_draft_settlement_tx("%bob", 1.0))
    assert d["status"] == "drafted"
    assert d["recipient_wallet"] == str(ATTACKER.pubkey())      # the hostile endpoint got its way

    v = json.loads(drafting.xete_verify_settlement_tx(
        d["unsigned_tx_b64"], "%bob", d["ticket"]["salt"], 1.0))
    assert v["verified"] is False, "one endpoint certified a payment it chose itself"
    assert "SAFE TO REVIEW AND SIGN" not in json.dumps(v)
    # A refusal with no way forward is how a human ends up reaching for the tool that says yes.
    # The remediation must survive the tool's error truncation, so it is asserted, not assumed.
    assert "base58" in json.dumps(v).lower(), "the refusal must say how to proceed safely"
    assert "XETE_ALIAS_RPC" in json.dumps(v)


def test_a_hostile_endpoint_is_outvoted_by_the_second_one(chain, two_endpoints):
    """The same attack against a two-endpoint operator: endpoint A lies, endpoint B does not.
    The disagreement itself is the signal — the tool does not have to know which one lied."""
    chain["bob"] = str(RECIPIENT.pubkey())
    chain.at(RPC_A)["bob"] = str(ATTACKER.pubkey())

    evil = _tx_b64([settlement._cb_limit(60_000), settlement._cb_price(1_000),
                    _deposit_ix(recipient=ATTACKER.pubkey())])
    v = json.loads(two_endpoints.xete_verify_settlement_tx(evil, "%bob", SALT.hex(), 1.0))
    assert v["verified"] is False
    assert "resolves DIFFERENTLY" in json.dumps(v)
    assert str(ATTACKER.pubkey()) in json.dumps(v) and str(RECIPIENT.pubkey()) in json.dumps(v)


def test_two_agreeing_endpoints_let_an_honest_name_verify(chain, two_endpoints):
    """The over-refusal guard: the fix must not be 'never accept a %name'. Two endpoints that
    agree on an honest draft still produce SAFE TO REVIEW AND SIGN."""
    chain["bob"] = str(RECIPIENT.pubkey())
    v = json.loads(two_endpoints.xete_verify_settlement_tx(
        _honest(), "%bob", SALT.hex(), 1.0, expect_escrow_id=ESCROW_ID.hex()))
    assert v["verified"] is True, v["failed_checks"]
    assert v["recipient_checked"] == str(RECIPIENT.pubkey())
    assert RPC_A in v["recipient_resolved_from"] and RPC_B in v["recipient_resolved_from"]


def test_both_endpoints_are_actually_asked(chain, two_endpoints):
    """Guards against the fix being cosmetic — two configured endpoints, one consulted."""
    chain["bob"] = str(RECIPIENT.pubkey())
    json.loads(two_endpoints.xete_verify_settlement_tx(_honest(), "%bob", SALT.hex(), 1.0))
    asked = {rpc for name, rpc in chain.calls if name == "bob"}
    assert asked == {RPC_A, RPC_B}, f"only {asked} were consulted"


def test_the_verifier_never_claims_the_chain_answered(chain, two_endpoints, drafting):
    """`recipient_resolved_from: the on-chain %alias registry` was an authenticity claim nothing
    in the answer could back — the bytes came from whichever URL was configured. Say which
    endpoint answered, or say nothing."""
    chain["bob"] = str(RECIPIENT.pubkey())
    v = json.loads(two_endpoints.xete_verify_settlement_tx(_honest(), "%bob", SALT.hex(), 1.0))
    assert v["recipient_resolved_from"] != "the on-chain %alias registry"
    assert "endpoint" in v["recipient_resolved_from"].lower()

    raw = json.loads(two_endpoints.xete_verify_settlement_tx(
        _honest(), str(RECIPIENT.pubkey()), SALT.hex(), 1.0))
    assert "nothing was resolved" in raw["recipient_resolved_from"]


def test_a_raw_wallet_still_verifies_with_a_single_endpoint(chain, drafting):
    """Non-regression, and the escape hatch the refusal points at: a base58 wallet involves no
    oracle at all, so one endpoint is irrelevant to it."""
    v = json.loads(drafting.xete_verify_settlement_tx(
        _honest(), str(RECIPIENT.pubkey()), SALT.hex(), 1.0, expect_escrow_id=ESCROW_ID.hex()))
    assert v["verified"] is True, v["failed_checks"]
    assert not [c for c in chain.calls], "a raw wallet must not touch the registry at all"


def test_listing_the_same_endpoint_twice_does_not_manufacture_agreement(chain, drafting,
                                                                        monkeypatch):
    """The trivial bypass of a two-source rule."""
    monkeypatch.setenv("XETE_ALIAS_RPC", f"{ONE_RPC},{ONE_RPC}")
    chain.at(ONE_RPC)["bob"] = str(ATTACKER.pubkey())
    v = json.loads(drafting.xete_verify_settlement_tx(_honest(), "%bob", SALT.hex(), 1.0))
    assert v["verified"] is False
    assert "only one Solana endpoint" in json.dumps(v)


# ── [15] round 2, tail: confusable Unicode reached the money path ─────────────────────

@pytest.mark.parametrize("name", [
    "%jo​hn",          # zero-width space
    "%jоhn",           # Cyrillic o
    "%jo‮hn",          # right-to-left override
    "%јohn",           # Cyrillic je
])
def test_a_confusable_name_is_refused_on_the_money_path(chain, drafting, name):
    """`%john` and these render identically in an agent transcript and in a human's approval
    prompt, but derive DIFFERENT registry PDAs. A chain-authoritative resolution of the wrong
    name is still the wrong name — authoritative is not the same as unambiguous. Refused, not
    folded together: folding would make two separately-registrable on-chain names resolve to one
    wallet, which is the same bug pointing the other way."""
    chain["john"] = str(RECIPIENT.pubkey())
    out = json.loads(drafting.xete_draft_settlement_tx(name, 1.0))
    assert out["status"] == "failed"
    assert "ASCII" in out["error"]
    assert not chain.calls, "a confusable name must be refused before any lookup"


def test_a_plain_ascii_name_is_unaffected(chain, drafting):
    """The over-refusal guard for the check above."""
    chain["john"] = str(RECIPIENT.pubkey())
    out = json.loads(drafting.xete_draft_settlement_tx("%john", 1.0))
    assert out["status"] == "drafted"
    assert out["recipient_wallet"] == str(RECIPIENT.pubkey())


# ── [18] round 2: `owner` is a field the hostile endpoint controls ────────────────────

def _two_endpoint_client(answers: dict):
    """A fake Client dispatching on URL: {url: (data|None, owner)}."""
    class _C:
        def __init__(self, url, *_a, **_k):
            self.url = url

        def get_account_info(self, _pda, commitment=None):
            data, owner = answers[self.url]
            if data is None:
                return SimpleNamespace(value=None)
            return SimpleNamespace(value=SimpleNamespace(data=data, lamports=5_000_000_000,
                                                         owner=owner))
    return _C


def test_an_endpoint_that_forges_the_owner_field_is_caught_by_the_second_endpoint(monkeypatch):
    """THE finding. The round-1 fix required `info.owner == program_id()` and its test only
    modelled an endpoint volunteering the WRONG owner — an adversary with no reason to exist. A
    hostile endpoint writes the settlement program into the field it controls and everything
    downstream believes it: the reviewer got `open True / beneficiary_verified True / VERIFIED`
    for an escrow that does not exist. Nothing in one JSON document can fix that; a second
    endpoint that has to agree can."""
    mine = settlement.commitment(RECIPIENT.pubkey(), SALT)
    forged = _state(ATTACKER.pubkey(), 5_000_000_000, mine)
    prog = settlement.program_id()
    monkeypatch.setattr(settlement, "Client", _two_endpoint_client({
        "https://hostile.example": (forged, prog),      # perfect forgery, correct owner
        "https://honest.example": (None, None),         # no such account
    }))
    out = settlement.status("https://hostile.example", ESCROW_ID.hex(),
                            expect_commitment_hex=mine.hex(),
                            second_rpc="https://honest.example")
    assert out["beneficiary_verified"] is not True
    assert out["open"] is None and out["determinate"] is False
    assert "ENDPOINTS DISAGREE" in out["verdict"]
    assert "VERIFIED" not in out["verdict"]


def test_a_single_endpoint_answer_does_not_claim_to_be_the_chain(monkeypatch):
    """With one source the honest answer is 'one endpoint says', because that is all it is."""
    mine = settlement.commitment(RECIPIENT.pubkey(), SALT)
    monkeypatch.setattr(settlement, "Client",
                        _account_client(_state(DEPOSITOR.pubkey(), AMOUNT, mine)))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex(),
                            expect_commitment_hex=mine.hex(), second_rpc="")
    assert out["beneficiary_verified"] is True
    assert out["corroborated"] is False
    assert not out["verdict"].startswith("VERIFIED")
    assert settlement.ENV_SECOND_RPC in out["verdict"], "say how to get a real answer"


def test_two_agreeing_endpoints_earn_the_verified_verdict(monkeypatch):
    """The over-refusal guard: corroboration must be reachable, not theoretical."""
    mine = settlement.commitment(RECIPIENT.pubkey(), SALT)
    real = _state(DEPOSITOR.pubkey(), AMOUNT, mine)
    prog = settlement.program_id()
    monkeypatch.setattr(settlement, "Client", _two_endpoint_client({
        "https://a.example": (real, prog),
        "https://b.example": (real, prog),
    }))
    out = settlement.status("https://a.example", ESCROW_ID.hex(),
                            expect_commitment_hex=mine.hex(), second_rpc="https://b.example")
    assert out["corroborated"] is True
    assert out["open"] is True and out["determinate"] is True
    assert out["verdict"].startswith("VERIFIED")


def test_the_second_endpoint_is_read_from_the_environment(monkeypatch):
    mine = settlement.commitment(RECIPIENT.pubkey(), SALT)
    real = _state(DEPOSITOR.pubkey(), AMOUNT, mine)
    prog = settlement.program_id()
    monkeypatch.setenv(settlement.ENV_SECOND_RPC, "https://b.example")
    monkeypatch.setattr(settlement, "Client", _two_endpoint_client({
        "https://a.example": (real, prog),
        "https://b.example": (real, prog),
    }))
    out = settlement.status("https://a.example", ESCROW_ID.hex(), expect_commitment_hex=mine.hex())
    assert out["corroborated"] is True
    assert out["endpoints_asked"] == ["https://a.example", "https://b.example"]


def test_the_same_endpoint_twice_is_not_two_sources(monkeypatch):
    monkeypatch.setenv(settlement.ENV_SECOND_RPC, "https://a.example")
    assert settlement.second_rpc_url("https://a.example") is None
    assert settlement.second_rpc_url("https://other.example") == "https://a.example"


def test_a_second_endpoint_that_errors_degrades_instead_of_failing(monkeypatch):
    """A corroborating endpoint that is down must cost confidence, not availability — the
    settlement is still readable, it just cannot be called corroborated."""
    mine = settlement.commitment(RECIPIENT.pubkey(), SALT)
    real = _state(DEPOSITOR.pubkey(), AMOUNT, mine)

    class _C:
        def __init__(self, url, *_a, **_k):
            self.url = url

        def get_account_info(self, _pda, commitment=None):
            if self.url == "https://down.example":
                raise RuntimeError("429 Too Many Requests")
            return SimpleNamespace(value=SimpleNamespace(
                data=real, lamports=1, owner=settlement.program_id()))

    monkeypatch.setattr(settlement, "Client", _C)
    out = settlement.status("https://a.example", ESCROW_ID.hex(),
                            expect_commitment_hex=mine.hex(), second_rpc="https://down.example")
    assert out["open"] is True and out["determinate"] is True
    assert out["corroborated"] is False
    assert "429" in out["second_endpoint_error"]
    assert not out["verdict"].startswith("VERIFIED")


# ── [17] round 2: open=False meant both "settled" and "I could not authenticate" ──────

def test_a_program_owned_escrow_of_an_unexpected_length_is_indeterminate(monkeypatch):
    """THE finding's money path. A real, funded, genuinely-open escrow whose layout is not
    STATE_LEN read back as open=False — and xete_settle_create's timeout guidance says a
    settlement that is not open means 'the deposit did not happen and your funds never left'.
    The agent follows that, discards the only copy of the salt, and the deposit becomes
    unclaimable by anyone, forever."""
    mine = settlement.commitment(RECIPIENT.pubkey(), SALT)
    eighty_two = _state(DEPOSITOR.pubkey(), AMOUNT, mine) + b"\x00"
    monkeypatch.setattr(settlement, "Client", _account_client(eighty_two, lamports=1_002_039_280))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex())
    assert out["open"] is None, "open=False here tells the agent its money never left"
    assert out["determinate"] is False
    assert "KEEP YOUR CLAIM TICKET" in out["verdict"]
    assert out["lamports"] == 1_002_039_280, "the funds visibly at the PDA must still be shown"


def test_an_owner_mismatch_is_indeterminate_not_settled(monkeypatch):
    """Needs no layout drift at all — a lying or stale endpoint, or a mis-set
    XETE_SETTLEMENT_PROGRAM, reaches it."""
    mine = settlement.commitment(RECIPIENT.pubkey(), SALT)
    monkeypatch.setattr(settlement, "Client",
                        _account_client(_state(DEPOSITOR.pubkey(), AMOUNT, mine),
                                        owner=SYSTEM_PROGRAM))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex())
    assert out["open"] is None and out["determinate"] is False
    assert "KEEP YOUR CLAIM TICKET" in out["verdict"]


def test_an_absent_account_is_still_a_determinate_settled(monkeypatch):
    """The other half: the tri-state must not make everything mushy. Nothing at the PDA is a
    real answer and has to stay one, or reclaim/claim flows never conclude."""
    monkeypatch.setattr(settlement, "Client", _account_client(None))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex())
    assert out["open"] is False and out["determinate"] is True


def test_a_real_escrow_is_a_determinate_open(monkeypatch):
    mine = settlement.commitment(RECIPIENT.pubkey(), SALT)
    monkeypatch.setattr(settlement, "Client",
                        _account_client(_state(DEPOSITOR.pubkey(), AMOUNT, mine)))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex())
    assert out["open"] is True and out["determinate"] is True


def test_the_status_tool_shouts_when_the_answer_is_indeterminate(server_mod, monkeypatch):
    """`open: null` is falsey in every language an agent might post-process this in, so the
    warning has to live in a key that cannot be read as a boolean."""
    mine = settlement.commitment(RECIPIENT.pubkey(), SALT)
    monkeypatch.setattr(settlement, "Client",
                        _account_client(_state(DEPOSITOR.pubkey(), AMOUNT, mine) + b"\x00"))
    out = json.loads(server_mod.xete_settle_status(ESCROW_ID.hex()))
    assert out["open"] is None and out["determinate"] is False
    assert "WARNING_STATUS_IS_INDETERMINATE" in out
    assert "Do NOT discard a claim ticket" in out["WARNING_STATUS_IS_INDETERMINATE"]


@pytest.mark.parametrize("tool,fn,args", [
    ("xete_settle_create", "deposit", (str(RECIPIENT.pubkey()), 1.0)),
    ("xete_settle_claim", "claim", (ESCROW_ID.hex(), SALT.hex())),
    ("xete_settle_reclaim", "reclaim", (ESCROW_ID.hex(),)),
])
def test_no_timeout_guidance_authorises_a_conclusion_from_open_alone(server_mod, monkeypatch,
                                                                     tool, fn, args):
    """The instruction the agent actually follows. All three said open=false means X — and
    open=false is now also what an unauthenticated read produces. Every one of them must gate
    its conclusion on `determinate` first."""
    monkeypatch.setattr(server_mod, "load_or_create_identity",
                        lambda _p: SimpleNamespace(ed_seed=bytes([1] * 32),
                                                   pubkey_b58=str(DEPOSITOR.pubkey())))

    def timeout(*_a, **_k):
        raise settlement.SettlementSubmitError("not confirmed within 90s", signature="SiG",
                                               outcome="unconfirmed")

    monkeypatch.setattr(settlement, fn, timeout)
    step = json.loads(getattr(server_mod, tool)(*args))["next_step"]
    assert "determinate" in step, f"{tool} still reads a conclusion off `open` alone"
    assert "determinate=false" in step and "null" in step


def test_state_len_is_the_length_the_deployed_program_allocates():
    """Pinned to a READ-ONLY mainnet observation, not to this module's own docstring — the
    reviewer's standing objection was that nobody had ever checked it, and it now gates 'did my
    money land'. Deposit 4zAVuxHQ... on GPCsJ6kv... emitted an inner createAccount CPI with
    space=81 and owner=GPCsJ6kv...; claim 5fwM657m... closed it. The program is IMMUTABLE, so
    that observation cannot go stale."""
    assert settlement.STATE_LEN == 81
    assert draft.ESCROW_RENT_LAMPORTS == (128 + 81) * 3480 * 2


# ── [16] round 2: any post-submit exception, not just the in-band timeout ─────────────

class _DiesAfterSubmit:
    """send_transaction succeeds — the transaction is LIVE — and then the RPC 429s. This is not
    exotic: api.mainnet-beta is this repo's default endpoint and rate-limits routinely."""

    def __init__(self, exc=None):
        self.exc = exc or RuntimeError("429 Too Many Requests")
        self.sent = 0
        self.signature = None

    def get_latest_blockhash(self):
        return SimpleNamespace(value=SimpleNamespace(blockhash=Hash.default()))

    def get_balance(self, *_a, **_k):
        return SimpleNamespace(value=0)

    def send_transaction(self, _tx, opts=None):
        self.sent += 1
        self.signature = str(_tx.signatures[0])
        return SimpleNamespace(value=_tx.signatures[0])

    def get_signature_statuses(self, _sigs):
        raise self.exc

    def is_blockhash_valid(self, _bh, commitment=None):
        raise self.exc


def test_an_rpc_that_dies_after_a_successful_submit_keeps_the_signature(instant):
    """Fixed at ONE site inside _send, so create, claim and reclaim all inherit it."""
    client = _DiesAfterSubmit()
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        settlement._send(client, [DEPOSITOR], [_deposit_ix()], DEPOSITOR, "deposit",
                         ticket={"escrow_id": ESCROW_ID.hex(), "salt": SALT.hex()})
    assert client.sent == 1, "the transaction really was submitted"
    assert ei.value.outcome == "unconfirmed", "'failed' asserts an outcome we do not know"
    assert ei.value.signature == client.signature
    assert ei.value.ticket["salt"] == SALT.hex()
    assert "MAY WELL HAVE LANDED" in str(ei.value)


@pytest.mark.parametrize("tool,args", [
    ("xete_settle_claim", (ESCROW_ID.hex(), SALT.hex())),
    ("xete_settle_reclaim", (ESCROW_ID.hex(),)),
])
def test_claim_and_reclaim_keep_the_signature_when_the_rpc_429s_after_submit(
        server_mod, monkeypatch, instant, tool, args):
    """The reviewer's a8.py: status='failed', signature discarded, for a transaction live on the
    cluster. The round-1 handlers only covered the in-band timeout; everything else fell through
    to `except Exception`."""
    monkeypatch.setattr(server_mod, "load_or_create_identity",
                        lambda _p: SimpleNamespace(ed_seed=bytes([1] * 32),
                                                   pubkey_b58=str(DEPOSITOR.pubkey())))
    factory, made = _capture(_DiesAfterSubmit)
    monkeypatch.setattr(settlement, "Client", factory)
    out = json.loads(getattr(server_mod, tool)(*args))
    assert out["status"] == "submitted_unconfirmed", "'failed' for a live transaction"
    assert out["tx_signature"] == made[0].signature, "the signature is the only way to resolve it"
    assert "xete_settle_status" in out["next_step"]


def test_settle_create_keeps_ticket_and_signature_when_the_rpc_429s_after_submit(
        server_mod, monkeypatch, instant, spend_ok):
    """create was 'better but still incomplete' — it kept the ticket via early_ticket but lost
    the signature, because the exception never became a SettlementSubmitError."""
    monkeypatch.setattr(server_mod, "load_or_create_identity",
                        lambda _p: SimpleNamespace(ed_seed=bytes([1] * 32),
                                                   pubkey_b58=str(DEPOSITOR.pubkey())))
    factory, made = _capture(_DiesAfterSubmit)
    monkeypatch.setattr(settlement, "Client", factory)
    out = json.loads(server_mod.xete_settle_create(str(RECIPIENT.pubkey()), 1.0))
    assert out["status"] == "submitted_unconfirmed"
    assert out["tx_signature"] == made[0].signature
    assert len(bytes.fromhex(out["ticket"]["salt"])) == 16
    assert "KEEP_THIS_TICKET" in out


def test_a_receipt_read_failure_does_not_unclaim_a_confirmed_claim(monkeypatch, instant):
    """claim() reads the balance AFTER _send returns a confirmed signature, purely to report how
    much arrived. A 429 on that read used to unwind out of a claim that had already settled."""
    class _C(_SendClient):
        def __init__(self, *_a, **_k):
            super().__init__([_Status(TCS.Confirmed)])
            self.calls = 0

        def get_balance(self, *_a, **_k):
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError("429 Too Many Requests")
            return SimpleNamespace(value=0)

    factory, made = _capture(_C)
    monkeypatch.setattr(settlement, "Client", factory)
    sig, received = settlement.claim("http://127.0.0.1:1", RECIPIENT, ESCROW_ID.hex(), SALT.hex())
    assert sig == made[0].signature, "the claim confirmed; a receipt read must not undo that"
    assert received is None, "unknown, and reported as unknown rather than as zero"


def test_a_genuine_on_chain_failure_is_still_a_failure(instant):
    """The over-correction guard: 'the RPC stopped answering' must not swallow a real error the
    chain actually reported."""
    client = _SendClient([_Status(TCS.Confirmed, err="InsufficientFundsForRent")])
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        settlement._send(client, [DEPOSITOR], [_deposit_ix()], DEPOSITOR, "deposit")
    assert ei.value.outcome == "failed"


def test_a_submit_that_never_happened_is_not_reported_as_submitted():
    """The other over-correction guard: an exception BEFORE send_transaction must stay an
    ordinary error — claiming a signature that does not exist would be its own disaster."""
    class _NeverSends:
        def get_latest_blockhash(self):
            raise RuntimeError("connection refused")

    with pytest.raises(settlement.SettlementSubmitError):
        raise settlement.SettlementSubmitError("placeholder")   # sanity: the type exists
    # the real assertion:
    with pytest.raises(RuntimeError) as ei:
        settlement._send(_NeverSends(), [DEPOSITOR], [_deposit_ix()], DEPOSITOR, "deposit")
    assert not isinstance(ei.value, settlement.SettlementSubmitError)


# ── [23] round 2: OverflowError escaped verify_draft ──────────────────────────────────

def _overflowing_seed_tx() -> str:
    """CreateAccountWithSeed whose bincode String length is 0xFFFFFFFFFFFFFFFF. _system_movement
    read it as a u64 and used it as an OFFSET into struct.unpack_from."""
    evil = Instruction(
        program_id=settlement.SYS,
        data=struct.pack("<I", 3) + b"\x00" * 32 + struct.pack("<Q", 0xFFFFFFFFFFFFFFFF),
        accounts=[AccountMeta(DEPOSITOR.pubkey(), True, True)])
    return _honest(extra=[evil])


def test_a_bincode_length_overflow_returns_a_result_instead_of_raising():
    """OverflowError is not struct.error, IndexError or ValueError, so it sailed out of
    verify_draft and broke its documented contract."""
    r = _verify(_overflowing_seed_tx())
    assert isinstance(r, draft.VerifyResult)
    assert not r.ok
    assert "every_instruction_decoded" in r.failures


def test_the_overflowing_instruction_is_refused_at_the_mcp_boundary(chain, drafting):
    v = json.loads(drafting.xete_verify_settlement_tx(
        _overflowing_seed_tx(), str(RECIPIENT.pubkey()), SALT.hex(), 1.0))
    assert v["verified"] is False
    assert "DO NOT SIGN" in v["verdict"]


@pytest.mark.parametrize("seed_len", [0xFFFFFFFFFFFFFFFF, 2 ** 63, 2 ** 40, 10 ** 6])
def test_an_out_of_range_seed_length_is_bounded_before_it_becomes_an_offset(seed_len):
    m = draft._system_movement(
        struct.pack("<I", 3) + b"\x00" * 32 + struct.pack("<Q", seed_len), [])
    assert m["decoded"] is False, "an unbounded attacker u64 must never reach unpack_from"


def test_verify_draft_always_returns_a_result_even_if_it_errors_internally(monkeypatch):
    """The structural guarantee. Patching each novel exception type as it is discovered leaves
    the contract resting on the completeness of a list; an escape must be a FAILED result."""
    def boom(*_a, **_k):
        raise OverflowError("a parser bug nobody has found yet")

    monkeypatch.setattr(draft, "_lamport_movements", boom)
    r = _verify(_honest())
    assert isinstance(r, draft.VerifyResult)
    assert r.ok is False
    assert "verifier_internal_error" in r.failures
    assert "DO NOT SIGN" in json.dumps(r.checks)


# ── [20] round 2: the escrow-id expectation defaults to absent, and said nothing ──────

def test_omitting_the_escrow_id_expectation_is_flagged_not_silent(chain, drafting):
    """The tool default certified a draft that funds a different escrow than the claim ticket
    names, in silence. xete_settle_status warns when handed half a claim ticket; this is the
    same class of omission on the argument whose absence WAS finding [20]."""
    other = bytes(Keypair.from_seed(bytes([11] * 32)).pubkey())
    tx = _tx_b64([settlement._cb_limit(60_000), settlement._cb_price(1_000),
                  _deposit_ix(escrow_id=other)])
    v = json.loads(drafting.xete_verify_settlement_tx(tx, str(RECIPIENT.pubkey()), SALT.hex(), 1.0))
    assert v["verified"] is True, "the draft itself is well-formed; only the id is unchecked"
    assert "WARNING_ESCROW_ID_NOT_CHECKED" in v
    assert other.hex() in v["WARNING_ESCROW_ID_NOT_CHECKED"]
    assert "NOT checked" in v["verdict"], "the verdict line is what a human actually reads"


def test_supplying_the_escrow_id_removes_the_warning(chain, drafting):
    v = json.loads(drafting.xete_verify_settlement_tx(
        _honest(), str(RECIPIENT.pubkey()), SALT.hex(), 1.0, expect_escrow_id=ESCROW_ID.hex()))
    assert v["verified"] is True, v["failed_checks"]
    assert "WARNING_ESCROW_ID_NOT_CHECKED" not in v
    assert v["verdict"] == "SAFE TO REVIEW AND SIGN"


# ══ THE SUBMIT/RECEIPT REPORTING GROUP — [G8] [G9] [G13] [G15] [G19] ═════════════════
#
# One bug wearing five hats: a transaction that IS or MAY BE live on the cluster is reported as
# a clean failure, and the signature — which this client computes locally before it submits
# anything — is thrown away. The caller is then told they were not paid, and has no string with
# which to find out otherwise.


def _raiser(exc):
    """A settlement.Client replacement whose construction itself fails — an RPC that is simply
    not there."""
    def _factory(*_a, **_k):
        raise exc
    return _factory


class _ReceiptDies(_SendClient):
    """The claim CONFIRMS, and the balance read that measures the receipt does not answer.

    `which` picks the trigger: "pre" fails the read taken BEFORE submission, "post" the one
    after. Either alone makes settlement.claim return received=None — deliberately, so that a
    429 on a receipt cannot become "your claim failed".
    """

    def __init__(self, which):
        super().__init__([_Status(TCS.Confirmed)])
        self.which = which
        self.balance_calls = 0

    def get_balance(self, *_a, **_k):
        self.balance_calls += 1
        if (self.which == "pre") == (self.balance_calls == 1):
            raise RuntimeError("429 Too Many Requests")
        return SimpleNamespace(value=0)


@pytest.mark.parametrize("which", ["pre", "post"])
def test_the_claim_TOOL_does_not_report_a_confirmed_claim_as_failed(
        server_mod, monkeypatch, instant, which):
    """[G8] THE ONE THAT WAS ALREADY TESTED ONE LAYER TOO LOW.

    test_a_receipt_read_failure_does_not_unclaim_a_confirmed_claim asserts the exact value that
    breaks this tool — received is None — but it calls settlement.claim directly and never
    xete_settle_claim. The tool then did `received / 1e9`, TypeError, straight into its own bare
    `except Exception`: a CONFIRMED, landed claim reported as {"status": "failed"} with no
    tx_signature, no DO_NOT_ASSUME_YOU_WERE_NOT_PAID and no next_step. The agent tells the
    depositor to reclaim, and a settled payment is unwound.
    """
    _identity(monkeypatch, server_mod)
    factory, made = _capture(_ReceiptDies, which)
    monkeypatch.setattr(settlement, "Client", factory)

    out = json.loads(server_mod.xete_settle_claim(ESCROW_ID.hex(), SALT.hex()))

    assert out["status"] == "claimed", "a confirmed claim reported as a failure"
    assert out["tx_signature"] == made[0].signature, "the signature must survive a lost receipt"
    assert out["received_sol"] is None, "unknown, and reported as unknown rather than as zero"
    assert "receipt_note" in out and "CONFIRMED" in out["receipt_note"]


def test_an_unforeseen_error_after_a_confirmed_claim_still_carries_the_signature(
        server_mod, monkeypatch):
    """[G8], second half. The division was one instance of a class: anything raising after the
    claim returns lands in the generic handler, which emitted a bare failure. If the tool holds a
    signature, the money already moved and 'failed' is never the honest word."""
    _identity(monkeypatch, server_mod)

    class _Unserialisable:
        def __truediv__(self, _o):
            raise TypeError("a shape nobody anticipated")

    monkeypatch.setattr(settlement, "claim",
                        lambda *_a, **_k: ("CoNfIrMeDsIg", _Unserialisable()))
    out = json.loads(server_mod.xete_settle_claim(ESCROW_ID.hex(), SALT.hex()))

    assert out["status"] != "failed", "the claim confirmed; only the reporting broke"
    assert out["tx_signature"] == "CoNfIrMeDsIg"
    assert "DO_NOT_ASSUME_YOU_WERE_NOT_PAID" in out


class _SendRaises(_SendClient):
    """The endpoint accepts the transaction — the cluster will index it under the signature this
    client already holds — and then the response never arrives. A read timeout, a proxy 502, a
    dropped socket. Indistinguishable, from here, from an endpoint that never forwarded it."""

    def __init__(self, exc=None):
        super().__init__([_Status(TCS.Confirmed)])
        self.exc = exc or RuntimeError("ReadTimeout: the response never came back")

    def get_balance(self, *_a, **_k):
        return SimpleNamespace(value=0)

    def send_transaction(self, _tx, opts=None):
        self.sent += 1
        self.signature = str(_tx.signatures[0])     # what the cluster will index it under
        raise self.exc


def test_a_send_that_raises_keeps_the_locally_signed_signature(instant):
    """[G9] The 'FROM HERE ON THE TRANSACTION IS LIVE' comment sat one line BELOW the send call,
    and nothing guarded the call itself. The signature was never unknown — the transaction is
    signed locally on the line above — it was simply never captured."""
    client = _SendRaises()
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(client)
    assert client.sent == 1
    assert ei.value.outcome == "unconfirmed", "'failed' asserts an outcome we do not know"
    assert ei.value.signature == client.signature, "the id the cluster would index it under"
    assert "MAY ALREADY BE LIVE" in str(ei.value)


def test_a_send_that_raises_keeps_the_deposit_ticket_too(instant):
    """[G9] The ticket is the only copy of the salt. A submit-call failure must not lose it."""
    ticket = {"escrow_id": ESCROW_ID.hex(), "salt": SALT.hex()}
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        settlement._send(_SendRaises(), [DEPOSITOR], [_deposit_ix()], DEPOSITOR, "deposit",
                         ticket=ticket)
    assert ei.value.ticket == ticket


@pytest.mark.parametrize("tool,args", [
    ("xete_settle_claim", (ESCROW_ID.hex(), SALT.hex())),
    ("xete_settle_reclaim", (ESCROW_ID.hex(),)),
])
def test_the_tools_report_a_send_that_raises_as_live_not_failed(
        server_mod, monkeypatch, instant, tool, args):
    """[G9] at the surface the agent actually reads. Both tools returned nothing but an error
    string for a transaction the cluster may be confirming."""
    _identity(monkeypatch, server_mod)
    factory, made = _capture(_SendRaises)
    monkeypatch.setattr(settlement, "Client", factory)

    out = json.loads(getattr(server_mod, tool)(*args))

    assert out["status"] == "submitted_unconfirmed", "'failed' for a possibly-live transaction"
    assert out["tx_signature"] == made[0].signature
    assert "xete_settle_status" in out["next_step"]


def test_settle_create_reports_a_send_that_raises_as_live_and_keeps_the_ticket(
        server_mod, monkeypatch, instant, spend_ok):
    """[G9] create kept the ticket but lost the signature, because the raise never became a
    SettlementSubmitError."""
    _identity(monkeypatch, server_mod)
    factory, made = _capture(_SendRaises)
    monkeypatch.setattr(settlement, "Client", factory)

    out = json.loads(server_mod.xete_settle_create(str(RECIPIENT.pubkey()), 1.0))

    assert out["status"] == "submitted_unconfirmed"
    assert out["tx_signature"] == made[0].signature
    assert len(bytes.fromhex(out["ticket"]["salt"])) == 16
    assert "KEEP_THIS_TICKET" in out


def test_a_failure_before_the_send_call_is_still_an_ordinary_error(instant):
    """[G9]'s over-correction guard. The boundary moved UP to the send call, not further: an
    exception raised before it must not claim a transaction was submitted."""
    class _NeverSends(_SendClient):
        def get_latest_blockhash(self):
            raise RuntimeError("connection refused")

    with pytest.raises(RuntimeError) as ei:
        _send(_NeverSends([None]))
    assert not isinstance(ei.value, settlement.SettlementSubmitError)


class _ForeignSignature(_SendClient):
    """An endpoint that answers with a receipt for a DIFFERENT transaction — a hostile endpoint,
    a buggy one, or a proxy that submitted something else."""

    FOREIGN = "5fwM657mN3n3LXbMeGSttmUG3N147sHcmn775i3kZ92Afrx3iVGStXMnSyVzpD39t6H3L7e3mz8Sb4zP4iTc4MM7"

    def send_transaction(self, _tx, opts=None):
        self.sent += 1
        self.signature = str(_tx.signatures[0])
        return SimpleNamespace(value=self.FOREIGN)


def test_an_endpoint_does_not_get_to_name_our_transaction(instant):
    """[G13] The signature is deterministic and computed locally, so comparing it is free — and
    it was not done. An endpoint could hand back a receipt pointing at a stranger's transaction,
    and the whole recovery story ('check signature X on chain') would then confirm that
    stranger's transaction as ours."""
    client = _ForeignSignature([_Status(TCS.Confirmed)])
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(client, rpc_url="https://liar.example")
    assert ei.value.outcome == "unconfirmed", "the transaction may still be live"
    assert ei.value.signature == client.signature, "report OUR signature, never the endpoint's"
    assert _ForeignSignature.FOREIGN not in ei.value.signature
    assert "liar.example" in str(ei.value), "name the endpoint that did it"


def test_a_foreign_signature_never_reaches_the_caller_as_a_success(server_mod, monkeypatch,
                                                                   instant):
    """[G13] at the tool surface: the reviewer's poc7 reported status=reclaimed with a mainnet
    signature belonging to somebody else."""
    _identity(monkeypatch, server_mod)
    factory, made = _capture(_ForeignSignature, [_Status(TCS.Confirmed)])
    monkeypatch.setattr(settlement, "Client", factory)

    out = json.loads(server_mod.xete_settle_reclaim(ESCROW_ID.hex()))

    assert out["status"] != "reclaimed"
    assert out["tx_signature"] == made[0].signature
    assert _ForeignSignature.FOREIGN not in json.dumps(out), \
        "no field an agent could lift a signature from may carry the endpoint's"
    # The tools truncate str(e) at 400 characters and the ENDPOINT chooses that text, so a
    # message that ends with "check signature <ours>" can be cut off while an attacker-supplied
    # signature-shaped string survives at the front. Our signature has to lead.
    assert made[0].signature in out["error"], \
        "the recovery string must survive the tools' 400-character truncation"


def test_a_dropped_verdict_is_not_taken_from_one_endpoint(instant, monkeypatch):
    """[G15] `dropped` is the one outcome the tools turn into a flat {"status": "failed"}, and
    xete_settle_claim's own guidance reads it as proof the claim did not land. Both facts behind
    it — 'no status for this signature' and 'the blockhash is dead' — are chosen by the SAME
    endpoint. This module refuses single-source conclusions everywhere else; this was the one
    place it did not."""
    monkeypatch.delenv(settlement.ENV_SECOND_RPC, raising=False)   # and no network from a test
    client = _SendClient([None], blockhash_valid=False)
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(client, rpc_url="https://only.example")
    assert ei.value.outcome == "unconfirmed", "one endpoint cannot prove a transaction is dead"
    assert ei.value.signature == client.signature
    assert settlement.ENV_SECOND_RPC in str(ei.value), "say how to earn the definite answer"


def test_a_second_endpoint_that_has_seen_the_transaction_blocks_the_dropped_verdict(
        instant, monkeypatch):
    """[G15] The contradiction case. If the corroborator HAS a status for the signature, the
    primary's 'the cluster never saw it' is contradicted and must not become a verdict."""
    monkeypatch.setenv(settlement.ENV_SECOND_RPC, "https://second.example")
    monkeypatch.setattr(settlement, "Client",
                        lambda *_a, **_k: _SendClient([_Status(TCS.Processed)]))
    client = _SendClient([None], blockhash_valid=False)
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(client, rpc_url="https://primary.example")
    assert ei.value.outcome == "unconfirmed"
    assert client.polls > 20, "it must go back to watching, not conclude from the primary"


def test_a_silenced_second_endpoint_does_not_upgrade_a_guess_into_a_verdict(instant, monkeypatch):
    """[G15] The adversary who can lie on endpoint 1 can usually also drop endpoint 2. A
    corroborator that does not answer corroborates nothing."""
    monkeypatch.setenv(settlement.ENV_SECOND_RPC, "https://second.example")

    def _refused(*_a, **_k):
        raise ConnectionRefusedError("silenced")

    monkeypatch.setattr(settlement, "Client", _refused)
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(_SendClient([None], blockhash_valid=False), rpc_url="https://primary.example")
    assert ei.value.outcome == "unconfirmed"


def test_settle_status_reports_determinate_false_when_the_read_itself_fails(
        server_mod, monkeypatch):
    """[G19] Every unconfirmed-submit message from create/claim/reclaim says 'call
    xete_settle_status and read `determinate` FIRST' — and the RPC outage that produces an
    unconfirmed submit is the same outage that produces this branch. The field the guidance names
    was missing exactly when it was needed, and an absent key reads as falsey: 'the deposit did
    not happen', 'you were paid'."""
    def _down(*_a, **_k):
        raise ConnectionRefusedError("primary down")

    monkeypatch.setattr(settlement, "Client", _down)
    out = json.loads(server_mod.xete_settle_status(ESCROW_ID.hex()))

    assert out["status"] == "failed", "the READ failed, and that much is true"
    assert out["determinate"] is False, "the field the recovery guidance tells agents to read"
    assert out["open"] is None, "not false — nothing was learned about the escrow"
    assert "WARNING_STATUS_IS_INDETERMINATE" in out
    assert "Do NOT discard a claim ticket" in out["WARNING_STATUS_IS_INDETERMINATE"]
    assert "primary down" in out["error"], "the diagnostic must not be swallowed either"


def test_every_settle_status_shape_carries_determinate(server_mod, monkeypatch):
    """[G19] as a property rather than a case: an agent following the recovery guidance branches
    on `determinate`, so no answer-shaped response from this tool may omit it."""
    mine = settlement.commitment(RECIPIENT.pubkey(), SALT)
    shapes = {
        "open": _account_client(_state(DEPOSITOR.pubkey(), AMOUNT, mine)),
        "settled": _account_client(None),
        "unknown-layout": _account_client(_state(DEPOSITOR.pubkey(), AMOUNT, mine) + b"\x00"),
        "read-failed": _raiser(ConnectionRefusedError("primary down")),
    }
    for name, client in shapes.items():
        monkeypatch.setattr(settlement, "Client", client)
        out = json.loads(server_mod.xete_settle_status(ESCROW_ID.hex()))
        assert "determinate" in out, f"the {name} shape omits `determinate`"
        assert isinstance(out["determinate"], bool)


# ══ what the fresh-context adversarial pass on this change broke ═════════════════════
# See reviews/DDR-settlement-submit-receipt-20260801.md, doubts D1-D6. Every test below
# corresponds to a claim that pass BROKE, or to a branch it found had no coverage at all.


class _PreflightRefusal(_SendClient):
    """The endpoint SIMULATES the transaction (skip_preflight=False) and refuses to forward it.
    A wrong salt, an escrow already claimed, not enough lamports. It answered, and its answer is
    a refusal: nothing was forwarded and nothing executed."""

    def __init__(self, statuses=(None,)):
        super().__init__(list(statuses))

    def get_balance(self, *_a, **_k):
        return SimpleNamespace(value=0)

    def send_transaction(self, _tx, opts=None):
        self.sent += 1
        self.signature = str(_tx.signatures[0])
        raise RPCException("Transaction simulation failed: Error processing Instruction 0: "
                           "custom program error: 0x1")


def test_a_preflight_refusal_is_a_failure_not_a_maybe_live_transaction(instant):
    """[D2] The G9 guard's over-correction. Wrapping the send call turned every DETERMINISTIC
    rejection into 'MAY ALREADY BE LIVE — do not re-claim', which is the opposite of the advice
    a wrong salt needs. An endpoint that answered with a JSON-RPC error refused to forward it."""
    client = _PreflightRefusal()
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(client, rpc_url="https://honest.example")
    assert ei.value.outcome == "failed", "the endpoint answered, and its answer was a refusal"
    assert ei.value.signature == client.signature, "keep the signature anyway — it costs nothing"
    assert "REJECTED" in str(ei.value)


def test_the_claim_tool_tells_an_agent_to_fix_a_rejected_claim_not_to_wait(
        server_mod, monkeypatch, instant):
    """[D2] at the surface: 'submitted_unconfirmed' here would tell the agent its bad-salt claim
    might still land, and to leave it alone."""
    _identity(monkeypatch, server_mod)
    factory, made = _capture(_PreflightRefusal)
    monkeypatch.setattr(settlement, "Client", factory)
    out = json.loads(server_mod.xete_settle_claim(ESCROW_ID.hex(), SALT.hex()))
    assert out["status"] == "failed"
    assert out["submit_outcome"] == "failed"
    assert out["tx_signature"] == made[0].signature, "HEAD lost this; a rejection keeps it now"


def test_a_transport_failure_is_still_treated_as_possibly_live(instant):
    """[D2]'s own guard: narrowing to RPCException must not swallow the G9 case it was built
    for. A transport error is not an answer."""
    client = _SendRaises()
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(client)
    assert ei.value.outcome == "unconfirmed"


def test_an_error_at_processed_is_not_yet_a_definite_failure(instant):
    """[D1] THE REVIEWER'S HEADLINE. `Processed` is refused as proof of SUCCESS one line below,
    because it can still be forked away — so it cannot be proof of FAILURE either. This was the
    cheaper twin of the single-source `dropped` verdict: one poll, one endpoint, and the tools
    turn outcome='failed' into 'you were not paid' / 'your funds are still locked'."""
    client = _SendClient([_Status(TCS.Processed, err={"InstructionError": [0, {"Custom": 1}]})])
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(client)
    assert ei.value.outcome != "failed", "one forkable opinion is not a definite failure"
    assert ei.value.outcome == "unconfirmed"
    assert ei.value.signature == client.signature
    assert client.polls > 1, "it must keep watching, not conclude on the first poll"


def test_an_error_that_reaches_a_durable_status_is_still_a_definite_failure(instant):
    """[D1]'s over-correction guard. The chain's own answer, at a commitment that cannot be
    forked away, must still be reported as the failure it is."""
    client = _SendClient([_Status(TCS.Processed, err="Custom(1)"),
                          _Status(TCS.Finalized, err="Custom(1)")])
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(client)
    assert ei.value.outcome == "failed"


def test_a_second_endpoint_that_calls_the_blockhash_alive_blocks_the_dropped_verdict(
        instant, monkeypatch):
    """[D5] The one _corroborate_dropped branch the first round left untested: the corroborator
    has no status either, but does NOT agree the blockhash is dead."""
    monkeypatch.setenv(settlement.ENV_SECOND_RPC, "https://second.example")
    monkeypatch.setattr(settlement, "Client",
                        lambda *_a, **_k: _SendClient([None], blockhash_valid=True))
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(_SendClient([None], blockhash_valid=False), rpc_url="https://primary.example")
    assert ei.value.outcome == "unconfirmed"
    assert "does not agree" in str(ei.value)


def test_the_corroboration_is_time_bounded(instant, monkeypatch):
    """[D4] solana-py's default is 10 SECONDS PER REQUEST and this makes two of them, from
    inside a loop whose documented contract is that the confirmation budget bounds the total."""
    seen: list = []

    def _factory(url, *_a, **kw):
        seen.append(kw.get("timeout"))
        return _SendClient([None], blockhash_valid=False)

    monkeypatch.setenv(settlement.ENV_SECOND_RPC, "https://second.example")
    monkeypatch.setenv(settlement.ENV_CONFIRM_SECONDS, "10")   # enough polls to reach the check
    monkeypatch.setattr(settlement, "Client", _factory)
    with pytest.raises(settlement.SettlementSubmitError):
        _send(_SendClient([None], blockhash_valid=False), rpc_url="https://primary.example")
    assert seen, "the corroborating client was never built"
    assert all(t is not None for t in seen), "an unbounded corroborator can hang the tool"
    assert all(t <= settlement._CORROBORATION_TIMEOUT for t in seen)


@pytest.mark.parametrize("bad_args,why", [
    ((OVERLONG_ESCROW_ID,), "a malformed escrow_id"),
    ((ESCROW_ID.hex(), str(RECIPIENT.pubkey()), "zz"), "a malformed salt"),
])
def test_settle_status_argument_refusals_also_carry_determinate(server_mod, bad_args, why):
    """[D3] The property test in the first round enumerated four dict shapes and missed the two
    guard early-returns — which are the shapes an attacker-supplied claim ticket reaches. Escrow
    ids and salts arrive in the inbox."""
    out = json.loads(server_mod.xete_settle_status(*bad_args))
    assert out["status"] == "failed"
    assert out["determinate"] is False, f"{why} must not omit the field agents branch on"
    assert out["open"] is None
    assert "WARNING_STATUS_IS_INDETERMINATE" in out


@pytest.mark.parametrize("tool,fn,args", [
    ("xete_settle_create", "deposit", (str(RECIPIENT.pubkey()), 1.0)),
    ("xete_settle_reclaim", "reclaim", (ESCROW_ID.hex(),)),
])
def test_create_and_reclaim_also_carry_a_signature_out_of_the_generic_handler(
        server_mod, monkeypatch, spend_ok, tool, fn, args):
    """[D6] The mutation pass found the signature-carry in create's and reclaim's generic
    handlers had no test at all — working code, zero coverage. Same property as the claim tool:
    settlement.deposit/reclaim return only on a durable confirmation, so anything raising after
    that broke the reporting, not the money."""
    _identity(monkeypatch, server_mod)

    class _Weird:
        def __str__(self):
            raise TypeError("not serialisable, and not the chain's problem")

    def _returns_then_breaks(*_a, **_k):
        # deposit returns a 4-tuple, reclaim a bare signature; both then meet an object that
        # blows up during response assembly.
        return ("00" * 32, "11" * 16, _Weird(), "CoNfIrMeDsIg") if fn == "deposit" \
            else "CoNfIrMeDsIg"

    monkeypatch.setattr(settlement, fn, _returns_then_breaks)
    if fn == "reclaim":
        monkeypatch.setattr(server_mod, "json", _BreaksOnce(server_mod.json))
    out = json.loads(getattr(server_mod, tool)(*args))

    assert out["status"] != "failed", "the transaction confirmed; only the reporting broke"
    assert out["tx_signature"] == "CoNfIrMeDsIg"


class _BreaksOnce:
    """`json` for the module under test: the FIRST dumps() raises, later ones work. Models an
    unforeseen serialisation failure on the success path without touching the error path."""

    def __init__(self, real):
        self._real = real
        self._armed = True

    def __getattr__(self, name):
        return getattr(self._real, name)

    def dumps(self, *a, **k):
        if self._armed:
            self._armed = False
            raise TypeError("Object of type _Weird is not JSON serializable")
        return self._real.dumps(*a, **k)
