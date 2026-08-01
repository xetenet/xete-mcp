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
    mine = settlement.commitment(RECIPIENT.pubkey(), SALT)
    monkeypatch.setattr(settlement, "Client",
                        _account_client(_state(DEPOSITOR.pubkey(), AMOUNT, mine)))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex(),
                            expect_commitment_hex=mine.hex())
    assert out["beneficiary_verified"] is True
    assert out["verdict"].startswith("VERIFIED")


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
    """Fake RPC. `statuses` is consumed one per poll; the last entry repeats forever."""

    def __init__(self, statuses, blockhash_valid=True):
        self.statuses = list(statuses)
        self.blockhash_valid = blockhash_valid
        self.sent = 0
        self.polls = 0

    def get_latest_blockhash(self):
        return SimpleNamespace(value=SimpleNamespace(blockhash=Hash.default()))

    def send_transaction(self, _tx, opts=None):
        self.sent += 1
        return SimpleNamespace(value="SiGnAtUrE")

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


def _send(client):
    return settlement._send(client, [DEPOSITOR], [_deposit_ix()], DEPOSITOR, "deposit")


def test_send_keeps_watching_through_a_congestion_spike(instant):
    """The old client gave up after 60 polls (18s) while the RPC rebroadcasts for 60-90s."""
    client = _SendClient([None] * 70 + [_Status(TCS.Confirmed)])
    assert _send(client) == "SiGnAtUrE"
    assert client.polls > 60


def test_send_does_not_call_processed_confirmed(instant):
    """`if st.confirmation_status:` is true for Processed too — every enum variant is truthy.
    Processed is one validator's opinion and can still be forked away."""
    client = _SendClient([_Status(TCS.Processed)])
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(client)
    assert ei.value.outcome == "unconfirmed"


def test_send_accepts_finalized(instant):
    assert _send(_SendClient([_Status(TCS.Finalized)])) == "SiGnAtUrE"


def test_a_timeout_hands_back_the_signature_instead_of_a_bare_failure(instant):
    client = _SendClient([None])
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(client)
    assert ei.value.signature == "SiGnAtUrE"
    assert ei.value.outcome == "unconfirmed"
    assert "MAY STILL LAND" in str(ei.value)


def test_a_dead_blockhash_with_no_status_is_reported_as_definitely_dropped(instant):
    client = _SendClient([None], blockhash_valid=False)
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        _send(client)
    assert ei.value.outcome == "dropped"


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

    def fake_send(_client, _signers, _ixs, _payer, label, ticket=None):
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


@pytest.fixture()
def chain(monkeypatch):
    """Control what the on-chain %alias registry says, and fail the test if anything reaches
    the permit server over HTTP — asking a server who owns a name is the bug."""
    from xete_mcp import server as server_mod

    state: dict = {"bob": None}

    def fake_resolve(name, rpc=None):
        owner = state.get(alias_chain.normalize_name(name))
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


@pytest.fixture()
def drafting(monkeypatch, server_mod):
    """A configured depositor wallet and an RPC that only ever hands out a blockhash."""
    class _C:
        def __init__(self, *_a, **_k):
            pass

        def get_latest_blockhash(self):
            return SimpleNamespace(value=SimpleNamespace(blockhash=Hash.default()))

    monkeypatch.setattr(server_mod, "DEPOSITOR_WALLET", str(DEPOSITOR.pubkey()))
    monkeypatch.setattr(server_mod, "NONCE_ACCOUNT", "")
    monkeypatch.setattr(server_mod, "NONCE_AUTHORITY", "")
    monkeypatch.setattr(draft, "Client", _C)
    return server_mod


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


def test_verification_uses_the_chain_not_the_draft(chain, drafting):
    """An attacker-built draft paying ATTACKER, verified against %bob, must fail — the chain says
    %bob is RECIPIENT and the commitment cannot match."""
    chain["bob"] = str(RECIPIENT.pubkey())
    evil = _tx_b64([settlement._cb_limit(60_000), settlement._cb_price(1_000),
                    _deposit_ix(recipient=ATTACKER.pubkey())])
    v = json.loads(drafting.xete_verify_settlement_tx(evil, "%bob", SALT.hex(), 1.0))
    assert v["verified"] is False
    assert "recipient_commitment" in v["failed_checks"]
    assert v["recipient_checked"] == str(RECIPIENT.pubkey())
    assert "SAFE TO REVIEW AND SIGN" not in json.dumps(v)


def test_an_unreadable_chain_fails_closed_instead_of_falling_back_to_a_server(chain, drafting):
    """A chain read that fails must refuse, not quietly ask the permit server instead — that
    fallback is how a hostile server gets to answer whenever it can also cause a timeout."""
    chain["bob"] = alias_chain.AliasChainError("RPC timed out")
    out = json.loads(drafting.xete_draft_settlement_tx("%bob", 1.0))
    assert out["status"] == "failed"
    assert "PERMIT_SERVER_WAS_ASKED" not in out["error"]
    assert "RPC timed out" in out["error"]
    v = json.loads(drafting.xete_verify_settlement_tx(_honest(), "%bob", SALT.hex(), 1.0))
    assert v["verified"] is False
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
    0-data account at a known PDA; before this it read back as {open: true}."""
    monkeypatch.setattr(settlement, "Client", _account_client(b"\x00" * n))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex())
    assert out["open"] is False, f"a {n}-byte account is not an open escrow"
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

def test_a_hostile_rpc_cannot_forge_a_verified_escrow(monkeypatch):
    """Perfectly-formed 81 bytes whose commitment matches — served from an account the settlement
    program does not own. This used to return beneficiary_verified=True and 'VERIFIED — the
    hidden beneficiary of this escrow is the wallet you named'."""
    mine = settlement.commitment(RECIPIENT.pubkey(), SALT)
    forged = _state(ATTACKER.pubkey(), 5_000_000_000, mine)
    monkeypatch.setattr(settlement, "Client",
                        _account_client(forged, owner=SYSTEM_PROGRAM))
    out = settlement.status("http://127.0.0.1:1", ESCROW_ID.hex(),
                            expect_commitment_hex=mine.hex())
    assert out["beneficiary_verified"] is not True
    assert out["open"] is False and out["is_escrow"] is False
    assert "VERIFIED" not in out["verdict"].replace("NOT AN ESCROW", "")
    assert "depositor" not in out, "no field may be read out of an account this program does not own"


def test_an_rpc_that_omits_the_owner_fails_closed(monkeypatch):
    """No owner field at all is not a pass. Fail closed."""
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
    assert out["open"] is False
    assert out["beneficiary_verified"] is not True


def test_the_owner_is_surfaced_so_a_human_can_see_what_answered(monkeypatch):
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
