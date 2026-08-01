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


def _account_client(data: bytes | None, lamports: int = 2_000_000):
    class _C:
        def __init__(self, *_a, **_k):
            pass

        def get_account_info(self, _pda, commitment=None):
            if data is None:
                return SimpleNamespace(value=None)
            return SimpleNamespace(value=SimpleNamespace(data=data, lamports=lamports))
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


@pytest.fixture()
def instant(monkeypatch):
    monkeypatch.setattr(settlement.time, "sleep", lambda _s: None)


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
