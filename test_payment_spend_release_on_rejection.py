"""A preflight rejection must give the spend back, and must not tell the agent to retry forever.

THE DEFECT (fresh-context adversarial review). `pay_herd` releases the recorded spend for the
pre-submission span only. A preflight rejection happens INSIDE `send_transaction`, one line past
that boundary, so the ledger entry stood. With the stock window (50,000,000 lamports / 24h) and
the stock floor (2,000,000), roughly 25 rejected one-blob attempts locked the agent out of ALL
spending for 24 hours having moved exactly zero lamports — and upgrading the client afterwards
does not give the burnt window back.

That is the same shape the module already fixed for a dead RPC, and it deserves the same answer
for the same reason: a `skip_preflight=False` rejection means the node SIMULATED this exact
transaction and it failed, so it cannot move lamports whether or not the endpoint also forwarded
it — a forwarded copy fails on chain for the identical deterministic reason. `already processed`
is the one refusal that must never be released, and it is handled separately.

SECOND HALF. The rejection an agent can least fix was the one it was told to fix. The program
explains itself in its own log, but `str(e)` was truncated to 160 characters and the log never
reached the caller, who got "Fix the cause and retry" — a retry loop that cannot succeed and
burns budget per attempt. When the cause is that this package predates the deployed program, the
only true remedy is to upgrade the package, so that case now says so.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "src"))

from solders.hash import Hash          # noqa: E402
from solders.keypair import Keypair    # noqa: E402
from solana.rpc.core import RPCException  # noqa: E402

import xete_mcp.payment as payment     # noqa: E402


# The real repr shape of a treasury-mismatch rejection, captured from an actual rejection on a
# validator rather than invented — the extractor is a regex over this text, so a hand-waved
# approximation would test the approximation.
MISMATCH = (
    'SendTransactionPreflightFailureMessage { message: "Transaction simulation failed: '
    'Error processing Instruction 0: invalid program argument", data: '
    'RpcSimulateTransactionResult(RpcSimulateTransactionResult { err: '
    'Some(UiTransactionError(InstructionError(0, InvalidArgument))), logs: '
    'Some(["Program GLdM82RspCLDFmAUqty2Ef8GBGursZVgMD9cqeNHDq2U invoke [1]", '
    '"Program log: xete: xete_wallet mismatch — refuses to redirect funds", '
    '"Program GLdM82RspCLDFmAUqty2Ef8GBGursZVgMD9cqeNHDq2U failed: invalid program argument"]) })'
)

UNRELATED = (
    'SendTransactionPreflightFailureMessage { message: "Transaction simulation failed: '
    'Attempt to debit an account but found no record of a prior credit.", data: '
    'RpcSimulateTransactionResult(RpcSimulateTransactionResult { err: Some(x), logs: Some([]) })'
)


def _entries(ledger: Path):
    if not ledger.exists():
        return []
    return json.loads(ledger.read_text(encoding="utf-8")).get("entries", [])


class _RejectingClient:
    """Answers the blockhash, then refuses at submit. Nothing else is reached."""

    def __init__(self, text):
        self._text = text

    def get_latest_blockhash(self, *a, **k):
        class _V:
            blockhash = Hash.default()
        class _R:
            value = _V()
        return _R()

    def send_transaction(self, *a, **k):
        raise RPCException(self._text)


@pytest.fixture
def rig(monkeypatch, tmp_path):
    ledger = tmp_path / "ledger.json"
    monkeypatch.setenv("XETE_SPEND_LEDGER", str(ledger))
    monkeypatch.setenv("XETE_SPEND_MAX_LAMPORTS", "50000000")
    monkeypatch.setenv("XETE_SPEND_WINDOW_LAMPORTS", "50000000")
    monkeypatch.setenv("XETE_SPEND_FLOOR_LAMPORTS", "2000000")
    return ledger


def _attempt(monkeypatch, text):
    # payment.py does `from solana.rpc.api import Client` at module level, so the binding to
    # patch is payment.Client. Patching solana.rpc.api.Client instead would leave the already-
    # bound name untouched, the real client would be constructed, and the test would fail for
    # an unrelated network reason — which reads as the fix being broken.
    monkeypatch.setattr(payment, "Client", lambda *a, **k: _RejectingClient(text))
    with pytest.raises(payment.PaymentNotSettled) as ei:
        payment.pay_herd("http://127.0.0.1:1", Keypair(), "nonce-under-test", 1)
    return str(ei.value)


def test_a_treasury_mismatch_rejection_gives_the_spend_back(rig, monkeypatch):
    msg = _attempt(monkeypatch, MISMATCH)
    assert _entries(rig) == [], (
        "a preflight-REJECTED payment kept its ledger entry. The node simulated it and it "
        "failed, so no lamport can have moved; charging it drains the agent's 24-hour window "
        "for free, a few attempts at a time.")
    assert "UPGRADE xete-mcp" in msg, (
        "the caller was not told the one thing that resolves this. The program's own log says "
        f"the client and program disagree; the message said: {msg}")
    assert "Fix the cause and retry." not in msg, (
        "told to retry a rejection that cannot succeed on this version; each retry burns budget")


def test_b_the_program_log_reaches_the_caller(rig, monkeypatch):
    """The useful sentence is the program's. It used to be truncated away."""
    msg = _attempt(monkeypatch, MISMATCH)
    assert "xete_wallet mismatch" in msg, f"program log did not survive into the message: {msg}"


def test_c_an_unrelated_rejection_is_also_released_but_keeps_the_ordinary_advice(rig, monkeypatch):
    """The release is about determinism, not about this one guard: ANY preflight rejection is
    proof the transaction cannot succeed. The ADVICE, though, must stay 'fix the cause' — an
    unfixable-by-upgrade case must not be mislabelled as a stale client."""
    msg = _attempt(monkeypatch, UNRELATED)
    assert _entries(rig) == [], "an unrelated preflight rejection still burnt window budget"
    assert "Fix the cause and retry." in msg, f"lost the ordinary remedy: {msg}"
    assert "UPGRADE xete-mcp" not in msg, (
        "an unrelated rejection was blamed on a stale client, which sends the agent to upgrade "
        "instead of fixing the real cause")


def test_d_repeated_rejections_cannot_exhaust_the_window(rig, monkeypatch):
    """The defect's actual consequence, stated as a test: the lockout, not the single entry."""
    for _ in range(30):
        _attempt(monkeypatch, MISMATCH)
    assert _entries(rig) == [], (
        "30 rejected attempts left ledger entries behind; that is the 24-hour lockout the "
        "original defect produced")


def test_e_an_already_processed_refusal_is_NOT_released(rig, monkeypatch):
    """The one refusal that means the payment LANDED. Releasing it would under-count a real
    spend, which is the unsafe direction. This pins the boundary of the fix above."""
    already = (
        'SendTransactionPreflightFailureMessage { message: "This transaction has already been '
        'processed", data: RpcSimulateTransactionResult(...) }'
    )
    monkeypatch.setattr(payment, "Client", lambda *a, **k: _RejectingClient(already))
    with pytest.raises(payment.PaymentUnconfirmed):
        payment.pay_herd("http://127.0.0.1:1", Keypair(), "nonce-already", 1)
    assert _entries(rig) != [], (
        "an already-processed refusal was released. That refusal is EVIDENCE THE PAYMENT "
        "LANDED, so giving the budget back under-counts a real spend.")
