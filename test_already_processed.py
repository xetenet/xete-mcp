"""An endpoint saying "already processed" is saying the transaction LANDED, not that it failed.

`skip_preflight=False` means the node simulates before forwarding, and a refusal at that
point is ordinarily deterministic: wrong salt, escrow already claimed, not enough lamports.
Reporting that as `failed` is correct and useful -- it tells the agent to fix the cause
rather than retry the same thing.

BUT ONE REFUSAL IS NOT LIKE THE OTHERS. `AlreadyProcessed` / "This transaction has already
been processed" means the node is refusing BECAUSE IT ALREADY HAS THIS TRANSACTION. The
signature is on the cluster. It is the single case where the endpoint's refusal is positive
evidence of success, and it was being flattened into the same `failed` verdict as every
other rejection -- which the tools surface as `"status": "failed"`, i.e. nothing moved,
safe to retry.

The consequence is the worst one available on a money path: an escrow deposit or a payment
that DID land, reported as not having happened, to a caller whose obvious next move is to
do it again.

This is a one-endpoint verdict either way. What changes is which verdict a single endpoint
is allowed to license: it may license "retry-able failure" only when its own words do not
say the opposite.

Offline. Nothing touches a network or a real keypair.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from solana.rpc.core import RPCException

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "src"))

from xete_mcp import payment, settlement  # noqa: E402

# The spellings that actually come back off a Solana node. The bare `AlreadyProcessed`
# variant is what solders' error enum stringifies to; the prose variant is what the JSON-RPC
# error message carries. Both are real and neither is a substring of the other.
ALREADY = [
    "This transaction has already been processed",
    "SendTransactionPreflightFailureMessage { err: AlreadyProcessed }",
    "RPC response error -32002: Transaction simulation failed: This transaction has "
    "already been processed",
]
ORDINARY = [
    "Transaction simulation failed: custom program error: 0x1",
    "insufficient funds for rent",
    "SendTransactionPreflightFailureMessage { err: InstructionError(0, Custom(6001)) }",
]


def _settlement_client(err_text):
    from solders.hash import Hash

    class _C:
        def get_latest_blockhash(self):
            return SimpleNamespace(value=SimpleNamespace(blockhash=Hash.default()))

        def send_transaction(self, tx, opts=None):
            raise RPCException(err_text)

    return _C()


def _drive_settlement(err_text):
    from solders.keypair import Keypair
    from solders.system_program import TransferParams, transfer

    payer = Keypair()
    ix = transfer(TransferParams(from_pubkey=payer.pubkey(),
                                 to_pubkey=Keypair().pubkey(), lamports=1))
    with pytest.raises(settlement.SettlementSubmitError) as ei:
        settlement._send(_settlement_client(err_text), [payer], [ix], payer, "claim",
                         rpc_url="https://rpc.test")
    return ei.value


@pytest.mark.parametrize("err_text", ALREADY)
def test_settlement_does_not_call_an_already_landed_transaction_a_failure(err_text):
    e = _drive_settlement(err_text)

    # ARRIVAL FIRST. A SettlementSubmitError from argument validation or a stubbed method
    # that was never called would satisfy every assertion below while proving nothing about
    # this branch -- and a red for the wrong reason is indistinguishable from a guard
    # working. See BM-a-red-that-came-from-the-wrong-cause.
    assert e.signature, "did not reach the submit branch: no signature was attached"

    assert e.outcome != "failed", (
        f"the endpoint said the transaction ALREADY LANDED and this was reported as "
        f"`failed`, which the tools surface as \"status\": \"failed\" -- nothing moved, "
        f"safe to retry. Endpoint said: {err_text!r}")
    assert e.outcome == "unconfirmed"
    assert "already" in str(e).lower(), (
        "the message must say WHY this is not a clean failure, or the caller has an "
        "outcome string and no explanation for it")


@pytest.mark.parametrize("err_text", ORDINARY)
def test_an_ordinary_rejection_is_still_reported_as_a_failure(err_text):
    """THE OPPOSITE DIRECTION, and it matters as much.

    A deterministic rejection dressed up as "may be live" tells an agent not to retry the
    very thing it should fix. `DDR-settlement-submit-receipt-20260801` D2 records exactly
    that over-correction being made here once already, so widening the ambiguous case is
    the specific mistake this test exists to prevent.
    """
    e = _drive_settlement(err_text)
    assert e.signature, "did not reach the submit branch"
    assert e.outcome == "failed", (
        f"an ordinary deterministic rejection became {e.outcome!r}; an agent told 'may be "
        f"live' will not fix the cause. Endpoint said: {err_text!r}")


# ── the same defect, the same day, in the module that moves the other kind of money ────


def _drive_payment(monkeypatch, err_text, tmp_path):
    monkeypatch.setenv("XETE_SPEND_LEDGER", str(tmp_path / "ledger.json"))
    monkeypatch.setattr(payment, "authorize", lambda *a, **k: {"charged_lamports": 0},
                        raising=False)
    monkeypatch.setattr(payment, "_release_recorded_spend", lambda *a, **k: None)
    monkeypatch.setattr(payment, "time", SimpleNamespace(sleep=lambda *_: None))

    class _Tx:
        signatures = ["5x" + "T" * 42]

    monkeypatch.setattr(payment, "Transaction", lambda *a, **k: _Tx())
    monkeypatch.setattr(payment, "Message",
                        SimpleNamespace(new_with_blockhash=lambda *a, **k: object()))
    monkeypatch.setattr(payment, "Client", lambda url: _settlement_client(err_text))

    from solders.keypair import Keypair
    with pytest.raises(payment.PaymentNotSettled) as ei:
        payment.pay_herd("https://rpc.test", Keypair(), "n1", 1, declared_lamports=0)
    return ei.value


@pytest.mark.parametrize("err_text", ALREADY)
def test_payment_does_not_call_an_already_landed_transaction_a_failure(
        err_text, monkeypatch, tmp_path):
    """`pay_herd` grew this same RPCException branch hours ago, in the F4 fix.

    It was written by copying the settlement split -- which means it inherited the defect
    along with the design. A fix applied to one of two parallel implementations is half a
    fix, and this is the half that would have been found in production.
    """
    e = _drive_payment(monkeypatch, err_text, tmp_path)
    assert e.signature, "did not reach the submit branch"
    assert "already" in str(e).lower(), (
        f"the payment endpoint said the transaction ALREADY LANDED and the message does "
        f"not say so; a caller reading 'REJECTED ... nothing was paid' will pay again. "
        f"Endpoint said: {err_text!r}")
    assert "nothing was paid" not in str(e).lower(), (
        "this text is false when the transaction already landed")


@pytest.mark.parametrize("err_text", ORDINARY)
def test_an_ordinary_payment_rejection_still_says_nothing_was_paid(
        err_text, monkeypatch, tmp_path):
    e = _drive_payment(monkeypatch, err_text, tmp_path)
    assert e.signature, "did not reach the submit branch"
    assert "REJECTED" in str(e), (
        f"a deterministic rejection must remain a rejection. Endpoint said: {err_text!r}")
