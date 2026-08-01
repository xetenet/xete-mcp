"""`pay_herd` must never report a payment it did not see durably confirmed.

THE DEFECT, which shipped in 0.1.4 and is live on PyPI today: the confirmation loop broke
on ANY truthy `confirmation_status` and then `return str(sig)` when it simply ran out of
attempts. Three separate ways to certify a payment that did not happen:

  1. the loop exhausted after 15s and returned success with no status at all;
  2. `Processed` was accepted -- and `settlement.py` in this same package refuses it in as
     many words, "one validator's opinion, and it can still be forked away";
  3. `st.err` was never read, so a transaction that landed and FAILED read as success.

A payment tool that says "sent" for a transaction that failed is worse than one that
errors: the caller stops watching.

The second property here matters as much as the first: a submitted-but-unconfirmed
transaction is NOT a clean failure. The signature must survive into the caller's hands,
because a blind retry pays twice if the first one landed.

Offline. Nothing touches a network or a real keypair.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from solders.transaction_status import TransactionConfirmationStatus as TCS

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "src"))

from xete_mcp import payment  # noqa: E402

SIG = "5x" + "T" * 42


def _status(cs, err=None):
    return SimpleNamespace(value=[SimpleNamespace(confirmation_status=cs, err=err)])


class _Client:
    """A Solana client whose confirmation answers the test controls."""

    def __init__(self, statuses):
        self._statuses = list(statuses)
        self.sent = 0

    def get_latest_blockhash(self):
        from solders.hash import Hash
        return SimpleNamespace(value=SimpleNamespace(blockhash=Hash.default()))

    def send_transaction(self, tx, opts=None):
        self.sent += 1
        return SimpleNamespace(value=SIG)

    def get_signature_statuses(self, sigs):
        return self._statuses.pop(0) if self._statuses else _status(None)


@pytest.fixture()
def harness(monkeypatch, tmp_path):
    """Neutralise the spend gate and the transaction build; the loop is what is under test."""
    monkeypatch.setenv("XETE_SPEND_LEDGER", str(tmp_path / "ledger.json"))
    monkeypatch.setattr(payment, "authorize", lambda *a, **k: {"charged_lamports": 0},
                        raising=False)
    monkeypatch.setattr(payment, "_release_recorded_spend", lambda *a, **k: None)

    class _Tx:
        signatures = [SIG]

    monkeypatch.setattr(payment, "Transaction", lambda *a, **k: _Tx())
    monkeypatch.setattr(payment, "Message",
                        SimpleNamespace(new_with_blockhash=lambda *a, **k: object()))
    return _Tx


def _run(monkeypatch, harness, statuses):
    cl = _Client(statuses)
    monkeypatch.setattr(payment, "Client", lambda url: cl)
    monkeypatch.setattr(payment.time, "sleep", lambda *_: None, raising=False)
    from solders.keypair import Keypair
    return cl, payment.pay_herd("https://rpc.test", Keypair(), "nonce-1", 1,
                                declared_lamports=0)


def test_a_durable_confirmation_is_the_only_thing_that_returns_success(monkeypatch, harness):
    monkeypatch.setattr(payment, "time", SimpleNamespace(sleep=lambda *_: None))
    cl = _Client([_status(TCS.Confirmed)])
    monkeypatch.setattr(payment, "Client", lambda url: cl)
    from solders.keypair import Keypair
    assert payment.pay_herd("https://rpc.test", Keypair(), "n", 1, declared_lamports=0) == SIG


def test_processed_alone_is_not_a_paid_invoice(monkeypatch, harness):
    """`Processed` is one validator's opinion and can be forked away. This package already
    refuses it for settlement; accepting it here was the same claim at a lower price."""
    monkeypatch.setattr(payment, "time", SimpleNamespace(sleep=lambda *_: None))
    cl = _Client([_status(TCS.Processed)] * 40)
    monkeypatch.setattr(payment, "Client", lambda url: cl)
    from solders.keypair import Keypair
    with pytest.raises(payment.PaymentUnconfirmed) as e:
        payment.pay_herd("https://rpc.test", Keypair(), "n", 1, declared_lamports=0)
    assert e.value.signature == SIG, "the signature was lost -- it is the whole recovery path"


def test_a_transaction_that_confirmed_with_an_error_is_not_a_payment(monkeypatch, harness):
    """It landed AND failed. Nothing was delivered, the fee was still spent, and the old
    code called that success because it never read `err`."""
    monkeypatch.setattr(payment, "time", SimpleNamespace(sleep=lambda *_: None))
    cl = _Client([_status(TCS.Confirmed, err={"InstructionError": [0, "Custom"]})])
    monkeypatch.setattr(payment, "Client", lambda url: cl)
    from solders.keypair import Keypair
    with pytest.raises(payment.PaymentFailedOnChain) as e:
        payment.pay_herd("https://rpc.test", Keypair(), "n", 1, declared_lamports=0)
    assert e.value.signature == SIG


def test_running_out_of_attempts_is_not_success(monkeypatch, harness):
    """THE headline defect: the loop simply ended and returned the signature as if paid."""
    monkeypatch.setattr(payment, "time", SimpleNamespace(sleep=lambda *_: None))
    cl = _Client([])                      # every poll answers None
    monkeypatch.setattr(payment, "Client", lambda url: cl)
    from solders.keypair import Keypair
    with pytest.raises(payment.PaymentUnconfirmed) as e:
        payment.pay_herd("https://rpc.test", Keypair(), "n", 1, declared_lamports=0)
    assert "MAY STILL LAND" in str(e.value).upper()
    assert e.value.signature == SIG


def test_a_polling_failure_does_not_decide_anything(monkeypatch, harness):
    """An unreadable poll is not evidence about the transaction. It must keep waiting, and
    a later durable answer must still count."""
    monkeypatch.setattr(payment, "time", SimpleNamespace(sleep=lambda *_: None))

    class _Flaky(_Client):
        def __init__(self):
            super().__init__([])
            self.n = 0

        def get_signature_statuses(self, sigs):
            self.n += 1
            if self.n < 3:
                raise RuntimeError("429 from the endpoint")
            return _status(TCS.Finalized)

    cl = _Flaky()
    monkeypatch.setattr(payment, "Client", lambda url: cl)
    from solders.keypair import Keypair
    assert payment.pay_herd("https://rpc.test", Keypair(), "n", 1, declared_lamports=0) == SIG


def test_both_unconfirmed_shapes_are_one_catchable_family():
    """The caller has to be able to catch "may be live" without enumerating subclasses --
    that is what stops the generic handler reporting it as a clean failure."""
    assert issubclass(payment.PaymentUnconfirmed, payment.PaymentNotSettled)
    assert issubclass(payment.PaymentFailedOnChain, payment.PaymentNotSettled)
    assert payment.PaymentNotSettled("m", signature=SIG).signature == SIG
