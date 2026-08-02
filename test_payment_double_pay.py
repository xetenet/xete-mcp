"""A payment that MAY be live must never reach the caller as a clean failure.

Three findings from an independent review of the payment path, all sharing one
consequence: THE CALLER PAYS TWICE.

  F4  `client.send_transaction` is unguarded. The signature is computed locally two lines
      above it, with a comment saying its whole purpose is to survive exactly this -- and
      it is dead on that path. A transport failure AFTER the write reaches the wire looks
      identical, from here, to one that never left, so the transaction may be on the
      cluster while the caller is told the send failed.

  F5  The RPC endpoint gets to NAME our transaction. `sig` comes back from the endpoint's
      reply and is what the confirmation loop polls and what the function RETURNS, while
      the messages quote the locally-computed `sig_local`. `settlement.py` refuses this in
      as many words and explains why; `payment.py` was the second instance, not the
      positive example an earlier report called it.

  F3  `xete_send_message` must keep the `PaymentNotSettled` branch ahead of the generic
      handler. It currently does -- but nothing pinned it, so removing it was silent, and
      the generic handler returns `{"status": "failed"}` with NO signature, which tells an
      agent the payment did not happen and invites the retry that pays twice.

WHY THIS IS FIXED TONIGHT EVEN THOUGH IT IS LATENT. F3 and F4 sit behind the relay
returning a falsy `free_alpha`, and sending is free on xete.net, so neither is reachable
today. They go live the instant that flips, and against any charging server immediately.
A latent double-spend is not a smaller bug than a live one; it is the same bug with a
worse discovery story, because the first person to meet it is whoever turns pricing on.

Offline. Nothing touches a network or a real keypair.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from solders.transaction_status import TransactionConfirmationStatus as TCS

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "src"))

from xete_mcp import payment  # noqa: E402

OURS = "5x" + "T" * 42          # what this client signed
THEIRS = "9z" + "Q" * 42        # a well-formed signature that is not ours


def _status(cs, err=None):
    return SimpleNamespace(value=[SimpleNamespace(confirmation_status=cs, err=err)])


class _Client:
    """A client whose submit behaviour and confirmation answers the test controls."""

    def __init__(self, statuses=(), *, send_raises=None, returns=OURS):
        self._statuses = list(statuses)
        self._send_raises = send_raises
        self._returns = returns
        self.polled = []

    def get_latest_blockhash(self):
        from solders.hash import Hash
        return SimpleNamespace(value=SimpleNamespace(blockhash=Hash.default()))

    def send_transaction(self, tx, opts=None):
        if self._send_raises is not None:
            raise self._send_raises
        return SimpleNamespace(value=self._returns)

    def get_signature_statuses(self, sigs):
        self.polled.append(str(sigs[0]))
        return self._statuses.pop(0) if self._statuses else _status(None)


@pytest.fixture()
def harness(monkeypatch, tmp_path):
    monkeypatch.setenv("XETE_SPEND_LEDGER", str(tmp_path / "ledger.json"))
    monkeypatch.setattr(payment, "authorize", lambda *a, **k: {"charged_lamports": 0},
                        raising=False)
    monkeypatch.setattr(payment, "_release_recorded_spend", lambda *a, **k: None)

    class _Tx:
        signatures = [OURS]

    monkeypatch.setattr(payment, "Transaction", lambda *a, **k: _Tx())
    monkeypatch.setattr(payment, "Message",
                        SimpleNamespace(new_with_blockhash=lambda *a, **k: object()))
    monkeypatch.setattr(payment, "time", SimpleNamespace(sleep=lambda *_: None))


def _pay(monkeypatch, client):
    from solders.keypair import Keypair
    monkeypatch.setattr(payment, "Client", lambda url: client)
    return payment.pay_herd("https://rpc.test", Keypair(), "nonce-1", 1,
                            declared_lamports=0)


# ── F4: a submit that raises must not lose the signature ───────────────────────────────


def test_a_transport_failure_at_submit_keeps_the_signature_and_says_it_may_be_live(
        monkeypatch, harness):
    """No answer from the endpoint. The transaction MAY be on the cluster.

    An endpoint that forwarded the transaction and then failed to reply is
    indistinguishable, from this client, from one that never forwarded it. The only safe
    report is "may be live, here is the signature".
    """
    cl = _Client(send_raises=ConnectionError("connection reset by peer"))
    with pytest.raises(payment.PaymentNotSettled) as ei:
        _pay(monkeypatch, cl)
    assert ei.value.signature == OURS, (
        "the locally-computed signature was lost on the one path it exists to survive; "
        "the caller cannot check whether they already paid")
    assert not isinstance(ei.value, payment.PaymentFailedOnChain), (
        "an unanswered submit is not a definitive failure -- reporting it as one invites "
        "the retry that pays twice")


def test_a_preflight_rejection_is_reported_as_the_failure_it_is(monkeypatch, harness):
    """The endpoint ANSWERED, and its answer is a refusal.

    The opposite direction, and it must not be blanket-wrapped into "may be live".
    `DDR-settlement-submit-receipt-20260801` D2 records exactly that over-correction: a
    reviewer's blanket `except Exception` turned every deterministic rejection into MAY BE
    LIVE, which tells an agent not to retry the very thing it should fix. With
    skip_preflight=False the node simulated it and declined to forward it, so nothing
    moved -- but the signature still travels, because an endpoint that lies about not
    forwarding looks exactly like this.
    """
    from solana.rpc.core import RPCException

    cl = _Client(send_raises=RPCException("custom program error 0x1"))
    with pytest.raises(payment.PaymentNotSettled) as ei:
        _pay(monkeypatch, cl)
    assert ei.value.signature == OURS
    assert "REJECTED" in str(ei.value) or "refused" in str(ei.value).lower(), (
        "a deterministic rejection must not be dressed up as an ambiguous outcome")


# ── F5: the endpoint does not get to name our transaction ──────────────────────────────


def test_the_endpoint_cannot_rename_our_transaction(monkeypatch, harness):
    """A returned signature that is not the one we signed is refused, not adopted.

    If this client polls and returns the endpoint's string, then the whole recovery story
    -- "check signature X on chain" -- confirms a STRANGER'S transaction as ours.
    `settlement.py` already refuses this; this module was the second instance.
    """
    cl = _Client([_status(TCS.Finalized)], returns=THEIRS)
    with pytest.raises(payment.PaymentNotSettled) as ei:
        _pay(monkeypatch, cl)
    assert ei.value.signature == OURS, "the refusal must name OUR signature, not theirs"
    assert THEIRS not in str(ei.value)[:60], (
        "our signature must lead the message: the tools truncate it, and the endpoint "
        "chooses the rest of the text")


def test_confirmation_polls_the_signature_we_signed(monkeypatch, harness):
    """Even on the ordinary success path, the poll must use the LOCAL signature.

    Polling the endpoint's value asks a possibly-hostile party about a transaction it
    chose. This test passes trivially when the two agree -- which is exactly why it is
    written to assert the local one specifically rather than 'a' signature.
    """
    cl = _Client([_status(TCS.Finalized)])
    assert _pay(monkeypatch, cl) == OURS
    assert cl.polled and all(p == OURS for p in cl.polled), (
        f"the confirmation loop polled {cl.polled}, not the signature this client signed")


# ── F3: the tool must not flatten a submitted payment into "failed" ────────────────────


def test_the_send_tool_never_reports_a_submitted_payment_as_a_clean_failure(monkeypatch):
    """`PaymentNotSettled` is a `RuntimeError` subclass, so ordering is load-bearing.

    Its handler must stay ahead of the generic `except Exception`. Nothing pinned that,
    and the generic handler returns `{"status": "failed"}` with no signature -- which
    reads to an agent as "it did not happen" and invites the retry that pays twice.
    """
    from xete_mcp import server

    def _boom(*a, **k):
        raise payment.PaymentUnconfirmed(
            "submitted but not durable", signature=OURS)

    from solders.keypair import Keypair

    monkeypatch.setattr(server.payment, "pay_herd", _boom)
    monkeypatch.setattr(server, "_signing_rpc_url", lambda: "https://rpc.test")
    # Without a payer the tool returns `payment_required` and never reaches the handler
    # under test. An in-memory throwaway key: nothing is signed, `pay_herd` is stubbed.
    monkeypatch.setattr(server, "_load_payer", lambda: Keypair())

    class _C:
        def lookup_agent(self, *a, **k):
            return {"agent_id": "peer", "x25519_public": "k"}

        def send_multi(self, *a, **k):
            # `free_alpha` is the RELAY's wire field name and is deliberately not renamed
            # anywhere in this package -- renaming it breaks payment detection. Falsy here
            # is what puts this send on the paid path at all, which is the configuration
            # F3 and F4 are latent behind today.
            return {"payment_nonce": "n1", "message_count": 1, "amount_sol": 0.001,
                    "free_alpha": False, "amount_lamports": 1000}

    monkeypatch.setattr(server, "_get_client", lambda: _C())

    fn = getattr(server.xete_send_message, "fn", server.xete_send_message)
    out = json.loads(fn("peer", "hello"))

    assert out["status"] != "failed", (
        "a SUBMITTED payment was flattened into a clean failure; the agent is now being "
        "told to retry a payment that may already have landed")
    assert out.get("tx_signature") == OURS, (
        "the signature is the entire recovery path and it did not survive")
    assert "DO_NOT_RETRY_BLINDLY" in out
