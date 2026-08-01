""""claimed" must mean the CHAIN said so, not the permit server.

THE DEFECT (fresh-context review, release blocker). Two ways `xete_alias_claim` reported
`status: "claimed"` on no durable on-chain evidence:

  1. `if st.confirmation_status:` accepted **Processed** -- the last surviving truthy-commitment
     test in the package. settlement.py refuses it in as many words ("one validator's opinion,
     and it can still be forked away") and payment.py refuses it too.
  2. On 30 consecutive Nones the loop simply exhausted and control fell through to
     `/alias/claim/confirm` -- asking THE PARTY THAT BUILT THE TRANSACTION whether the
     transaction worked. server.py's own header promises the permit server "is NOT trusted for
     who owns a name". That promise was false on this path.

Why it matters more than an ordinary wrong status: an operator told they own a %name publishes
it. If the claim never landed, the attacker who withheld it claims the name and receives their
mail.

The permit server's answer is still reported -- under its own key, as its opinion. It just no
longer decides.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from solders.transaction_status import TransactionConfirmationStatus as TCS

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "src"))

from test_signing_regression import (  # noqa: E402
    _accepting, _AcceptingRpcClient, _fake_permit, _mainnet_shaped_claim, alias_server)

__all__ = ["alias_server"]


def _run(server, monkeypatch, *, statuses):
    """Drive a real claim whose confirmation statuses the test controls."""
    from xete_mcp.client import load_or_create_identity
    _accepting(server, monkeypatch, sim_debit=1_628_640 + 10_000)
    pubkey = load_or_create_identity(server.IDENTITY_PATH).pubkey_b58
    _fake_permit(server, monkeypatch, _mainnet_shaped_claim(pubkey, price=0), pubkey,
                 price_lamports=0)
    seq = list(statuses)

    class _St:
        def __init__(self, cs):
            self.confirmation_status = cs
            self.err = None

    def statuses_fn(sigs):
        from types import SimpleNamespace
        cs = seq.pop(0) if seq else None
        return SimpleNamespace(value=[_St(cs) if cs is not None else None])

    monkeypatch.setattr(_AcceptingRpcClient, "get_signature_statuses",
                        lambda self, sigs: statuses_fn(sigs), raising=False)
    monkeypatch.setattr(server, "_t", type("T", (), {"sleep": staticmethod(lambda *_: None)}),
                        raising=False)
    return json.loads(server.xete_alias_claim("mcptestname"))


def test_a_durable_confirmation_is_what_licenses_claimed(alias_server, monkeypatch):
    r = _run(alias_server, monkeypatch, statuses=[TCS.Confirmed])
    assert r["status"] == "claimed", r


def test_processed_alone_does_not_license_claimed(alias_server, monkeypatch):
    """Processed can be forked away. This package refuses it for payments and for settlement;
    it was accepted here, which made the claim tool the weakest of the three."""
    r = _run(alias_server, monkeypatch, statuses=[TCS.Processed] * 40)
    assert r["status"] == "submitted_unconfirmed", r
    assert r.get("tx_signature"), "the signature was dropped -- it is the whole recovery path"


def test_the_permit_server_cannot_declare_the_name_claimed(alias_server, monkeypatch):
    """The 30-None path. The permit server BUILT this transaction; asking it whether the
    transaction worked is not evidence, and the module header explicitly promises it is not
    trusted for who owns a name."""
    r = _run(alias_server, monkeypatch, statuses=[])          # every poll answers None
    assert r["status"] == "submitted_unconfirmed", r
    assert "DO_NOT_ASSUME_THE_NAME_IS_YOURS" in r, (
        "an unconfirmed claim carries no warning; an operator would publish the %name")
    assert r.get("permit_server_says") is not None, (
        "the permit server's answer was dropped entirely -- it should be reported as its "
        "opinion, just not treated as proof")
    assert "resolve" in r["DO_NOT_ASSUME_THE_NAME_IS_YOURS"].lower(), (
        "the warning does not tell the agent how to actually check")
