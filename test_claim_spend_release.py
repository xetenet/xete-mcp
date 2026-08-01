"""Nine attacker-chosen failures must not lock the agent out of its 24-hour window.

THE DEFECT (fresh-context review). `xete_alias_claim` gated the spend and then did all
remaining pre-submission work unguarded. A hostile permit server returns a transaction with a
stale blockhash: simulation passes (replaceRecentBlockhash rewrites it), preflight then rejects
it, and the charge stands. Nine such attempts at the stock per-transaction cap against the stock
window locked the agent out of ALL spending -- messaging included -- having moved zero lamports.
Free, repeatable, and chosen entirely by the remote.

The fix already existed at the sibling call site: payment.pay_herd wraps exactly this span in
_release_recorded_spend + re-raise, implemented in the CALLER using spendguard's own lock, so
the do-not-edit freeze on spendguard.py never blocked it.

SECOND HALF, and the reason the release alone is not enough: send_raw_transaction can raise
AFTER the bytes are on the wire. The generic handler reported {"status": "failed"} with no
signature -- telling an agent nothing happened and inviting a retry that pays the fee twice.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "src"))

from test_signing_regression import (  # noqa: E402
    _accepting, _AcceptingRpcClient, _fake_permit, _mainnet_shaped_claim, alias_server)

__all__ = ["alias_server"]


def _entries(ledger: Path):
    if not ledger.exists():
        return []
    return json.loads(ledger.read_text()).get("entries", [])


def _setup(server, monkeypatch, price=5_000_000):
    from xete_mcp.client import load_or_create_identity
    _accepting(server, monkeypatch, sim_debit=price + 1_628_640 + 10_000)
    pubkey = load_or_create_identity(server.IDENTITY_PATH).pubkey_b58
    _fake_permit(server, monkeypatch, _mainnet_shaped_claim(pubkey, price=price), pubkey,
                 price_lamports=price)
    return pubkey


def test_a_presubmission_failure_gives_the_spend_back(alias_server, monkeypatch, tmp_path):
    """Nothing was signed and nothing was sent, so no lamport can have moved. Charging it is
    over-counting in the one direction that is not safe: it spends the agent's budget on
    something the attacker chose."""
    ledger = tmp_path / "ledger.json"
    monkeypatch.setenv("XETE_SPEND_LEDGER", str(ledger))
    _setup(alias_server, monkeypatch)

    # Fail at Client() construction -- strictly before any signature exists.
    #
    # Patch solana.rpc.api.Client, NOT alias_server.Client. server.py imports Client INSIDE
    # the function, so setattr on the server module with raising=False silently creates an
    # attribute nothing reads: the injection never fires, the claim succeeds, and the test
    # reports the fix as broken. That happened here first.
    import solana.rpc.api as _api
    monkeypatch.setattr(_api, "Client",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("ConnectError")))
    alias_server.xete_alias_claim("mcptestname")

    assert _entries(ledger) == [], (
        "a claim that never reached the signer kept its ledger entry: "
        f"{_entries(ledger)}")


def test_nine_hostile_failures_do_not_exhaust_the_window(alias_server, monkeypatch, tmp_path):
    """The scenario as reported. Before the fix this locked all spending for 24 hours."""
    ledger = tmp_path / "ledger.json"
    monkeypatch.setenv("XETE_SPEND_LEDGER", str(ledger))
    _setup(alias_server, monkeypatch)
    import solana.rpc.api as _api
    monkeypatch.setattr(_api, "Client",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("ConnectError")))

    for _ in range(9):
        alias_server.xete_alias_claim("mcptestname")

    spent = sum(e.get("lamports", 0) for e in _entries(ledger))
    assert spent == 0, (
        f"nine attacker-triggered pre-submission failures consumed {spent} lamports of the "
        "window while moving nothing on chain")


def test_a_submit_that_raises_still_names_the_transaction(alias_server, monkeypatch):
    """send_raw_transaction can raise after the bytes are on the wire. Reporting a bare
    failure with no signature is the benchmarked live-transaction-as-clean-failure defect:
    it tells the agent nothing happened, and the retry pays the fee again."""
    _setup(alias_server, monkeypatch)

    def _boom(self, *a, **k):
        raise RuntimeError("connection reset after write")
    monkeypatch.setattr(_AcceptingRpcClient, "send_raw_transaction", _boom, raising=False)

    r = json.loads(alias_server.xete_alias_claim("mcptestname"))
    assert r["status"] == "submitted_unconfirmed", r
    assert r.get("tx_signature"), "the locally-known signature was discarded on a submit raise"
    assert "DO_NOT_ASSUME_THE_NAME_IS_YOURS" in r
    assert "retry" in r["DO_NOT_ASSUME_THE_NAME_IS_YOURS"].lower()
