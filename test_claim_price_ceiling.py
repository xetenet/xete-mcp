"""`max_price_lamports=0` means THIS CLAIM MUST BE FREE. It used to mean "no ceiling".

THE DEFECT (fresh-context review, F2/HIGH): the code read

    cap = int(max_price_lamports or 0)
    ...
    if cap and quoted > cap:

so `0` and `None` collapsed to the same value and BOTH disabled the check. An agent that
explicitly demanded a free claim -- the natural thing to pass for the 6+ character names this
tool advertises as free by the length rule -- silently got no ceiling at all and paid whatever
the permit server asked, bounded only by the blanket spend cap. The repair DDR asserts the
opposite in writing ("supplied and exceeded -> refused"); it was never true for 0.

The existing `test_max_price_lamports_bounds_what_the_permit_server_can_charge` only ever
exercises cap=1_000_000 and cap=8_000_000. Every one of its assertions passes on the broken
code, because a nonzero cap was the one case that worked. That is why this hole survived a
review that specifically looked at price ceilings.

SECOND DEFECT, introduced by the obvious fix and caught before commit: the parameter DEFAULTED
to 0. Making 0 mean "must be free" while leaving that default turns every priced claim into a
refusal for callers who never asked for a ceiling. The default is now None. The last test here
is the one that would have caught it.
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

PRICED = 8_000_000
RENT_AND_FEES = 1_628_640 + 10_000


def _claim(server, monkeypatch, *, quoted, **kwargs):
    from xete_mcp.client import load_or_create_identity
    _accepting(server, monkeypatch, sim_debit=quoted + RENT_AND_FEES)
    pubkey = load_or_create_identity(server.IDENTITY_PATH).pubkey_b58
    _fake_permit(server, monkeypatch, _mainnet_shaped_claim(pubkey, price=quoted),
                 pubkey, price_lamports=quoted)
    return json.loads(server.xete_alias_claim("mcptestname", **kwargs))


def test_a_zero_ceiling_refuses_a_priced_claim(alias_server, monkeypatch):
    """THE finding. Passing 0 is an agent saying "only if it is free". It was silently
    ignored and the agent paid."""
    r = _claim(alias_server, monkeypatch, quoted=PRICED, max_price_lamports=0)
    assert r["status"] == "refused", r
    assert not _AcceptingRpcClient.submitted, "a claim the caller capped at zero was SUBMITTED"
    assert "free" in r["reason"].lower(), (
        "the refusal does not tell the agent its zero ceiling is why: " + r["reason"])


def test_a_zero_ceiling_still_allows_a_genuinely_free_claim(alias_server, monkeypatch):
    """The bound must not break the case it exists to serve. 6+ character names are free by
    the length rule, and demanding free is exactly when an agent passes 0."""
    r = _claim(alias_server, monkeypatch, quoted=0, max_price_lamports=0)
    assert r["status"] == "claimed", r


def test_omitting_the_ceiling_is_not_the_same_as_asking_for_free(alias_server, monkeypatch):
    """The regression the obvious fix would have shipped. The parameter DEFAULTED to 0, so
    '0 means free' plus that default refuses every priced claim for callers who never asked
    for a ceiling at all. Omitted means no opinion; the spend cap still applies."""
    r = _claim(alias_server, monkeypatch, quoted=PRICED)
    assert r["status"] == "claimed", (
        "a priced claim with NO ceiling supplied was refused -- 'omitted' has collapsed "
        "into 'must be free': " + json.dumps(r)[:300])


def test_a_nonzero_ceiling_still_refuses_above_it(alias_server, monkeypatch):
    r = _claim(alias_server, monkeypatch, quoted=PRICED, max_price_lamports=1_000_000)
    assert r["status"] == "refused", r
    assert not _AcceptingRpcClient.submitted


def test_a_nonzero_ceiling_still_allows_at_or_below_it(alias_server, monkeypatch):
    r = _claim(alias_server, monkeypatch, quoted=PRICED, max_price_lamports=PRICED)
    assert r["status"] == "claimed", r


def test_a_negative_ceiling_is_refused_and_says_how_to_ask_for_free(alias_server, monkeypatch):
    """A negative ceiling is a caller error. The refusal has to name the two things it could
    have meant, or the operator's next guess is another wrong value."""
    r = _claim(alias_server, monkeypatch, quoted=PRICED, max_price_lamports=-1)
    assert r["status"] == "refused", r
    assert "0" in r["reason"] and "free" in r["reason"].lower()
