"""Tests for the client-side spend limits (src/xete_mcp/spendguard.py).

Runs offline: nothing here touches the network, a real wallet, or the real ~/.xete/.
Every test points XETE_SPEND_LEDGER at a temporary directory.

Run with:  python -m pytest test_spendguard.py -v
"""
from __future__ import annotations

import ast
import base64
import hashlib
import importlib
import json

from solders.transaction_status import TransactionConfirmationStatus as _TCS
import os
import stat
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent
SRC = REPO / "src"
sys.path.insert(0, str(SRC))

from xete_mcp import spendguard  # noqa: E402

SPEND_ENV = [
    spendguard.ENV_MAX,
    spendguard.ENV_WINDOW,
    spendguard.ENV_WINDOW_SECONDS,
    spendguard.ENV_FLOOR,
    spendguard.ENV_LEDGER,
]


@pytest.fixture()
def ledger(tmp_path, monkeypatch):
    """A clean ledger in a temp dir, with every spend env var under our control."""
    for name in SPEND_ENV:
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / ".xete" / "spend-ledger.json"
    monkeypatch.setenv(spendguard.ENV_LEDGER, str(path))
    monkeypatch.setenv(spendguard.ENV_FLOOR, "0")   # off unless a test is about the floor
    return path


def _entries(path: Path) -> list:
    return json.loads(path.read_text())["entries"]


# ── defaults: never unlimited ────────────────────────────────────────────────────────

def test_defaults_are_conservative_and_finite(monkeypatch):
    for name in SPEND_ENV:
        monkeypatch.delenv(name, raising=False)
    assert 0 < spendguard.DEFAULT_MAX_LAMPORTS < spendguard.LAMPORTS_PER_SOL
    assert 0 < spendguard.DEFAULT_WINDOW_LAMPORTS < spendguard.LAMPORTS_PER_SOL
    assert spendguard.DEFAULT_WINDOW_SECONDS > 0
    assert spendguard.DEFAULT_FLOOR_LAMPORTS > 0
    # A single spend can never exceed the window on the defaults.
    assert spendguard.DEFAULT_MAX_LAMPORTS <= spendguard.DEFAULT_WINDOW_LAMPORTS


def test_unset_limits_still_refuse_a_large_spend(ledger, monkeypatch):
    monkeypatch.delenv(spendguard.ENV_FLOOR, raising=False)
    with pytest.raises(spendguard.SpendRefused) as ex:
        spendguard.authorize(5 * spendguard.LAMPORTS_PER_SOL, "xete_settle_create")
    assert "per-transaction cap" in str(ex.value)


def test_default_ledger_lives_under_dot_xete(monkeypatch):
    monkeypatch.delenv(spendguard.ENV_LEDGER, raising=False)
    path = spendguard.ledger_path()
    assert path.parent.name == ".xete"
    assert path.name == "spend-ledger.json"
    assert path.name != "identity.json"


# ── per-transaction cap ──────────────────────────────────────────────────────────────

def test_per_transaction_cap_allows_at_the_boundary(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "1000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW, "100000000")
    result = spendguard.authorize(1_000_000, "xete_send_message")
    assert result["charged_lamports"] == 1_000_000


def test_per_transaction_cap_refuses_one_lamport_over(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "1000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW, "100000000")
    with pytest.raises(spendguard.SpendRefused) as ex:
        spendguard.authorize(1_000_001, "xete_settle_create")
    msg = str(ex.value)
    assert "per-transaction cap" in msg
    assert "1000001" in msg and "1000000" in msg          # attempted and the limit
    assert "waiting will not help" in msg                  # tells the agent not to retry
    assert "Nothing was signed" in msg
    assert not ledger.exists() or _entries(ledger) == []   # a refusal records nothing


# ── windowed cap ─────────────────────────────────────────────────────────────────────

def test_window_accumulates_and_then_refuses(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW, "3000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW_SECONDS, "3600")
    spendguard.authorize(1_000_000, "xete_send_message")
    spendguard.authorize(1_000_000, "xete_send_message")
    spendguard.authorize(1_000_000, "xete_send_message")
    with pytest.raises(spendguard.SpendRefused) as ex:
        spendguard.authorize(1_000_000, "xete_send_message")
    msg = str(ex.value)
    assert "windowed cap" in msg
    assert "3000000" in msg                       # the limit
    assert "1000000" in msg                       # what was attempted
    assert "frees up at" in msg                   # when budget returns
    assert "in 1h 0m" in msg or "in 59m" in msg   # ...expressed as a wait, too
    assert len(_entries(ledger)) == 3             # the refused one was not recorded


def test_window_refusal_names_a_reachable_time(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW, "2000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW_SECONDS, "600")
    spendguard.authorize(2_000_000, "xete_send_message")
    with pytest.raises(spendguard.SpendRefused) as ex:
        spendguard.authorize(1_000_000, "xete_send_message")
    assert "frees up at" in str(ex.value)
    assert "never inside" not in str(ex.value)


def test_spend_larger_than_the_whole_window_says_never(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW, "3000000")
    with pytest.raises(spendguard.SpendRefused) as ex:
        spendguard.authorize(4_000_000, "xete_settle_create")
    assert "never inside" in str(ex.value)


def test_entries_outside_the_window_stop_counting(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW, "1000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW_SECONDS, "3600")
    spendguard.authorize(1_000_000, "xete_send_message")
    with pytest.raises(spendguard.SpendRefused):
        spendguard.authorize(1_000_000, "xete_send_message")

    # Age the recorded spend past the window.
    data = json.loads(ledger.read_text())
    data["entries"][0]["ts"] -= 3601
    ledger.write_text(json.dumps(data))

    assert spendguard.authorize(1_000_000, "xete_send_message")["approved"] is True


# ── persistence: a restart is not a fresh budget ─────────────────────────────────────

def test_budget_survives_a_process_restart(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW, "2000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW_SECONDS, "3600")
    monkeypatch.setenv(spendguard.ENV_FLOOR, "0")

    env = dict(os.environ)
    prog = (
        f"import sys; sys.path.insert(0, {str(SRC)!r})\n"
        "from xete_mcp import spendguard\n"
        "try:\n"
        "    spendguard.authorize(2_000_000, 'xete_send_message'); print('OK')\n"
        "except spendguard.SpendRefused:\n"
        "    print('REFUSED')\n"
    )
    first = subprocess.run([sys.executable, "-c", prog], capture_output=True, text=True, env=env)
    second = subprocess.run([sys.executable, "-c", prog], capture_output=True, text=True, env=env)
    assert first.stdout.strip() == "OK", first.stderr
    # A brand new process must NOT get a fresh window.
    assert second.stdout.strip() == "REFUSED", second.stderr


# ── concurrency ──────────────────────────────────────────────────────────────────────

def test_racing_processes_cannot_both_pass_a_check_only_one_should(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "1000000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW, "10000000")     # room for exactly 10
    monkeypatch.setenv(spendguard.ENV_WINDOW_SECONDS, "3600")
    monkeypatch.setenv(spendguard.ENV_FLOOR, "0")

    env = dict(os.environ)
    prog = (
        f"import sys; sys.path.insert(0, {str(SRC)!r})\n"
        "from xete_mcp import spendguard\n"
        "try:\n"
        "    spendguard.authorize(1_000_000, 'race'); print('OK')\n"
        "except spendguard.SpendRefused:\n"
        "    print('REFUSED')\n"
    )

    def run(_):
        return subprocess.run([sys.executable, "-c", prog],
                              capture_output=True, text=True, env=env).stdout.strip()

    with ThreadPoolExecutor(max_workers=30) as pool:
        results = list(pool.map(run, range(30)))

    assert results.count("OK") == 10, results
    assert results.count("REFUSED") == 20, results
    total = sum(e["lamports"] for e in _entries(ledger))
    assert total == 10_000_000       # never over the cap, not even by one lamport


# ── ledger integrity: corruption must not reset the budget ───────────────────────────

@pytest.mark.parametrize("blob", [
    "",                                             # truncated to nothing
    "not json at all",
    "[]",                                           # right JSON, wrong shape
    '{"version": 1, "entries": "lots"}',
    '{"version": 1, "entries": [{"ts": "soon", "lamports": 5}]}',
    '{"version": 1, "entries": [{"ts": 1.0, "lamports": -5000}]}',
    '{"version": 1, "entries": [{"ts": 1.0, "lamports": "5000"}]}',
    '{"version": 1, "entries": [], "last_ts": "yesterday"}',
])
def test_a_damaged_ledger_refuses_rather_than_resetting(ledger, monkeypatch, blob):
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text(blob)
    with pytest.raises(spendguard.SpendGuardUnavailable) as ex:
        spendguard.authorize(1_000, "xete_send_message")
    assert "NOT being reset" in str(ex.value)
    assert ledger.read_text() == blob      # and it did not overwrite the evidence


def test_an_unknown_ledger_version_refuses(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text(json.dumps({"version": 999, "last_ts": 0, "entries": []}))
    with pytest.raises(spendguard.SpendGuardUnavailable) as ex:
        spendguard.authorize(1_000, "xete_send_message")
    assert "version" in str(ex.value)


def test_rolling_the_ledger_back_does_not_grant_more_than_the_window(ledger, monkeypatch):
    """A snapshot-and-restore of the ledger is a rollback. It cannot exceed the cap,
    because the restored file is itself subject to the same window arithmetic."""
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW, "2000000")
    spendguard.authorize(1_000_000, "xete_send_message")
    snapshot = ledger.read_text()
    spendguard.authorize(1_000_000, "xete_send_message")
    with pytest.raises(spendguard.SpendRefused):
        spendguard.authorize(1_000_000, "xete_send_message")

    ledger.write_text(snapshot)            # roll back one spend
    spendguard.authorize(1_000_000, "xete_send_message")   # the rolled-back one is re-spendable
    with pytest.raises(spendguard.SpendRefused):
        spendguard.authorize(1_000_000, "xete_send_message")
    # i.e. rollback replays budget but never lifts the ceiling above the window.


def test_no_temp_files_are_left_behind(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    for _ in range(5):
        spendguard.authorize(1_000, "xete_send_message")
    leftovers = [p.name for p in ledger.parent.iterdir() if ".tmp" in p.name]
    assert leftovers == []


# ── configuration errors fail closed ─────────────────────────────────────────────────

@pytest.mark.parametrize("value", ["abc", "1.5", "0x10", " ten ", "1,000", "1e6"])
def test_malformed_limit_refuses_every_spend(ledger, monkeypatch, value):
    monkeypatch.setenv(spendguard.ENV_MAX, value)
    with pytest.raises(spendguard.SpendGuardUnavailable) as ex:
        spendguard.authorize(1, "xete_send_message")
    assert spendguard.ENV_MAX in str(ex.value)
    assert "not a whole number" in str(ex.value)


def test_negative_limit_refuses_every_spend(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_WINDOW, "-1")
    with pytest.raises(spendguard.SpendGuardUnavailable):
        spendguard.authorize(1, "xete_send_message")


def test_zero_cap_disables_spending_with_a_clear_reason(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "0")
    with pytest.raises(spendguard.SpendRefused) as ex:
        spendguard.authorize(1, "xete_send_message")
    assert "disabled by" in str(ex.value)


def test_floor_above_cap_is_reported_as_contradictory(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "1000")
    monkeypatch.setenv(spendguard.ENV_FLOOR, "2000")
    with pytest.raises(spendguard.SpendGuardUnavailable) as ex:
        spendguard.authorize(1, "xete_send_message")
    assert "contradictory configuration" in str(ex.value)


def test_zero_window_seconds_is_refused(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_WINDOW_SECONDS, "0")
    with pytest.raises(spendguard.SpendGuardUnavailable):
        spendguard.authorize(1, "xete_send_message")


# ── the on-chain floor ───────────────────────────────────────────────────────────────

def test_a_zero_quote_still_costs_budget(ledger, monkeypatch):
    """A free 6+ letter %name quotes 0 but still burns rent and gas. Charging the floor
    is what stops an unbounded loop of 'free' claims from draining the wallet."""
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW, "5000000")
    monkeypatch.setenv(spendguard.ENV_FLOOR, "2000000")
    for _ in range(2):
        assert spendguard.authorize(0, "xete_alias_claim")["charged_lamports"] == 2_000_000
    with pytest.raises(spendguard.SpendRefused) as ex:
        spendguard.authorize(0, "xete_alias_claim")
    assert "windowed cap" in str(ex.value)
    assert "quoted 0 SOL" in str(ex.value)      # honest about quote vs charge


def test_the_floor_never_lowers_a_real_quote(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    monkeypatch.setenv(spendguard.ENV_FLOOR, "2000000")
    assert spendguard.authorize(9_000_000, "xete_alias_claim")["charged_lamports"] == 9_000_000


# ── the clock ────────────────────────────────────────────────────────────────────────

def test_a_backwards_clock_does_not_age_spending_out_early(ledger, monkeypatch):
    """A clock correction must not stamp new spends into the past, where a later
    correction forwards would expire them prematurely."""
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW, "10000000")
    future = time.time() + 100_000
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text(json.dumps({"version": 1, "last_ts": future, "entries": []}))

    spendguard.authorize(1_000, "xete_send_message")

    data = json.loads(ledger.read_text())
    assert data["entries"][0]["ts"] == pytest.approx(future, abs=1.0)
    assert data["last_ts"] >= future


def test_a_normal_clock_stamps_now(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    before = time.time()
    spendguard.authorize(1_000, "xete_send_message")
    assert _entries(ledger)[0]["ts"] == pytest.approx(before, abs=5.0)


# ── the filesystem ───────────────────────────────────────────────────────────────────

@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                    reason="root ignores directory permissions")
def test_an_unwritable_directory_refuses_the_spend(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    ledger.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(ledger.parent, 0o500)
    try:
        with pytest.raises(spendguard.SpendGuardUnavailable) as ex:
            spendguard.authorize(1_000, "xete_send_message")
        assert "cannot be limited" in str(ex.value)
    finally:
        os.chmod(ledger.parent, 0o700)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_identity_json_is_never_touched(ledger, monkeypatch):
    """~/.xete/ holds the identity keystore. The ledger shares the directory and must
    leave the keystore, and the directory's own mode, exactly as it found them."""
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    xete_dir = ledger.parent
    xete_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(xete_dir, 0o755)                     # deliberately NOT 0o700
    identity = xete_dir / "identity.json"
    identity.write_text('{"secret": "do not touch"}')
    os.chmod(identity, 0o600)

    before_dir_mode = stat.S_IMODE(xete_dir.stat().st_mode)
    before_id = (identity.read_bytes(), stat.S_IMODE(identity.stat().st_mode),
                 identity.stat().st_mtime_ns)

    for _ in range(3):
        spendguard.authorize(1_000, "xete_send_message")

    assert stat.S_IMODE(xete_dir.stat().st_mode) == before_dir_mode
    assert (identity.read_bytes(), stat.S_IMODE(identity.stat().st_mode),
            identity.stat().st_mtime_ns) == before_id


def test_the_ledger_refuses_to_be_aimed_at_the_keystore(tmp_path, monkeypatch):
    for name in SPEND_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(spendguard.ENV_LEDGER, str(tmp_path / ".xete" / "identity.json"))
    with pytest.raises(spendguard.SpendGuardUnavailable) as ex:
        spendguard.authorize(1, "xete_send_message")
    assert "identity keystore" in str(ex.value)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
def test_a_ledger_symlinked_onto_the_keystore_cannot_destroy_it(ledger, monkeypatch):
    """If the ledger path is a symlink pointing at the keystore, reading it must fail
    closed and the keystore must survive untouched."""
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    ledger.parent.mkdir(parents=True, exist_ok=True)
    identity = ledger.parent / "identity.json"
    identity.write_text('{"secret": "do not touch"}')
    ledger.symlink_to(identity)

    with pytest.raises(spendguard.SpendGuardUnavailable):
        spendguard.authorize(1_000, "xete_send_message")

    assert identity.read_text() == '{"secret": "do not touch"}'
    assert identity.is_file() and not identity.is_symlink()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_a_directory_we_create_is_private(tmp_path, monkeypatch):
    for name in SPEND_ENV:
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / "fresh" / ".xete" / "spend-ledger.json"
    monkeypatch.setenv(spendguard.ENV_LEDGER, str(path))
    spendguard.authorize(1_000, "xete_send_message")
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


# ── housekeeping ─────────────────────────────────────────────────────────────────────

def test_compaction_preserves_the_total(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW, "1000000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW_SECONDS, "86400")
    now = time.time()
    entries = [{"ts": now - i, "lamports": 100, "path": "x", "detail": ""}
               for i in range(spendguard.MAX_ENTRIES + 500)]
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text(json.dumps({"version": 1, "last_ts": now, "entries": entries}))

    spendguard.authorize(50, "xete_send_message")

    after = _entries(ledger)
    assert len(after) <= spendguard.MAX_ENTRIES
    assert sum(e["lamports"] for e in after) == 100 * len(entries) + 50


def test_status_reports_the_limits_and_the_remaining_budget(ledger, monkeypatch):
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW, "5000000")
    spendguard.authorize(1_000_000, "xete_send_message")
    s = spendguard.status()
    assert s["enforced"] is True
    assert s["per_transaction_max_lamports"] == 10_000_000
    assert s["window_spent_lamports"] == 1_000_000
    assert s["window_remaining_lamports"] == 4_000_000
    assert s["transactions_in_window"] == 1
    assert "error" not in s


def test_status_surfaces_a_broken_ledger_instead_of_lying(ledger, monkeypatch):
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text("garbage")
    s = spendguard.status()
    assert "error" in s and s["enforced"] is True


# ── the anti-bypass tripwire ─────────────────────────────────────────────────────────
#
# A gate that one path routes around is worthless. This walks the AST of every module in
# src/xete_mcp and finds every place that submits a transaction, adds a signature, or
# loads a signing key. The result must match the table below EXACTLY: a new spending path
# fails this test until somebody either gates it or writes down why it needs no gate.
#
# FINDING [F2]. The first version of this scan was name-based and evadable two ways, both
# demonstrated by the reviewer against this very package:
#
#   (a) it globbed `(SRC/"xete_mcp").glob("*.py")` — NON-recursive — so any module added
#       in a subpackage was invisible to it. `rglob` now.
#   (b) its name lists were short of real spellings that already work here:
#       `Keypair.from_base58_string`, `tx.sign(...)`, `send_and_confirm_transaction`, an
#       aliased import (`from solders.keypair import Keypair as KP` defeated a scan that
#       compared the LOCAL name), and a raw JSON-RPC `sendTransaction` posted through
#       httpx or requests, which names no solana symbol at all.
#   (c) it only walked FunctionDef/AsyncFunctionDef, so module-level code — which runs at
#       import, before any caller can gate anything — was never scanned.
#
# All three are closed below, and `test_the_tripwire_sees_past_every_way_around_its_name_list`
# builds a scratch subpackage that uses every one of those spellings and asserts each is
# caught. A name list can never be complete; what it can be is wide enough that going
# around it is a deliberate act rather than an ordinary import.

# Adding a signature to a transaction, or putting one on the wire. Used BOTH by the census
# below and by the gate-ordering rule in `_assert_gate_discipline`.
SUBMIT_OR_SIGN = {"send_transaction", "send_raw_transaction",
                  "send_and_confirm_transaction", "partial_sign"}

# The census is wider than the ordering rule: a bare `.sign(...)` is any use of a private
# key, transaction or not. It is deliberately NOT in SUBMIT_OR_SIGN, because
# `xete_alias_claim` legitimately signs the permit server's AUTH CHALLENGE before the spend
# gate runs — that signature moves no money — and an ordering rule that counted it would
# have to be weakened to something that no longer says "gate before you spend".
KEY_USE_CALLS = SUBMIT_OR_SIGN | {"sign"}

# Loading an EXISTING private key. `Keypair()` (fresh, random) is not a loader.
KEY_LOADER_METHODS = {"from_seed", "from_bytes", "from_base58_string"}
# Matched against the IMPORTED path, so `from solders.keypair import Keypair as KP` is
# still Keypair. The bare spelling stays as a fallback for a name this scan cannot resolve
# to an import — over-flagging is the safe direction for a tripwire.
KEY_CLASSES = {"solders.keypair.Keypair", "Keypair"}

# A transaction submitted as raw JSON-RPC names no library symbol at all: the only thing
# that identifies it is the method string in the request body.
RPC_SUBMIT_METHOD = "sendTransaction"

EXPECTED_TOUCHPOINTS = {
    ("payment.py", "pay_herd"):
        "GATED — calls spendguard.authorize before building or signing anything",
    ("settlement.py", "_send"):
        "EXEMPT — shared submitter. Its only spending caller, deposit(), gates before "
        "calling it; claim() and reclaim() are income, see below",
    ("server.py", "_load_payer"):
        "EXEMPT — reads the payer keypair but spends nothing itself; every consumer is gated",
    ("server.py", "xete_alias_claim"):
        "GATED — calls spendguard.authorize before txguard.approve_and_sign. Its earlier "
        "`.sign()` is the permit server's auth challenge, which signguard validates and "
        "which moves nothing",
    ("txguard.py", "approve_and_sign"):
        "EXEMPT — the signing chokepoint itself. It signs nothing it was not handed a "
        "matching ClaimInspection for, and its only caller in this package is "
        "xete_alias_claim, which gates first (asserted in test_signing_regression.py)",
    ("server.py", "xete_settle_create"):
        "GATED indirectly — the spend happens inside settlement.deposit, which gates",
    ("server.py", "xete_settle_claim"):
        "EXEMPT — income. Claiming funds addressed to this agent; a cap here would block a "
        "user from collecting money owed to them",
    ("server.py", "xete_settle_reclaim"):
        "EXEMPT — income. Recovering this agent's own deposit; net positive",

    # ── newly VISIBLE, not newly unsafe ────────────────────────────────────────────────
    # These five reach a submitter through a module-local helper call, which the scan used
    # to discard because it only looked at attribute calls. Every one of them was already
    # correct; the control simply could not see them. Each is classified on its own merits
    # below rather than waved through as a batch — a blanket exemption here would recreate
    # the blindness in table form.
    ("settlement.py", "deposit"):
        "GATED — calls authorize() at settlement.py:511 before any transaction is built, "
        "and it is in GATED_DIRECTLY, which asserts that independently",
    ("settlement.py", "claim"):
        "EXEMPT — income. Proves you are the hidden beneficiary and RECEIVES funds; it "
        "moves money toward this agent, and a cap here would block someone collecting what "
        "is owed to them. Costs only a signature fee",
    ("settlement.py", "reclaim"):
        "EXEMPT — income. Depositor-only cancel that returns the funds AND the rent. Net "
        "positive to this agent by construction",
    ("server.py", "xete_send_message"):
        "GATED indirectly — the only spend is inside payment.pay_herd, which gates before "
        "it builds or signs. Reaches a submitter here only via _load_payer, which loads a "
        "key and spends nothing",
    ("server.py", "xete_my_identity"):
        "EXEMPT — reports identity and spend limits. It touches _load_payer to say whether "
        "a payer is configured and never builds, signs or submits anything",
    # The three below are new to the table only because the census now sees `.sign(...)`.
    # None of them spends; all three are places the identity key is used, which is exactly
    # what a census of key use is for.
    ("client.py", "derive_x25519_secret"):
        "EXEMPT — signs the ONE reserved derivation constant with nacl to produce the "
        "messaging secret. Spends nothing; the signature never leaves the process (only "
        "SHA256 of it does), and signguard refuses this constant everywhere else",
    ("client.py", "login"):
        "EXEMPT — signs the relay's auth challenge, after validate_relay_auth_challenge "
        "has proved it is the template bound to our nonce. An authentication signature "
        "over printable ASCII moves no lamports",
    ("signguard.py", "sign"):
        "EXEMPT — GuardedSigningKey.sign IS the guard: it runs assert_signable and only "
        "then delegates to nacl. Refusing binary is its whole job",
    ("client.py", "__post_init__"):
        "EXEMPT — Identity.__post_init__ derives the messaging key at construction by "
        "calling derive_x25519_secret, which is itself exempt above. Visible only through "
        "the transitive pass; its whole body is bytes/len/append plus that one call, and it "
        "builds, signs and submits nothing",
}

GATED_DIRECTLY = [
    ("payment.py", "pay_herd"),
    ("settlement.py", "deposit"),
    ("server.py", "xete_alias_claim"),
]


def _with_local_helpers(found: dict, root: Path) -> dict:
    """Extend `found` through module-local helper calls, to a fixed point.

    THE HOLE: every money function in settlement.py submits through `_send(...)`, a
    module-local ast.NAME call. A scanner that only classifies attribute calls cannot see
    the idiom this package actually uses, so the control meant to catch an ungated spending
    path was blind to the spelling that path would be written in. Reproduced: a
    `sweep_everything()` calling `_send(...)` left every meta-test green.

    A helper calling a helper calling a submitter is still a spending path, so this runs to
    a fixed point rather than one level deep.
    """
    changed = True
    while changed:
        changed = False
        for pyfile in sorted(root.rglob("*.py")):
            name = pyfile.relative_to(root).as_posix()
            tree = ast.parse(pyfile.read_text(encoding="utf-8"), filename=str(pyfile))
            known = {scope for (f, scope) in found if f == name}
            for scope, stmts in _scopes(tree):
                if (name, scope) in found:
                    continue
                for call in _calls_in(stmts):
                    if isinstance(call.func, ast.Name) and call.func.id in known:
                        found[(name, scope)] = [(f"-> {call.func.id}()", call.lineno)]
                        changed = True
                        break
    return found


def _import_aliases(tree) -> dict:
    """local name -> the dotted path it was imported from.

    Every Import/ImportFrom in the module, not just the top-level ones: this package
    imports solders INSIDE functions on several paths, and a scan that only read
    module-level imports would resolve those names to nothing.
    """
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                out[alias.asname or alias.name] = f"{module}.{alias.name}" if module else alias.name
    return out


def _scopes(tree):
    """(name, statements) for every function AND for the module's own body.

    Module-level code runs at import — before any caller exists to gate it — so it is
    scanned as a synthetic function called `<module>`. Class bodies are module-level code
    too and are folded in; a `def` inside a class is a function and gets its own scope.
    """
    def module_level(body):
        keep = []
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(stmt, ast.ClassDef):
                keep.extend(module_level(stmt.body))
                continue
            keep.append(stmt)
        return keep

    scopes = [("<module>", module_level(tree.body))]
    scopes += [(n.name, n.body) for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    return scopes


def _calls_in(stmts):
    """Every Call reachable from `stmts` without descending into a nested `def`.

    Nested functions are visited as their own scope, so descending would report the same
    call twice under two different names.
    """
    out = []

    def rec(node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return
        if isinstance(node, ast.Call):
            out.append(node)
        for child in ast.iter_child_nodes(node):
            rec(child)

    for stmt in stmts:
        rec(stmt)
    return out


def _why_flagged(call, aliases):
    """Why this call uses a key, or None. The reason string is for the failure message."""
    func = call.func
    if isinstance(func, ast.Attribute):
        if func.attr in KEY_USE_CALLS:
            return func.attr
        if func.attr in KEY_LOADER_METHODS and isinstance(func.value, ast.Name):
            base = func.value.id
            if aliases.get(base, base) in KEY_CLASSES:
                return f"{base}.{func.attr}"
    # Raw JSON-RPC: the method name is a string somewhere in the arguments, typically
    # `json={"method": "sendTransaction", ...}`. Walk the whole call so it does not matter
    # whether it arrived positionally, as a keyword, or nested in a dict.
    for node in ast.walk(call):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and RPC_SUBMIT_METHOD in node.value:
            return f"json-rpc {RPC_SUBMIT_METHOD}"
    return None


def _touchpoints(root: Path | None = None) -> dict:
    """{(module path, scope): [(why, line)]} for every key-using site under `root`.

    `root` is a parameter so the evasion test below can point it at a scratch package
    instead of at src/. rglob, not glob: a module one directory down was invisible.
    """
    root = root if root is not None else (SRC / "xete_mcp")
    found = {}
    for pyfile in sorted(root.rglob("*.py")):
        tree = ast.parse(pyfile.read_text(encoding="utf-8"), filename=str(pyfile))
        aliases = _import_aliases(tree)
        name = pyfile.relative_to(root).as_posix()
        for scope, stmts in _scopes(tree):
            for call in _calls_in(stmts):
                why = _why_flagged(call, aliases)
                if why:
                    found.setdefault((name, scope), []).append((why, call.lineno))
    return _with_local_helpers(found, root)
    return found


# A module that spends without gating, written five ways the ORIGINAL name-based scan
# could not see. It lives in a subpackage because the original glob was not recursive.
_EVASIVE_SPENDER = '''
"""Ungated spending, spelled so that a name list has to work for its living."""
import httpx
from solders.keypair import Keypair as KP

# Runs at import. The original scan only walked function bodies, so this was invisible
# no matter what it was spelled as.
_HOT_KEY = KP.from_base58_string("4wBqpZM9...")


def aliased_import(seed):
    return KP.from_seed(seed)


def transaction_sign(tx, keypair):
    tx.sign([keypair], tx.message.recent_blockhash)


def confirm_and_send(client, tx):
    return client.send_and_confirm_transaction(tx)


def raw_json_rpc(url, raw):
    return httpx.post(url, json={"jsonrpc": "2.0", "id": 1,
                                 "method": "sendTransaction", "params": [raw]})
'''


def test_the_tripwire_sees_past_every_way_around_its_name_list(tmp_path):
    """Finding [F2]: each of these was demonstrated against the previous scan, and each
    one is a spelling that works today with the libraries this package already depends on.

    Written as a permanent test rather than a one-off scratch file, because the reason the
    holes existed is that nothing was checking. The scratch package is built in tmp_path
    and thrown away with it.
    """
    pkg = tmp_path / "xete_mcp"
    (pkg / "deeper").mkdir(parents=True)
    (pkg / "deeper" / "spender.py").write_text(_EVASIVE_SPENDER, encoding="utf-8")

    found = _touchpoints(pkg)
    reasons = {scope: [why for why, _line in hits] for (_f, scope), hits in found.items()}

    assert all(f == "deeper/spender.py" for f, _s in found), (
        f"a module one directory down was not scanned at all: {sorted(found)}")
    assert "from_base58_string" in " ".join(reasons.get("<module>", [])), (
        "a key loaded at MODULE level, which runs at import, was not seen: "
        f"{reasons}")
    assert reasons.get("aliased_import") == ["KP.from_seed"], (
        f"an aliased `Keypair as KP` import defeated the loader check: {reasons}")
    assert reasons.get("transaction_sign") == ["sign"], f"tx.sign() was missed: {reasons}"
    assert reasons.get("confirm_and_send") == ["send_and_confirm_transaction"], (
        f"send_and_confirm_transaction was missed: {reasons}")
    assert reasons.get("raw_json_rpc") == [f"json-rpc {RPC_SUBMIT_METHOD}"], (
        f"a raw JSON-RPC submission through httpx names no solana symbol and was "
        f"missed: {reasons}")


def test_every_signing_site_is_gated_or_explicitly_exempt():
    found = set(_touchpoints())
    expected = set(EXPECTED_TOUCHPOINTS)
    unclassified = found - expected
    assert not unclassified, (
        "New code submits a transaction, signs, or loads a signing key in a function that "
        "the spend gate does not know about:\n  "
        + "\n  ".join(f"{f}:{fn}" for f, fn in sorted(unclassified))
        + "\n\nEither call spendguard.authorize() before it spends, or add it to "
          "EXPECTED_TOUCHPOINTS with the reason it needs no gate."
    )
    assert not (expected - found), (
        "A known signing site disappeared; update EXPECTED_TOUCHPOINTS: "
        f"{sorted(expected - found)}"
    )


_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _gate_and_sign_lines(tree, funcname):
    """(gate-call lines, sign/submit lines, gate-call lines that run INSIDE A LOOP) in `funcname`.

    The third value exists because "how many times does the source SAY authorize()" and "how many
    times does it RUN" are different questions, and only the second one is about money. One call
    in a loop body is one line and N charges.
    """
    func = next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == funcname)

    gate_lines, sign_lines, looped_gates = [], [], []

    def visit(node, in_loop: bool) -> None:
        if isinstance(node, ast.Call):
            name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if name in ("authorize", "_authorize_spend"):
                gate_lines.append(node.lineno)
                if in_loop:
                    looped_gates.append(node.lineno)
            if getattr(node.func, "attr", None) in SUBMIT_OR_SIGN:
                sign_lines.append(node.lineno)

        # Per-node accuracy, not a blanket "anything under a loop node". A `for`'s iterable and
        # a `for`/`while`'s `else:` run exactly once; the body does not, and a `while`'s test is
        # re-evaluated every iteration.
        if isinstance(node, (ast.For, ast.AsyncFor)):
            visit(node.target, in_loop)
            visit(node.iter, in_loop)
            for stmt in node.body:
                visit(stmt, True)
            for stmt in node.orelse:
                visit(stmt, in_loop)
            return
        if isinstance(node, ast.While):
            visit(node.test, True)
            for stmt in node.body:
                visit(stmt, True)
            for stmt in node.orelse:
                visit(stmt, in_loop)
            return
        if isinstance(node, _COMPREHENSIONS):
            for child in ast.iter_child_nodes(node):
                visit(child, True)
            return

        for child in ast.iter_child_nodes(node):
            visit(child, in_loop)

    visit(func, False)
    return sorted(gate_lines), sorted(sign_lines), sorted(looped_gates)


def _assert_gate_discipline(tree, filename, funcname):
    """The three properties a directly-gated spending path must have: it gates, it gates
    EXACTLY ONCE, and it gates before it signs.

    Factored out of the test so the test below can run it against a deliberately
    double-gated source and prove the middle property is actually enforced.
    """
    gate_lines, sign_lines, looped_gates = _gate_and_sign_lines(tree, funcname)

    assert gate_lines, f"{filename}:{funcname} never calls the spend gate"

    # A count of SOURCE LINES is not a count of CHARGES. One authorize() inside a loop body is
    # one line and N ledger entries, so `len(gate_lines) == 1` alone would wave it through —
    # raised by the fresh-context reviewer of the G22 fix as the cheapest way past the new rule.
    assert not looped_gates, (
        f"{filename}:{funcname} calls the spend gate inside a loop (line(s) {looped_gates}). "
        "That is one line and one charge per iteration. Authorize the whole spend once, "
        "outside the loop.")

    # EXACTLY ONCE — finding [G22]. `authorize()` records against the 24h window at approval
    # time, so a path that gates twice charges the ledger twice for one spend. That is
    # precisely the defect the integrator's hunk-3 merge resolution was guarding against (the
    # naive union merge reinstated a dropped early gate), and this tripwire — which asserted
    # only that a gate EXISTS and PRECEDES signing — passed on the double-gated source. The
    # only thing that went red was an unrelated window-cap figure in one signing fixture:
    # XETE_SPEND_WINDOW_LAMPORTS=100000000 against a 50M + 51.6M double charge. A slightly
    # larger fixture figure and the double-charge ships green. The guard the resolution
    # depends on now has an assertion of its own rather than a coincidence.
    assert len(gate_lines) == 1, (
        f"{filename}:{funcname} calls the spend gate {len(gate_lines)} times "
        f"(lines {gate_lines}). One spend must charge the ledger once: authorize() records "
        "against the 24h window at approval time, so a second call double-charges it and "
        "locks the agent out early having delivered one message."
    )

    if sign_lines:
        assert min(gate_lines) < min(sign_lines), (
            f"{filename}:{funcname} signs at line {min(sign_lines)} before gating at "
            f"line {min(gate_lines)} — the gate must run first"
        )


def test_the_gated_paths_really_call_the_gate_before_they_sign():
    for filename, funcname in GATED_DIRECTLY:
        tree = ast.parse((SRC / "xete_mcp" / filename).read_text(encoding="utf-8"))
        _assert_gate_discipline(tree, filename, funcname)


# The naive union merge of hunk 3, reduced to its shape: the early gate that the integrator
# dropped is reinstated alongside the one that was kept. Both of the tripwire's original
# assertions hold on this — a gate exists, and the first gate precedes the first signature.
_DOUBLE_GATED_SOURCE = '''
def deposit(rpc_url, depositor, recipient, amount_lamports, on_ticket=None):
    from .spendguard import authorize

    authorize(int(amount_lamports), "xete_settle_create", detail="")
    client = Client(rpc_url)
    authorize(int(amount_lamports), "xete_settle_create", detail="")
    return client.send_transaction(tx)
'''


# The cheapest way past a rule that counts source lines: charge N times from one line. Raised by
# the fresh-context reviewer of the G22 fix.
_LOOP_GATED_SOURCE = '''
def deposit(rpc_url, depositor, recipients, amount_lamports, on_ticket=None):
    from .spendguard import authorize

    client = Client(rpc_url)
    for recipient in recipients:
        authorize(int(amount_lamports), "xete_settle_create", detail="")
        client.send_transaction(tx)
'''

# The over-refusal guard for the loop rule: a gate outside a loop, in a function that HAS loops
# (which every confirmation poll in this package does), must still pass.
_LOOP_ELSEWHERE_SOURCE = '''
def deposit(rpc_url, depositor, recipient, amount_lamports, on_ticket=None):
    from .spendguard import authorize

    authorize(int(amount_lamports), "xete_settle_create", detail="")
    client = Client(rpc_url)
    sig = client.send_transaction(tx)
    for _ in range(30):
        if client.get_signature_statuses([sig]):
            break
    return sig
'''


def test_the_tripwire_itself_catches_a_path_that_gates_twice():
    """Finding [G22]: proves the single-call rule bites, rather than being a line of source
    that happens to be true today. Without the `len(gate_lines) == 1` assertion this passes
    the tripwire silently, which is how the double-charge would have shipped."""
    tree = ast.parse(_DOUBLE_GATED_SOURCE)

    # Both properties the tripwire checked BEFORE this finding hold on the double-gated source.
    gate_lines, sign_lines, _looped = _gate_and_sign_lines(tree, "deposit")
    assert gate_lines and sign_lines
    assert min(gate_lines) < min(sign_lines)

    # And the tripwire as a whole must still refuse it.
    with pytest.raises(AssertionError, match="calls the spend gate 2 times"):
        _assert_gate_discipline(tree, "settlement.py", "deposit")


def test_the_tripwire_catches_one_gate_that_charges_many_times():
    """A single authorize() in a loop body is ONE line and N ledger entries, so a rule that
    counts source lines waves it through. Counting lines was the fix for [G22]; this is the
    hole in that fix, found by the fresh-context pass on it."""
    tree = ast.parse(_LOOP_GATED_SOURCE)

    # The line count says one gate, which is exactly why the count alone is not enough.
    gate_lines, _sign, looped = _gate_and_sign_lines(tree, "deposit")
    assert len(gate_lines) == 1
    assert looped == gate_lines

    with pytest.raises(AssertionError, match="inside a loop"):
        _assert_gate_discipline(tree, "settlement.py", "deposit")


def test_the_loop_rule_does_not_refuse_a_confirmation_poll():
    """Over-refusal guard. Every submitting function in this package polls for confirmation in a
    `for` loop AFTER gating once — `settlement.deposit` and `payment.pay_herd` both do. A rule
    that flagged "this function contains a loop" instead of "this gate runs inside one" would
    have gone red on the real code, and the honest response to that is to weaken the rule."""
    tree = ast.parse(_LOOP_ELSEWHERE_SOURCE)

    gate_lines, _sign, looped = _gate_and_sign_lines(tree, "deposit")
    assert gate_lines and not looped

    _assert_gate_discipline(tree, "settlement.py", "deposit")     # must not raise


# ── the gate is really wired, not merely present in the source ───────────────────────

@pytest.fixture()
def no_network():
    class Bomb:
        def __init__(self, *_a, **_k):
            raise AssertionError("execution reached the RPC client — the gate did not stop it")
    return Bomb


def test_pay_herd_refuses_before_touching_the_network(ledger, monkeypatch, no_network):
    from xete_mcp import payment

    monkeypatch.setattr(payment, "Client", no_network)
    monkeypatch.setenv(spendguard.ENV_MAX, "1000000")
    with pytest.raises(spendguard.SpendRefused):
        payment.pay_herd("http://127.0.0.1:1", object(), "nonce-1", 50)


def test_pay_herd_uses_the_derived_cost_when_the_server_understates_the_quote(
        ledger, monkeypatch, no_network):
    """A server that quotes 1 lamport for 50 blobs must not shrink what the gate checks."""
    from xete_mcp import payment

    monkeypatch.setattr(payment, "Client", no_network)
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    with pytest.raises(spendguard.SpendRefused) as ex:
        payment.pay_herd("http://127.0.0.1:1", object(), "n", 50, declared_lamports=1)
    assert "50000000" in str(ex.value)      # 50 blobs derived on this side, not the quoted 1


def test_settlement_deposit_refuses_before_touching_the_network(ledger, monkeypatch, no_network):
    from xete_mcp import settlement

    monkeypatch.setattr(settlement, "Client", no_network)
    monkeypatch.setenv(spendguard.ENV_MAX, "1000000")
    with pytest.raises(spendguard.SpendRefused):
        settlement.deposit("http://127.0.0.1:1", object(), object(), 2_000_000)


def test_an_allowed_spend_passes_the_gate_and_is_recorded(ledger, monkeypatch):
    """The other direction: within limits, execution continues and the ledger records it.

    The figure moved from 1_000_000 to 2_000_000 and NOTHING else about this test changed —
    same three assertions, same strength. 1_000_000 lamports is below the escrow account's
    rent-exempt minimum (1_454_640), so since finding [G12] it is a deposit that can never
    execute and `settlement.deposit` refuses it before the gate. It used to reach `Client`
    only because the mock raised before `deposit_ix` would have; the fixture was choosing an
    impossible amount to prove a possible spend is recorded. 2_000_000 is a deposit that could
    really happen, which is what this test is about.
    """
    from xete_mcp import settlement

    reached = []

    class Marker:
        def __init__(self, *_a, **_k):
            reached.append(True)
            raise RuntimeError("stop here — no network wanted in a unit test")

    monkeypatch.setattr(settlement, "Client", Marker)
    monkeypatch.setenv(spendguard.ENV_MAX, "10000000")
    with pytest.raises(RuntimeError, match="stop here"):
        settlement.deposit("http://127.0.0.1:1", object(), object(), 2_000_000)

    assert reached, "the gate refused a spend that was within limits"

    # THE ASSERTION BELOW WAS INVERTED, DELIBERATELY, AND HERE IS WHY.
    #
    # It used to read `_entries(ledger)[0]["lamports"] == 2_000_000` -- i.e. the charge
    # SURVIVES a failure at Client() construction. That was true, and it was the defect: a
    # failure here is strictly pre-submission (Client() opens no socket; the first network
    # call is get_latest_blockhash, inside _send, before Transaction() signs), so nothing
    # was signed, nothing was submitted, and no lamport can have moved. Charging it meant
    # five unreachable-RPC attempts at the stock cap exhausted the 24h window and locked
    # the agent out of settlement having spent zero.
    #
    # The test's REAL point -- that the gate runs BEFORE any network work -- is unchanged
    # and still asserted by `reached`. Only the claim about what happens to the entry
    # afterwards has moved, because the behaviour it described is the one being fixed.
    #
    # The opposite direction is covered separately and must stay covered: a deposit that
    # reaches the send call keeps its charge (test_a_deposit_that_reached_the_send_call_is
    # _still_charged). Without that pair, "release on failure" could silently become
    # "release always" and this file would not notice.
    assert _entries(ledger) == [], (
        "a deposit that failed before anything was signed kept its ledger entry; the "
        f"window is being drained for a transaction that never existed: {_entries(ledger)}")


def test_there_is_no_way_to_switch_the_gate_off():
    """No env var, argument or constant may mean 'unlimited'."""
    source = (SRC / "xete_mcp" / "spendguard.py").read_text(encoding="utf-8")
    for forbidden in ("XETE_SPEND_DISABLE", "XETE_SPEND_ENABLED", "XETE_NO_SPEND_LIMIT",
                      "float('inf')", 'float("inf")', "math.inf", "sys.maxsize"):
        assert forbidden not in source, f"spendguard.py contains an escape hatch: {forbidden}"


# ═════════════════════════════════════════════════════════════════════════════════════
# FINDING [F1] — eight guards that were STATED and not held in place
#
# Each of the eight was deleted, one at a time, in a scratch copy of the source and the
# whole 677-test suite stayed green. A guard nothing asserts is a comment. Everything
# below drives the published `xete_alias_claim` tool end to end against a hostile permit
# server, so what is asserted is what the TOOL does — refuses, signs nothing, submits
# nothing — not that a particular line still exists.
#
# The last of the eight is the worst: replacing
#     from .spendguard import authorize as _authorize_spend
# on the claim path with a no-op left 677 tests passing, because every signing test in the
# repo RAISES XETE_SPEND_MAX_LAMPORTS out of the way (test_signing_regression._accepting
# sets it to 100,000,000) so that the transaction guards can be exercised. Nothing ever
# lowered it and watched the tool refuse. `test_the_claim_tool_refuses_when_the_spend_cap_binds`
# is that missing test.
# ═════════════════════════════════════════════════════════════════════════════════════

_CLAIM_SEED = bytes([23] * 32)
_CLAIM_AGENT_ID = "agent-1"
_CLAIM_NAME = "mcptestname"
_ALIAS_PROGRAM = "AXTREGuYbpgcWFbZy124jcWDN2nd7mtmrCDsUojktZrd"
_SYSTEM_PROGRAM = "11111111111111111111111111111111"
_COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111"
# config.names_wallet as the live registry carries it. Pinned here through the documented
# XETE_ALIAS_TREASURY override so these tests need no network.
_CLAIM_TREASURY = "9zHPVcHhBeZBCLcw8NMWvAQqLWmMNBrcuiYVwyUcwFds"
# What an HONEST claim costs beyond its price: alias PDA rent + a two-signature fee.
_RENT_AND_FEE = 1_628_640 + 10_000


class _PermitResponse:
    """Enough of a requests.Response for safehttp's streaming reader."""

    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200
        self.text = json.dumps(payload)
        self.headers = {}
        self.reason = "OK"

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size=1):
        yield self.text.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def close(self):
        pass


def _solders():
    from solders.hash import Hash
    from solders.instruction import AccountMeta, CompiledInstruction, Instruction
    from solders.keypair import Keypair
    from solders.message import Message
    from solders.pubkey import Pubkey
    from solders.signature import Signature
    from solders.transaction import Transaction
    return (Hash, AccountMeta, CompiledInstruction, Instruction, Keypair, Message,
            Pubkey, Signature, Transaction)


def _claim_data(name=_CLAIM_NAME, price=0, trailing=0) -> bytes:
    """02 | u8 name_len | name | 32-byte record key | u64 price — the mainnet layout."""
    raw = name.encode()
    record = hashlib.sha256(_CLAIM_AGENT_ID.encode()).digest()
    return bytes([2, len(raw)]) + raw + record + struct.pack("<Q", price) + b"\x00" * trailing


def _claim_message(pubkey, *, price=0, system=None, data=None, extra_ixs=()):
    """The message the permit server serves today, with one knob per guard under test."""
    Hash, AccountMeta, _, Instruction, _, Message, Pubkey, _, _ = _solders()
    program = Pubkey.from_string(_ALIAS_PROGRAM)
    me = Pubkey.from_string(pubkey)
    accounts = [
        AccountMeta(me, True, True),                                    # payer
        AccountMeta(me, True, True),                                    # claim authority
        AccountMeta(Pubkey.find_program_address(
            [b"alias", _CLAIM_NAME.encode()], program)[0], False, True),
        AccountMeta(Pubkey.find_program_address([b"config"], program)[0], False, False),
        AccountMeta(Pubkey.from_string(_CLAIM_TREASURY), False, True),
        AccountMeta(Pubkey.from_string(system or _SYSTEM_PROGRAM), False, False),
    ]
    claim = Instruction(program_id=program,
                        data=_claim_data(price=price) if data is None else data,
                        accounts=accounts)
    return Message.new_with_blockhash([claim, *extra_ixs], me, Hash.default())


def _b64(tx) -> str:
    return base64.b64encode(bytes(tx)).decode()


def _honest_claim(pubkey, **kw) -> str:
    _, _, _, _, _, _, _, _, Transaction = _solders()
    return _b64(Transaction.new_unsigned(_claim_message(pubkey, **kw)))


def _with_extra_keys(message, extras):
    """The same message with `extras` appended to the account list, unreferenced.

    `num_readonly_unsigned_accounts` grows by the same amount, so the WRITABILITY of every
    account the claim instruction names is byte-for-byte what it was. Without that the
    added keys would silently flip the System-program slot writable and the test would be
    passing for a reason that has nothing to do with the account-count bound.
    """
    Hash, _, _, _, _, Message, _, _, _ = _solders()
    header = message.header
    return Message.new_with_compiled_instructions(
        header.num_required_signatures,
        header.num_readonly_signed_accounts,
        header.num_readonly_unsigned_accounts + len(extras),
        list(message.account_keys) + list(extras),
        Hash.default(),
        list(message.instructions),
    )


class _ClaimHarness:
    """Drives `xete_alias_claim` against a permit server that serves whatever we hand it.

    Records what was SIGNED and what was SUBMITTED separately, because "the tool returned
    an error" and "the tool refused before using the key" are different claims and only
    the second one is a security property.
    """

    def __init__(self, server, pubkey, signed, submitted, ledger):
        self.server = server
        self.pubkey = pubkey
        self.signed = signed
        self.submitted = submitted
        self.ledger = ledger
        self.sim_debit = _RENT_AND_FEE

    # max_price defaults to None -- "no opinion" -- NOT 0. Since 3a9177c those are
    # different: 0 means "this claim MUST BE FREE" and is a real ceiling, which would
    # refuse every priced claim in this file. This harness predates that fix.
    def run(self, tx_b64, *, price=0, name=_CLAIM_NAME, max_price=None) -> dict:
        self.serve(tx_b64, price=price)
        return json.loads(self.server.xete_alias_claim(name, max_price_lamports=max_price))

    def serve(self, tx_b64, *, price=0):
        self._tx_b64, self._price = tx_b64, price

    def _post(self, url, json=None, timeout=None, **_kw):
        if url.endswith("/alias/claim/challenge"):
            nonce = "48aSgGfAhcHvDJwwFNG3jh"
            return _PermitResponse({
                "nonce": nonce, "expires_in": 300,
                "message": (f"xete alias claim\npubkey:{self.pubkey}\nnonce:{nonce}"
                            f"\nts:{int(time.time())}"),
            })
        if url.endswith("/alias/claim"):
            return _PermitResponse({"status": "approved", "price_lamports": self._price,
                                    "free_grace": True, "transaction": self._tx_b64})
        if url.endswith("/alias/claim/confirm"):
            return _PermitResponse({"status": "confirmed"})
        raise AssertionError(f"unexpected permit call {url}")


@pytest.fixture()
def claim(tmp_path, monkeypatch):
    """An isolated identity, ledger and permit server, with the RPC faked into agreeing.

    Deliberately permissive by default: the spend cap is set high and simulation is made
    to answer, so that a transaction reaching this fixture is refused ONLY by the guard
    the test is about. When a test wants the cap to bind it lowers it itself.
    """
    for name in SPEND_ENV:
        monkeypatch.delenv(name, raising=False)
    ledger_path = tmp_path / "ledger.json"
    monkeypatch.setenv("XETE_IDENTITY", str(tmp_path / "identity.json"))
    monkeypatch.setenv(spendguard.ENV_LEDGER, str(ledger_path))
    monkeypatch.setenv(spendguard.ENV_MAX, "100000000")
    monkeypatch.setenv(spendguard.ENV_WINDOW, "100000000")
    monkeypatch.setenv("XETE_PERMIT_URL", "https://permit.invalid")
    monkeypatch.setenv("XETE_SERVER_URL", "https://relay.invalid")
    monkeypatch.setenv("XETE_RPC_URL", "https://rpc.invalid")
    monkeypatch.setenv("XETE_ALIAS_TREASURY", _CLAIM_TREASURY)
    (tmp_path / "identity.json").write_text(json.dumps({
        "ed_seed": base64.b64encode(_CLAIM_SEED).decode(), "agent_id": _CLAIM_AGENT_ID}))

    import xete_mcp.server as server
    server = importlib.reload(server)
    from xete_mcp.client import load_or_create_identity

    pubkey = load_or_create_identity(server.IDENTITY_PATH).pubkey_b58
    signed, submitted = [], []

    class _Rpc:
        """Accepts and confirms. A refusing mock cannot tell 'the guard stopped it' from
        'the fake RPC stopped it', and every guard here is supposed to fire first."""

        def __init__(self, *_a, **_k):
            pass

        def send_raw_transaction(self, raw, *_a, **_kw):
            submitted.append(bytes(raw))

            class _R:
                value = "5ig"
            return _R()

        def get_signature_statuses(self, *_a, **_kw):
            class _S:
                confirmation_status = _TCS.Confirmed
                err = None

            class _R:
                value = [_S()]
            return _R()

    import solana.rpc.api

    monkeypatch.setattr(solana.rpc.api, "Client", _Rpc)

    harness = _ClaimHarness(server, pubkey, signed, submitted, ledger_path)

    real_sign = server.txguard_mod.approve_and_sign

    def _spy_sign(tx, inspection, keypair):
        signed.append(inspection.message_sha256)
        return real_sign(tx, inspection, keypair)

    monkeypatch.setattr(server.txguard_mod, "approve_and_sign", _spy_sign)
    monkeypatch.setattr(server.txguard_mod, "simulated_debit",
                        lambda *_a, **_k: harness.sim_debit)
    monkeypatch.setattr(server.requests, "post", harness._post)
    # safehttp dispatches through requests.request, not requests.post.
    monkeypatch.setattr(server.requests, "request",
                        lambda method, url, **kw: harness._post(url, **kw))
    return harness


def _refused(harness, result):
    """Assert the tool refused AND that no key was used and nothing left the machine."""
    assert result.get("status") == "refused", result
    assert result.get("signed") is False and result.get("submitted") is False, result
    assert not harness.signed, "the transaction was SIGNED before it was refused"
    assert not harness.submitted, "the transaction was SUBMITTED on-chain"
    return result["reason"]


def test_the_harness_lets_an_honest_claim_through(claim):
    """The over-refusal guard for everything below. If this fixture refused every claim,
    the eight tests that follow would pass while asserting nothing at all — which is the
    exact failure mode that let the eight guards rot in the first place."""
    result = claim.run(_honest_claim(claim.pubkey))

    assert result["status"] == "claimed", result
    assert claim.signed and claim.submitted, result
    assert result["verified_before_signing"]["claim_name"] == _CLAIM_NAME


def test_the_transaction_shape_bounds_are_pinned_to_what_a_claim_needs():
    """Finding [F1]: MAX_INSTRUCTIONS 8 -> 64 and MAX_ACCOUNT_KEYS 32 -> 256 both left the
    whole suite green, because nothing anywhere asserted the numbers.

    The numbers are not arbitrary and are not a matter of taste, which is why they can be
    pinned rather than merely bounded. A claim the registry accepts is ONE registry
    instruction plus at most the four distinct compute-budget operations that exist
    (SetComputeUnitLimit, SetComputeUnitPrice, RequestHeapFrame,
    SetLoadedAccountsDataSizeLimit) — txguard refuses a repeated one — so five
    instructions is the true ceiling and 8 is already slack. It names seven accounts. Its
    instruction data is `02 | name_len | name | 32-byte key | u64 price`, at most 74 bytes
    for the longest name the registry can hold.

    Raising any of these buys no compatibility and widens what a hostile permit server can
    hide in a transaction we sign, so a change here should have to argue for itself.
    """
    from xete_mcp import txguard

    assert txguard.MAX_INSTRUCTIONS == 8
    assert txguard.MAX_ACCOUNT_KEYS == 32
    assert txguard.MAX_IX_DATA_BYTES == 512
    # And the bounds stay above what a real claim needs, or the guard becomes an outage.
    assert txguard.MAX_IX_DATA_BYTES > txguard._CLAIM_FIXED_BYTES + txguard.MAX_ALIAS_NAME_BYTES
    assert txguard.MAX_ACCOUNT_KEYS > txguard.CLAIM_ACCOUNT_COUNT


def test_a_claim_carrying_more_instructions_than_a_claim_needs_is_refused(claim):
    """Guard 1 of 8: MAX_INSTRUCTIONS.

    Nine instructions, refused on the count alone — before a single one of them is
    decoded, which is the point of a bound. With the cap raised to 64 this same
    transaction is refused for an unrelated reason (a repeated compute-budget operation),
    so the assertion is on the refusal the COUNT produces, not merely on being refused.
    """
    _, _, _, Instruction, _, _, Pubkey, _, _ = _solders()
    filler = [Instruction(program_id=Pubkey.from_string(_COMPUTE_BUDGET),
                          data=bytes([2]) + struct.pack("<I", 200_000), accounts=[])
              for _ in range(8)]

    result = claim.run(_honest_claim(claim.pubkey, extra_ixs=filler))

    assert "9 instructions, over the 8 an alias claim can need" in _refused(claim, result)


def test_a_claim_naming_more_accounts_than_a_claim_needs_is_refused(claim):
    """Guard 2 of 8: MAX_ACCOUNT_KEYS.

    Thirty-four spare account keys, referenced by nothing. With the cap raised to 256 this
    transaction is ACCEPTED, signed and submitted — every other check passes, because
    every other check looks at the accounts the claim instruction NAMES and this attack
    does not touch those. An unbounded account list is how a transaction is padded until
    the thing a human or an agent is asked to look at no longer fits on a screen.
    """
    _, _, _, _, Keypair, _, _, _, Transaction = _solders()
    message = _claim_message(claim.pubkey)
    padded = _with_extra_keys(message, [Keypair().pubkey() for _ in range(34)])

    result = claim.run(_b64(Transaction.new_unsigned(padded)))

    assert "40 accounts, over the 32 an alias claim can need" in _refused(claim, result)


def test_this_agents_wallet_may_appear_only_once_in_the_account_list(claim):
    """Guard 3 of 8: `keys.count(expect_fee_payer) != 1`.

    Delete it and this transaction is accepted, signed and submitted. Every positional
    check in `_check_claim_accounts` compares a slot against a PUBKEY, so a second copy of
    our wallet sitting at another index is a second handle on the same signature: the
    fee-payer identity the guard establishes at index 0 stops being the only place we
    appear, and any later instruction added to the transaction can name the copy while the
    checks keep agreeing with themselves about index 0.
    """
    _, _, _, _, _, _, Pubkey, _, Transaction = _solders()
    message = _claim_message(claim.pubkey)
    duplicated = _with_extra_keys(message, [Pubkey.from_string(claim.pubkey)])

    result = claim.run(_b64(Transaction.new_unsigned(duplicated)))

    assert "appears 2 times in the account list" in _refused(claim, result)


def test_a_transaction_needing_a_third_signature_is_refused(claim):
    """Guard 4 of 8: `not 1 <= nsig <= 2`.

    A claim needs this agent, or this agent plus the permit co-signer. This fixture
    requires THREE signatures and arrives with the other two already filled, so with the
    bound deleted every remaining check passes and the tool signs and submits.

    A third required signer is a third party whose transaction we are completing. Our
    signature over a message we did not choose the rest of is the whole reason this module
    exists.
    """
    Hash, _, CompiledInstruction, _, Keypair, Message, Pubkey, Signature, Transaction = _solders()
    program = Pubkey.from_string(_ALIAS_PROGRAM)
    me = Pubkey.from_string(claim.pubkey)
    authority, stranger = Keypair().pubkey(), Keypair().pubkey()
    pda = Pubkey.find_program_address([b"alias", _CLAIM_NAME.encode()], program)[0]
    config = Pubkey.find_program_address([b"config"], program)[0]
    # 3 signers (the last read-only), then the writable unsigned accounts, then the
    # read-only ones — the layout a Solana message header describes.
    keys = [me, authority, stranger,
            Pubkey.from_string(_CLAIM_TREASURY), pda,
            Pubkey.from_string(_SYSTEM_PROGRAM), config, program]
    compiled = CompiledInstruction(program_id_index=7, data=_claim_data(),
                                   accounts=bytes([0, 1, 4, 6, 3, 5]))
    message = Message.new_with_compiled_instructions(3, 1, 3, keys, Hash.default(), [compiled])
    cosigned = Signature.from_bytes(bytes([7] * 64))
    tx = Transaction.populate(message, [Signature.default(), cosigned, cosigned])

    result = claim.run(_b64(tx))

    assert "requires 3 signatures" in _refused(claim, result)


def test_a_transaction_whose_signature_slot_is_already_filled_is_refused(claim):
    """Guard 5 of 8: `tx.signatures[0] != empty`.

    Delete it and this is accepted: `partial_sign` simply overwrites the slot, so nothing
    downstream notices. But a permit server that hands back a transaction already carrying
    a signature in OUR slot is telling us something is wrong — either it holds a signature
    of ours over these bytes, or the bytes are not what it says they are. Refusing is the
    only answer that does not depend on guessing which.
    """
    _, _, _, _, _, _, _, Signature, Transaction = _solders()
    tx = Transaction.populate(_claim_message(claim.pubkey),
                              [Signature.from_bytes(bytes([7] * 64))])

    result = claim.run(_b64(tx))

    assert "signature slot already carries a signature we did not make" in _refused(claim, result)


def test_the_system_program_slot_of_a_claim_is_pinned(claim):
    """Guard 6 of 8: `accounts[IX_SYSTEM] != SYSTEM_PROGRAM`.

    Delete it and a claim whose sixth account is an address of the server's choosing is
    accepted, signed and submitted. That slot is what the registry does its inner
    CreateAccount and its inner transfer through; every other slot in the instruction is
    checked by position and this one was the hole in the row.
    """
    _, _, _, _, Keypair, _, _, _, _ = _solders()

    result = claim.run(_honest_claim(claim.pubkey, system=str(Keypair().pubkey())))

    assert "System-program slot holds" in _refused(claim, result)


def test_an_oversized_instruction_data_field_is_refused(claim):
    """Guard 7 of 8: MAX_IX_DATA_BYTES.

    573 bytes on the registry instruction. Removing the bound does not make this one
    ACCEPTED — the claim decoder rejects it a few lines later for the wrong length — so
    the assertion is on the refusal the SIZE bound produces. The bound is what stops
    unbounded attacker-chosen bytes reaching a decoder at all, and it is the only check
    here that applies to instructions this client does not otherwise decode.
    """
    result = claim.run(_honest_claim(claim.pubkey, data=_claim_data(trailing=520)))

    assert "over the 512-byte limit" in _refused(claim, result)


def test_the_claim_tool_refuses_when_the_spend_cap_binds(claim, monkeypatch):
    """Guard 8 of 8, and the worst one: THE SPEND GATE ITSELF.

    Replacing `from .spendguard import authorize as _authorize_spend` on the claim path
    with a no-op lambda left all 677 tests passing. There was no behavioural test that
    `xete_alias_claim` refuses when the cap binds, because every signing test RAISES
    XETE_SPEND_MAX_LAMPORTS out of its own way in order to exercise txguard — so the one
    direction the cap exists for was never driven.

    Here the permit server quotes 50,000,000 lamports against a 40,000,000 cap. The
    transaction is otherwise perfect: it passes every txguard check, simulation agrees
    with it, and the fixture's RPC would accept it. The gate is the only thing left.
    """
    claim.sim_debit = 50_000_000 + _RENT_AND_FEE
    monkeypatch.setenv(spendguard.ENV_MAX, "40000000")
    tx_b64 = _honest_claim(claim.pubkey, price=50_000_000)

    result = claim.run(tx_b64, price=50_000_000)

    assert result["status"] == "failed", result
    assert "SPEND REFUSED (per-transaction cap)" in result["error"], result
    assert not claim.signed, "the spend gate did not stop the signature"
    assert not claim.submitted, "a transaction over the spend cap was submitted on-chain"
    # A refusal records nothing, so the window is not burned by a spend that never happened.
    assert not claim.ledger.exists() or _entries(claim.ledger) == []


def test_the_same_claim_goes_through_once_the_cap_allows_it(claim, monkeypatch):
    """The other half of guard 8: the cap is a cap, not a brick. Byte-for-byte the same
    transaction as the test above, with the cap set above the price, completes.

    Without this, `test_the_claim_tool_refuses_when_the_spend_cap_binds` would still pass
    if the tool had simply stopped working, which is how a "the guard fires" test quietly
    becomes a test of nothing.
    """
    claim.sim_debit = 50_000_000 + _RENT_AND_FEE
    monkeypatch.setenv(spendguard.ENV_MAX, "60000000")
    tx_b64 = _honest_claim(claim.pubkey, price=50_000_000)

    result = claim.run(tx_b64, price=50_000_000)

    assert result["status"] == "claimed", result
    assert claim.signed and claim.submitted, result
    # The gate charged the largest figure anyone can justify — what simulation measured.
    assert _entries(claim.ledger)[0]["lamports"] == 50_000_000 + _RENT_AND_FEE
    assert _entries(claim.ledger)[0]["path"] == "xete_alias_claim"
