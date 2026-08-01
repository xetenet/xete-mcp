"""Tests for the client-side spend limits (src/xete_mcp/spendguard.py).

Runs offline: nothing here touches the network, a real wallet, or the real ~/.xete/.
Every test points XETE_SPEND_LEDGER at a temporary directory.

Run with:  python -m pytest test_spendguard.py -v
"""
from __future__ import annotations

import ast
import json
import os
import stat
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
# src/xete_mcp and finds every function that submits a transaction, adds a signature, or
# loads a signing key. The result must match the table below EXACTLY: a new spending path
# fails this test until somebody either gates it or writes down why it needs no gate.

SUBMIT_OR_SIGN = {"send_transaction", "send_raw_transaction", "partial_sign"}
KEY_LOADERS = {("Keypair", "from_seed"), ("Keypair", "from_bytes")}

EXPECTED_TOUCHPOINTS = {
    ("payment.py", "pay_herd"):
        "GATED — calls spendguard.authorize before building or signing anything",
    ("settlement.py", "_send"):
        "EXEMPT — shared submitter. Its only spending caller, deposit(), gates before "
        "calling it; claim() and reclaim() are income, see below",
    ("server.py", "_load_payer"):
        "EXEMPT — reads the payer keypair but spends nothing itself; every consumer is gated",
    ("server.py", "xete_alias_claim"):
        "GATED — calls spendguard.authorize before txguard.approve_and_sign",
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
}

GATED_DIRECTLY = [
    ("payment.py", "pay_herd"),
    ("settlement.py", "deposit"),
    ("server.py", "xete_alias_claim"),
]


def _direct_hit(node) -> str | None:
    """The submit/sign/key-load call name, if this node is one. Attribute calls only."""
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return None
    attr = node.func.attr
    if attr in SUBMIT_OR_SIGN:
        return attr
    if isinstance(node.func.value, ast.Name) and (node.func.value.id, attr) in KEY_LOADERS:
        return attr
    return None


def _touchpoints():
    """Every function that submits or signs -- DIRECTLY, or through a module-local helper.

    THE HOLE THIS CLOSES: the scan used to `continue` on anything that was not an
    ast.Attribute call, and every money function in settlement.py submits through the
    module-local helper `_send(...)`, which is an ast.NAME call. So the control that exists
    to catch an ungated spending path could not see the idiom this codebase actually uses.
    Reproduced by an outside reviewer: appending a plausible `sweep_everything()` calling
    `_send(...)` to a copy of settlement.py left every meta-test GREEN, while the same
    function calling `client.send_transaction` directly went RED.

    A name-based scan that misses the local convention is worse than no scan, because it
    reports success. So: find helpers that themselves submit, then treat a call to one of
    them as a submission too, to a FIXED POINT -- a helper calling a helper calling a
    submitter is still a spending path.
    """
    parsed = {}
    for pyfile in sorted((SRC / "xete_mcp").rglob("*.py")):   # rglob: a subpackage was invisible
        parsed[pyfile.name] = ast.parse(pyfile.read_text(encoding="utf-8"), filename=str(pyfile))

    # Pass 1 -- direct submitters, per file.
    direct = {}
    for name, tree in parsed.items():
        for func in [n for n in ast.walk(tree)
                     if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            for node in ast.walk(func):
                hit = _direct_hit(node)
                if hit:
                    direct.setdefault((name, func.name), []).append((hit, node.lineno))

    # Pass 2 -- transitive closure over module-local Name calls, within each file.
    found = dict(direct)
    changed = True
    while changed:
        changed = False
        for name, tree in parsed.items():
            submitters = {fn for (f, fn) in found if f == name}
            for func in [n for n in ast.walk(tree)
                         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
                if (name, func.name) in found:
                    continue
                for node in ast.walk(func):
                    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                            and node.func.id in submitters):
                        found[(name, func.name)] = [(f"-> {node.func.id}()", node.lineno)]
                        changed = True
                        break
    return found


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
    assert _entries(ledger)[0]["lamports"] == 2_000_000
    assert _entries(ledger)[0]["path"] == "xete_settle_create"


def test_there_is_no_way_to_switch_the_gate_off():
    """No env var, argument or constant may mean 'unlimited'."""
    source = (SRC / "xete_mcp" / "spendguard.py").read_text(encoding="utf-8")
    for forbidden in ("XETE_SPEND_DISABLE", "XETE_SPEND_ENABLED", "XETE_NO_SPEND_LIMIT",
                      "float('inf')", 'float("inf")', "math.inf", "sys.maxsize"):
        assert forbidden not in source, f"spendguard.py contains an escape hatch: {forbidden}"
