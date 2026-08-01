"""Client-side SPEND LIMITS — the gate that runs before anything is signed.

Every path in this package that autonomously signs and submits a transaction costing
SOL calls `authorize()` FIRST. If `authorize()` raises, no key has been used and
nothing has reached the network.

WHY THIS EXISTS
---------------
The amount charged for a message is quoted by the server being paid, and the %alias
claim transaction is BUILT by the permit server. Without a ceiling on this side the
trust assumption is inverted: the party receiving the money decides how much it
receives. These limits are the user's ceiling, enforced on the user's machine, before
any signature exists.

CONFIGURATION (environment)
---------------------------
  XETE_SPEND_MAX_LAMPORTS     Most a SINGLE spend may cost.
                              default 10000000 (0.01 SOL)
  XETE_SPEND_WINDOW_LAMPORTS  Most that may be spent inside the rolling window.
                              default 50000000 (0.05 SOL)
  XETE_SPEND_WINDOW_SECONDS   Length of the rolling window.
                              default 86400 (24 hours)
  XETE_SPEND_FLOOR_LAMPORTS   Minimum charged against the budget for ANY on-chain
                              action, covering the account rent and network fees that
                              a quoted price excludes. Without it, a path that quotes
                              zero (a free 6+ letter %name) could be repeated forever
                              while still draining the wallet.
                              default 2000000 (0.002 SOL)
  XETE_SPEND_LEDGER           Ledger location.
                              default ~/.xete/spend-ledger.json

FAIL CLOSED. There is deliberately NO "unlimited" value and no off switch:

  * an unset limit gets the conservative default above, never "no limit";
  * a malformed limit refuses every spend until it is corrected;
  * an unreadable or corrupt ledger refuses every spend rather than silently
    starting the budget over;
  * a ledger that cannot be written refuses the spend, because a spend that cannot
    be recorded cannot be limited.

To permit a large spend you must set a large number. That is an explicit, auditable
act, which is the point.

THE LEDGER
----------
`~/.xete/spend-ledger.json`, replaced atomically while an exclusive lock is held on a
SEPARATE `.lock` file, so two concurrent sends cannot both pass a check that only one
should pass. The spend is recorded BEFORE it is attempted: an attempt that is approved
and then fails still counts, because a transaction that never left is indistinguishable
from one that landed and lost its receipt, and over-counting is the safe direction for
a ceiling.

This module touches nothing else under ~/.xete/. It never reads, writes, moves or
re-permissions identity.json, and it never changes the permissions of a ~/.xete/ that
it did not create.

WHAT THIS DOES NOT PROTECT AGAINST — read before trusting it.
The gate binds this server's own spending paths against a runaway or prompt-injected
agent, and against a server quoting a price above what the user will tolerate. It
cannot bind an actor able to write to the ledger or move the system clock forward,
because that actor can equally read the signing key and transact without this server
at all. See reviews/DDR-spend-caps-20260731.md.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

LAMPORTS_PER_SOL = 1_000_000_000

ENV_MAX = "XETE_SPEND_MAX_LAMPORTS"
ENV_WINDOW = "XETE_SPEND_WINDOW_LAMPORTS"
ENV_WINDOW_SECONDS = "XETE_SPEND_WINDOW_SECONDS"
ENV_FLOOR = "XETE_SPEND_FLOOR_LAMPORTS"
ENV_LEDGER = "XETE_SPEND_LEDGER"

DEFAULT_MAX_LAMPORTS = 10_000_000       # 0.01 SOL
DEFAULT_WINDOW_LAMPORTS = 50_000_000    # 0.05 SOL
DEFAULT_WINDOW_SECONDS = 86_400         # 24 hours
DEFAULT_FLOOR_LAMPORTS = 2_000_000      # 0.002 SOL — covers typical account rent + fee

LEDGER_VERSION = 1
MAX_ENTRIES = 2_000
_CLOCK_SLACK_SECONDS = 2.0
_LOCK_TIMEOUT_SECONDS = 30.0


class SpendRefused(RuntimeError):
    """A spend was refused by the client-side limits. NOTHING was signed or sent."""


class SpendGuardUnavailable(SpendRefused):
    """The limits could not be enforced, so the spend was refused rather than allowed.

    A subclass of SpendRefused on purpose: every caller that handles "refused" already
    handles "could not tell", and both mean the same thing — no key was used.
    """


# ── formatting helpers ───────────────────────────────────────────────────────────────

def _fmt(lamports: int) -> str:
    whole = f"{lamports / LAMPORTS_PER_SOL:.9f}".rstrip("0").rstrip(".") or "0"
    return f"{whole} SOL ({lamports} lamports)"


def _dur(seconds: float) -> str:
    s = int(max(0, round(seconds)))
    hours, rem = divmod(s, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _utc(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


# ── configuration ────────────────────────────────────────────────────────────────────

def _int_env(name: str, default: int, *, minimum: int = 0) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        raise SpendGuardUnavailable(
            f"SPEND REFUSED (bad configuration): {name} is set to {raw!r}, which is not a whole "
            f"number of lamports. Every spend is refused until it is corrected, or unset to fall "
            f"back to the default of {default}. Nothing was signed."
        ) from None
    if value < minimum:
        raise SpendGuardUnavailable(
            f"SPEND REFUSED (bad configuration): {name} is set to {value}, below its minimum of "
            f"{minimum}. Every spend is refused until it is corrected. Nothing was signed."
        )
    return value


def ledger_path() -> Path:
    override = os.environ.get(ENV_LEDGER, "").strip()
    if not override:
        return Path.home() / ".xete" / "spend-ledger.json"
    path = Path(override).expanduser()
    if path.name == "identity.json":
        # ~/.xete/ holds the identity keystore. Nothing here may be aimed at it, however
        # the environment is configured.
        raise SpendGuardUnavailable(
            f"SPEND REFUSED: {ENV_LEDGER} points at {path}, which carries the name of the xete "
            "identity keystore. The spend ledger will not be written anywhere called "
            "identity.json. Point it somewhere else. Nothing was signed."
        )
    return path


# ── cross-process exclusive lock ─────────────────────────────────────────────────────

class _ExclusiveLock:
    """An exclusive lock held on a SEPARATE lock file.

    Deliberately never locks the ledger itself: the ledger is replaced by rename, and a
    lock held on an inode that has just been replaced protects nothing.
    """

    def __init__(self, path: Path):
        self._path = path
        self._fh = None
        self._posix = True

    def __enter__(self) -> "_ExclusiveLock":
        try:
            self._fh = open(self._path, "a+b")
        except OSError as e:
            raise SpendGuardUnavailable(
                f"SPEND REFUSED: the spend-limit lock file {self._path} could not be opened "
                f"({e.__class__.__name__}: {e}). A spend that cannot be recorded cannot be "
                "limited, so it is refused. Nothing was signed."
            ) from e
        try:
            self._acquire()
        except Exception:
            self._fh.close()
            self._fh = None
            raise
        return self

    def _acquire(self) -> None:
        try:
            import fcntl
        except ImportError:
            fcntl = None
        if fcntl is not None:
            self._posix = True
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
            return
        import msvcrt

        self._posix = False
        deadline = time.time() + _LOCK_TIMEOUT_SECONDS
        while True:
            try:
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_LOCK, 1)
                return
            except OSError:
                if time.time() >= deadline:
                    raise SpendGuardUnavailable(
                        f"SPEND REFUSED: timed out waiting for the spend-limit lock "
                        f"{self._path}. Another xete process may be stuck holding it. "
                        "Nothing was signed."
                    ) from None
                time.sleep(0.05)

    def __exit__(self, *_exc) -> bool:
        try:
            if self._posix:
                import fcntl

                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            else:
                import msvcrt

                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception:
            pass
        finally:
            self._fh.close()
            self._fh = None
        return False


# ── ledger I/O ───────────────────────────────────────────────────────────────────────

def _corrupt(path: Path, why: str) -> SpendGuardUnavailable:
    return SpendGuardUnavailable(
        f"SPEND REFUSED: the spend ledger at {path} is unusable — {why}. It is NOT being reset "
        "automatically: silently starting the budget over is precisely what a damaged ledger "
        "must not be able to cause. Inspect the file; if you are satisfied it is junk, move it "
        "aside deliberately and the window will start fresh. Nothing was signed."
    )


def _ensure_dir(path: Path) -> None:
    directory = path.parent
    try:
        directory.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        # Pre-existing — this is very likely ~/.xete/, which also holds identity.json.
        # Do not touch its mode. We only ever add our own file inside it.
        return
    except OSError as e:
        raise SpendGuardUnavailable(
            f"SPEND REFUSED: the spend-ledger directory {directory} could not be created "
            f"({e.__class__.__name__}: {e}). A spend that cannot be recorded cannot be limited, "
            "so it is refused. Nothing was signed."
        ) from e
    try:
        os.chmod(directory, 0o700)   # only ever on a directory we just created ourselves
    except OSError:
        pass


def _empty() -> dict:
    return {"version": LEDGER_VERSION, "last_ts": 0.0, "entries": []}


def _read_ledger(path: Path) -> dict:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return _empty()
    except OSError as e:
        raise SpendGuardUnavailable(
            f"SPEND REFUSED: the spend ledger at {path} could not be read "
            f"({e.__class__.__name__}: {e}). Spending is refused while the limits cannot be "
            "enforced. Nothing was signed."
        ) from e

    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise _corrupt(path, f"it is not valid JSON ({e})") from None
    if not isinstance(data, dict):
        raise _corrupt(path, "its top level is not a JSON object")
    if data.get("version") != LEDGER_VERSION:
        raise _corrupt(
            path,
            f"its version is {data.get('version')!r}, not {LEDGER_VERSION} — this xete-mcp does "
            "not know how to count the spending it records",
        )
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise _corrupt(path, "its 'entries' field is not a list")

    clean = []
    for item in entries:
        if not isinstance(item, dict):
            raise _corrupt(path, "one of its entries is not a JSON object")
        ts, lam = item.get("ts"), item.get("lamports")
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            raise _corrupt(path, f"an entry has a non-numeric timestamp ({ts!r})")
        if isinstance(lam, bool) or not isinstance(lam, int) or lam < 0:
            raise _corrupt(path, f"an entry has a non-integer or negative amount ({lam!r})")
        clean.append({
            "ts": float(ts),
            "lamports": int(lam),
            "path": str(item.get("path", "")),
            "detail": str(item.get("detail", "")),
        })

    last = data.get("last_ts", 0.0)
    if isinstance(last, bool) or not isinstance(last, (int, float)):
        raise _corrupt(path, f"its 'last_ts' field is not numeric ({last!r})")

    return {"version": LEDGER_VERSION, "last_ts": float(last), "entries": clean}


def _write_ledger(path: Path, data: dict) -> None:
    tmp = path.with_name(f"{path.name}.tmp{os.getpid()}")
    try:
        blob = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
        with open(tmp, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except OSError as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise SpendGuardUnavailable(
            f"SPEND REFUSED: the spend ledger at {path} could not be written "
            f"({e.__class__.__name__}: {e}). A spend that cannot be recorded cannot be limited, "
            "so it is refused. Check that the directory exists and is writable. Nothing was signed."
        ) from e


# ── window arithmetic ────────────────────────────────────────────────────────────────

def _effective_now(last_ts: float) -> float:
    """Wall clock, except never allowed to run backwards past what we have already seen.

    time.time() is UTC epoch seconds, so a timezone or DST change moves nothing here. A
    backwards jump (NTP correction, a hand-set clock) would otherwise age entries out
    early; holding the window open at the newest timestamp ever observed prevents that.
    A forwards jump cannot be detected from the wall clock alone — see the DDR.
    """
    now = time.time()
    return last_ts if now < last_ts - _CLOCK_SLACK_SECONDS else now


def _live(entries: list, effective_now: float, window_seconds: int) -> list:
    cutoff = effective_now - window_seconds
    return [e for e in entries if e["ts"] > cutoff]


def _frees_at(entries: list, needed: int, window_seconds: int):
    """When `needed` lamports of window budget will exist, if nothing else is spent."""
    freed = 0
    for entry in sorted(entries, key=lambda e: e["ts"]):
        freed += entry["lamports"]
        if freed >= needed:
            return entry["ts"] + window_seconds
    return None


def _compact(entries: list) -> list:
    """Bound the file size without ever under-counting.

    Merged entries take the NEWEST timestamp in the merged set, so the total expires
    later than it otherwise would, never sooner.
    """
    if len(entries) <= MAX_ENTRIES:
        return entries
    ordered = sorted(entries, key=lambda e: e["ts"])
    keep = ordered[-(MAX_ENTRIES - 1):]
    merged = ordered[: len(ordered) - len(keep)]
    return [{
        "ts": max(e["ts"] for e in merged),
        "lamports": sum(e["lamports"] for e in merged),
        "path": "(compacted)",
        "detail": f"{len(merged)} older entries merged",
    }] + keep


# ── the gate ─────────────────────────────────────────────────────────────────────────

def authorize(lamports: int, path_label: str, detail: str = "") -> dict:
    """Approve and record a spend, or refuse it. Call this BEFORE any key is used.

    Returns a summary dict on approval. Raises SpendRefused (or its subclass
    SpendGuardUnavailable) on refusal, in which case nothing has been signed or sent.

    The spend is recorded at approval time rather than on success, deliberately: an
    approved attempt that then fails still counts against the window, because a
    transaction that never left is indistinguishable from one that landed and lost its
    receipt, and over-counting is the safe direction for a ceiling.
    """
    try:
        quoted = int(lamports)
    except (TypeError, ValueError):
        raise SpendRefused(
            f"SPEND REFUSED: {path_label} asked to spend {lamports!r}, which is not a whole "
            "number of lamports. Nothing was signed."
        ) from None
    if quoted < 0:
        raise SpendRefused(
            f"SPEND REFUSED: {path_label} asked to spend {quoted} lamports, which is negative. "
            "Nothing was signed."
        )

    max_lamports = _int_env(ENV_MAX, DEFAULT_MAX_LAMPORTS)
    window_lamports = _int_env(ENV_WINDOW, DEFAULT_WINDOW_LAMPORTS)
    window_seconds = _int_env(ENV_WINDOW_SECONDS, DEFAULT_WINDOW_SECONDS, minimum=1)
    floor = _int_env(ENV_FLOOR, DEFAULT_FLOOR_LAMPORTS)

    if max_lamports == 0:
        raise SpendRefused(
            f"SPEND REFUSED: all spending is disabled by {ENV_MAX}=0, so {path_label} cannot "
            f"spend {_fmt(quoted)}. Set {ENV_MAX} to the most a single transaction may cost and "
            "restart the MCP server. Nothing was signed."
        )
    if window_lamports == 0:
        raise SpendRefused(
            f"SPEND REFUSED: all spending is disabled by {ENV_WINDOW}=0, so {path_label} cannot "
            f"spend {_fmt(quoted)}. Set {ENV_WINDOW} to the most that may be spent per window and "
            "restart the MCP server. Nothing was signed."
        )
    if floor > max_lamports:
        raise SpendGuardUnavailable(
            f"SPEND REFUSED (contradictory configuration): {ENV_FLOOR} is {floor} but {ENV_MAX} "
            f"is {max_lamports}, so every on-chain action is charged more than the "
            "per-transaction cap permits and nothing could ever be spent. Raise "
            f"{ENV_MAX} or lower {ENV_FLOOR}. Nothing was signed."
        )

    charged = max(quoted, floor)
    floor_note = ""
    if charged > quoted:
        floor_note = (f" (quoted {_fmt(quoted)}; charged at the {ENV_FLOOR} minimum of "
                      f"{_fmt(floor)}, which covers the on-chain rent and fees a quote excludes)")
    context = f" Context: {detail}." if detail else ""

    if charged > max_lamports:
        raise SpendRefused(
            f"SPEND REFUSED (per-transaction cap): {path_label} attempted {_fmt(charged)}"
            f"{floor_note}, above {ENV_MAX} = {_fmt(max_lamports)}. This cap is per single "
            "transaction, so waiting will not help. To allow it, raise "
            f"{ENV_MAX} (currently {max_lamports}) and restart the MCP server. "
            f"Nothing was signed.{context}"
        )

    path = ledger_path()
    _ensure_dir(path)
    with _ExclusiveLock(path.with_name(f"{path.name}.lock")):
        data = _read_ledger(path)
        effective_now = _effective_now(data["last_ts"])
        live = _live(data["entries"], effective_now, window_seconds)
        spent = sum(e["lamports"] for e in live)

        if spent + charged > window_lamports:
            headroom = max(0, window_lamports - spent)
            frees_at = _frees_at(live, charged - headroom, window_seconds)
            if frees_at is None:
                when = (f"never inside a {window_seconds}s window — this one spend of "
                        f"{_fmt(charged)} exceeds {ENV_WINDOW} = {_fmt(window_lamports)} by itself")
            else:
                when = f"{_utc(frees_at)} (in {_dur(frees_at - effective_now)})"
            raise SpendRefused(
                f"SPEND REFUSED (windowed cap): {path_label} attempted {_fmt(charged)}"
                f"{floor_note}, which would take spending in the last {window_seconds}s to "
                f"{_fmt(spent + charged)} — over {ENV_WINDOW} = {_fmt(window_lamports)}. "
                f"Already spent in this window: {_fmt(spent)} across {len(live)} transaction(s); "
                f"{_fmt(headroom)} of budget remains. Budget for this spend frees up at {when}. "
                f"To allow it now, raise {ENV_WINDOW} (currently {window_lamports}) or shorten "
                f"{ENV_WINDOW_SECONDS} (currently {window_seconds}) and restart the MCP server. "
                f"Nothing was signed.{context}"
            )

        live.append({
            "ts": effective_now,
            "lamports": charged,
            "path": str(path_label),
            "detail": str(detail)[:200],
        })
        _write_ledger(path, {
            "version": LEDGER_VERSION,
            "last_ts": max(effective_now, data["last_ts"]),
            "entries": _compact(live),
        })

    return {
        "approved": True,
        "path": path_label,
        "quoted_lamports": quoted,
        "charged_lamports": charged,
        "window_spent_lamports": spent + charged,
        "window_remaining_lamports": window_lamports - (spent + charged),
        "window_seconds": window_seconds,
    }


def status() -> dict:
    """Read-only view of the limits in force and what is left in the current window.

    Never creates anything and never takes the lock — the ledger is only ever replaced
    atomically, so an unlocked read cannot observe a torn file, only a slightly stale one.
    """
    try:
        out = {
            "enforced": True,
            "per_transaction_max_lamports": _int_env(ENV_MAX, DEFAULT_MAX_LAMPORTS),
            "window_lamports": _int_env(ENV_WINDOW, DEFAULT_WINDOW_LAMPORTS),
            "window_seconds": _int_env(ENV_WINDOW_SECONDS, DEFAULT_WINDOW_SECONDS, minimum=1),
            "on_chain_floor_lamports": _int_env(ENV_FLOOR, DEFAULT_FLOOR_LAMPORTS),
            "ledger": str(ledger_path()),
        }
    except SpendRefused as e:
        return {"enforced": True, "error": str(e)}

    try:
        data = _read_ledger(ledger_path())
    except SpendRefused as e:
        out["error"] = str(e)
        return out

    live = _live(data["entries"], _effective_now(data["last_ts"]), out["window_seconds"])
    spent = sum(e["lamports"] for e in live)
    out["window_spent_lamports"] = spent
    out["window_remaining_lamports"] = max(0, out["window_lamports"] - spent)
    out["transactions_in_window"] = len(live)
    return out
