"""The gates themselves must be armed, not merely present.

WHY THIS FILE EXISTS: for an entire session the pre-commit hook was NOT EXECUTABLE. git
silently ignores a non-executable hook -- it prints an advisory at most -- so the DDR gate and
the commit-time secret scan were OFF for every commit that session while the repo, the
CLAUDE.md rules and my own commit messages all described them as enforcing. `pre-push` happened
to be executable, which is the only reason nothing escaped.

That is the hollow-test failure mode one layer up: a control that reports success while doing
nothing. The repo already had `scripts/install.sh` and a `core.hooksPath` setting, and both were
correct -- "installed" and "armed" are different properties and only the first was ever checked.

These tests assert the second one.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent

# The hooks that must ACTUALLY RUN. pre-commit carries the DDR gate and the secret scan;
# pre-push is the last line before anything reaches a public remote.
REQUIRED_HOOKS = ("pre-commit", "pre-push")


def _hooks_dir() -> Path:
    out = subprocess.run(["git", "config", "core.hooksPath"], cwd=REPO,
                         capture_output=True, text=True).stdout.strip()
    if not out:
        pytest.skip("core.hooksPath is unset; hooks are not installed in this checkout")
    p = Path(out)
    return p if p.is_absolute() else (REPO / p)


def test_the_hooks_directory_is_actually_configured():
    d = _hooks_dir()
    assert d.is_dir(), f"core.hooksPath points at {d}, which is not a directory"


@pytest.mark.parametrize("hook", REQUIRED_HOOKS)
def test_each_required_hook_is_present_and_executable(hook):
    """PRESENT IS NOT ENOUGH. git skips a hook that is not executable, and says so only in an
    advisory that scrolls past in normal output. A hook file sitting there with mode 0644 is
    indistinguishable from a working gate in every check except this one."""
    d = _hooks_dir()
    path = d / hook
    assert path.exists(), f"{hook} is missing from {d}"
    assert os.access(path, os.X_OK), (
        f"{path} EXISTS BUT IS NOT EXECUTABLE. git will silently skip it, so this gate is "
        f"reporting success while doing nothing. Fix: chmod +x {path}")


@pytest.mark.parametrize("hook", REQUIRED_HOOKS)
def test_each_required_hook_has_an_interpreter_line(hook):
    """An executable file with no shebang is executed by the caller's shell if it is lucky and
    fails opaquely if it is not. Cheap to assert, and it fails loudly rather than at 2am."""
    d = _hooks_dir()
    first = (d / hook).read_text(errors="replace").splitlines()[:1]
    assert first and first[0].startswith("#!"), (
        f"{hook} has no shebang; its first line is {first[0][:60]!r} if any")


def test_the_protected_paths_file_is_readable_and_non_empty():
    """The DDR gate decides what it guards from this file. An empty or unreadable one turns the
    gate into a no-op that still exits 0 -- the same failure as the missing +x bit, expressed
    through data rather than permissions."""
    d = _hooks_dir()
    pp = d / "protected-paths"
    if not pp.exists():
        pytest.skip("no protected-paths file in this hooks dir")
    body = [ln for ln in pp.read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")]
    assert body, "protected-paths has no active patterns; the DDR gate guards nothing"


# ══════════════════════════════════════════════════════════════════════════════════════
# ARMED IS NOT THE SAME AS EFFECTIVE.
#
# Everything above checks the hook is present, executable and has a shebang. None of it
# checks that the hook STOPS ANYTHING. A hook can be all three and still `exit 0`
# unconditionally; protected-paths can be non-empty and match nothing real; the gate can
# be perfectly installed and guard the empty set.
#
# That is the identical failure family, one layer up: present-but-unarmed became
# armed-but-ineffective. Raised by an outside reviewer against the tests above, which is
# exactly the value of a second context -- I wrote those tests believing they closed the
# hole, and they closed half of it.
#
# These run the REAL hook against a scratch clone. Never the working tree.
# ══════════════════════════════════════════════════════════════════════════════════════

import shutil
import tempfile


def _scratch_repo(tmp: Path) -> Path:
    """A throwaway git repo wired to the real hooks. Nothing here touches the working tree."""
    r = tmp / "scratch"
    r.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=r, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=r, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=r, check=True)
    subprocess.run(["git", "config", "core.hooksPath", str(_hooks_dir())], cwd=r, check=True)
    (r / "seed.txt").write_text("seed\n")
    subprocess.run(["git", "add", "seed.txt"], cwd=r, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "seed", "--no-verify"], cwd=r, check=True)
    return r


def _try_commit(repo: Path, msg: str):
    return subprocess.run(["git", "commit", "-q", "-m", msg], cwd=repo,
                          capture_output=True, text=True)


def test_the_precommit_hook_actually_blocks_a_protected_path_without_a_ddr():
    """THE behavioural test. A protected-path change with no reviews/DDR-*.md must be REFUSED.
    If this passes while the hook is a no-op, every 'the gate protected us' claim in this
    repo's history is decoration."""
    with tempfile.TemporaryDirectory() as td:
        repo = _scratch_repo(Path(td))
        f = repo / "src" / "xete_mcp"
        f.mkdir(parents=True)
        (f / "server.py").write_text("# protected path, no DDR staged\n")
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        r = _try_commit(repo, "touch a protected path with no review")
        assert r.returncode != 0, (
            "THE PRE-COMMIT GATE IS A NO-OP: a change to src/xete_mcp/server.py committed with "
            "no reviews/DDR-*.md staged. The hook is present and executable and stops nothing.")


def test_the_same_change_is_allowed_once_a_ship_ddr_is_staged():
    """The gate must also be PASSABLE. One that refuses everything gets bypassed with
    --no-verify within a day, which is worse than no gate because it still reports success."""
    with tempfile.TemporaryDirectory() as td:
        repo = _scratch_repo(Path(td))
        (repo / "src" / "xete_mcp").mkdir(parents=True)
        (repo / "src" / "xete_mcp" / "server.py").write_text("# protected path\n")
        rv = repo / "reviews"
        rv.mkdir()
        (rv / "DDR-scratch-20260101.md").write_text(
            "# DDR: scratch\n## Claim\nx\n## Assumptions\nx\n## Doubts raised\nx\n"
            "## Reconciliation\nx\n## Verdict: SHIP\n")
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        r = _try_commit(repo, "protected path WITH a SHIP ddr")
        assert r.returncode == 0, (
            "the gate refuses a properly reviewed change, which is how gates get bypassed:\n"
            + (r.stdout + r.stderr)[-600:])


def test_protected_paths_patterns_match_files_that_actually_exist():
    """A pattern list can be non-empty and still guard nothing -- a stale path, a typo, a
    renamed directory. Assert at least one pattern matches a real tracked file."""
    import re
    d = _hooks_dir()
    pp = d / "protected-paths"
    if not pp.exists():
        pytest.skip("no protected-paths file")
    pats = [ln.strip() for ln in pp.read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")]
    tracked = subprocess.run(["git", "ls-files"], cwd=REPO,
                             capture_output=True, text=True).stdout.split()
    matched = {p: [f for f in tracked if re.search(p, f)] for p in pats}
    live = {p: v for p, v in matched.items() if v}
    assert live, (
        f"NONE of the {len(pats)} protected-path patterns match any tracked file. The DDR gate "
        f"is installed, armed, and guarding the empty set. Patterns: {pats}")
