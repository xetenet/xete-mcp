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
