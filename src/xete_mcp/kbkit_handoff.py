"""`xete-mcp --kbkit`: hand off to kbkit's setup, which is a separate program.

kbkit (https://github.com/xetenet/kbkit) is published on PyPI as `xete-kbkit`. This module runs
`uvx --from "xete-kbkit>=0.1.6" xete-kbkit setup` with the terminal passed through, so the setup's
questions reach the person, and returns its exit code. It starts no server, reads no xete
identity, and passes no XETE_* variable to the child.
"""
from __future__ import annotations

import os
import subprocess
import sys

FLAG = "--kbkit"
PACKAGE = "xete-kbkit"
REQUIREMENT = "xete-kbkit>=0.1.6"


def wants_handoff(argv: list[str]) -> bool:
    return len(argv) > 1 and argv[1] == FLAG


def find_uvx(path: str | None = None, windows: bool | None = None) -> str | None:
    """uvx from an absolute PATH entry only.

    shutil.which on Windows before Python 3.12 searches the current folder first, so a `uvx.bat`
    in a checked-out repository would run instead of uv. Relative entries are skipped for the same
    reason, as are drive-relative ones on Windows, and there only uvx.exe is accepted, so no batch
    file parses the arguments.
    """
    windows = os.name == "nt" if windows is None else windows
    name = "uvx.exe" if windows else "uvx"
    for entry in (os.environ.get("PATH", "") if path is None else path).split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry or not os.path.isabs(entry):
            continue
        if windows and not os.path.splitdrive(entry)[0]:
            continue  # a leading backslash with no drive is relative to the current folder's drive
        candidate = os.path.join(entry, name)
        if os.path.isfile(candidate) and (windows or os.access(candidate, os.X_OK)):
            return candidate
    return None


def child_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not k.upper().startswith("XETE_")}


def _spawn(args: list[str], env: dict[str, str]) -> int:
    proc = subprocess.Popen(args, env=env)
    while True:
        try:
            return proc.wait()
        except KeyboardInterrupt:
            # The terminal delivers Ctrl-C to the setup as well; let it finish its own exit
            # rather than killing it partway through a write.
            continue


def run(argv: list[str]) -> int:
    uvx = find_uvx()
    if uvx is None:
        print(
            f"xete-mcp --kbkit runs `uvx {PACKAGE} setup`, and uvx was not found on PATH.\n"
            "Install uv (https://docs.astral.sh/uv/), then run:\n"
            f"  uvx {PACKAGE} setup",
            file=sys.stderr,
        )
        return 127
    return _spawn([uvx, "--from", REQUIREMENT, PACKAGE, "setup", *argv[2:]], child_env())
