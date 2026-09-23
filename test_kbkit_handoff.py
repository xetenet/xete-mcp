"""`xete-mcp --kbkit` hands off to `uvx xete-kbkit setup` and never starts the MCP server.

The flag is only honoured as the first argument, so an MCP client config that happens to carry
the string elsewhere cannot divert the server. Without uvx the handoff fails loudly with the
command to run, instead of falling through to the server. uvx is taken only from an absolute PATH
entry, never from the current folder, and the child gets no XETE_* variable.
"""
from __future__ import annotations

import os
import sys

import pytest

from xete_mcp import kbkit_handoff, server


def test_flag_only_as_first_argument():
    assert kbkit_handoff.wants_handoff(["xete-mcp", "--kbkit"])
    assert kbkit_handoff.wants_handoff(["xete-mcp", "--kbkit", "--root", "x"])
    assert not kbkit_handoff.wants_handoff(["xete-mcp"])
    assert not kbkit_handoff.wants_handoff(["xete-mcp", "--other", "--kbkit"])
    assert not kbkit_handoff.wants_handoff(["xete-mcp", "--kbkit=1"])


def test_runs_uvx_setup_and_returns_its_exit_code(monkeypatch):
    calls = []
    monkeypatch.setattr(kbkit_handoff, "find_uvx", lambda: "/fake/uvx")
    monkeypatch.setattr(kbkit_handoff, "_spawn", lambda args, env: calls.append(args) or 3)
    assert kbkit_handoff.run(["xete-mcp", "--kbkit", "--root", "proj"]) == 3
    assert calls == [["/fake/uvx", "--from", "xete-kbkit>=0.1.6", "xete-kbkit", "setup", "--root", "proj"]]


def test_child_gets_no_xete_variables(monkeypatch):
    envs = []
    monkeypatch.setenv("XETE_SOL_KEYPAIR", "secret-path")
    monkeypatch.setenv("xete_lowercase", "also-secret")
    monkeypatch.setenv("KBKIT_HANDOFF_PROBE", "kept")
    monkeypatch.setattr(kbkit_handoff, "find_uvx", lambda: "/fake/uvx")
    monkeypatch.setattr(kbkit_handoff, "_spawn", lambda args, env: envs.append(env) or 0)
    kbkit_handoff.run(["xete-mcp", "--kbkit"])
    assert not any(k.upper().startswith("XETE_") for k in envs[0])
    assert envs[0]["KBKIT_HANDOFF_PROBE"] == "kept"


def test_missing_uvx_fails_loudly_without_running_anything(monkeypatch, capsys):
    monkeypatch.setattr(kbkit_handoff, "find_uvx", lambda: None)
    monkeypatch.setattr(kbkit_handoff, "_spawn", lambda args, env: pytest.fail("ran without uvx"))
    assert kbkit_handoff.run(["xete-mcp", "--kbkit"]) == 127
    err = capsys.readouterr().err
    assert "uvx xete-kbkit setup" in err and "docs.astral.sh/uv" in err


def test_uvx_in_the_current_folder_or_a_relative_entry_is_never_used(tmp_path, monkeypatch):
    here = tmp_path / "hostile-repo"
    here.mkdir()
    for name in ("uvx", "uvx.exe", "uvx.bat", "uvx.cmd"):
        (here / name).write_text("planted")
        os.chmod(here / name, 0o755)
    monkeypatch.chdir(here)
    for windows in (True, False):
        assert kbkit_handoff.find_uvx(path=os.pathsep.join(["", ".", "hostile-repo", "\\hostile-repo"]), windows=windows) is None
    real = tmp_path / "bin"
    real.mkdir()
    windows = os.name == "nt"
    (real / "uvx.bat").write_text("a batch file")
    assert kbkit_handoff.find_uvx(path=str(real), windows=windows) is None
    # the real one after a planted entry is still found, on the host's own path rules
    name = "uvx.exe" if windows else "uvx"
    (real / name).write_text("uv")
    os.chmod(real / name, 0o755)
    assert kbkit_handoff.find_uvx(path=os.pathsep.join([".", str(real)]), windows=windows) == os.path.join(str(real), name)


def test_ctrl_c_waits_for_the_setup_to_exit(monkeypatch):
    class Proc:
        waits = 0

        def wait(self):
            Proc.waits += 1
            if Proc.waits == 1:
                raise KeyboardInterrupt
            return 130

    monkeypatch.setattr(kbkit_handoff.subprocess, "Popen", lambda args, env: Proc())
    assert kbkit_handoff._spawn(["uvx"], {}) == 130
    assert Proc.waits == 2


def test_main_hands_off_before_the_server_starts(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["xete-mcp", "--kbkit"])
    monkeypatch.setattr(kbkit_handoff, "run", lambda argv: 0)
    monkeypatch.setattr(server.mcp, "run", lambda *a, **k: pytest.fail("the MCP server started"))
    with pytest.raises(SystemExit) as exit_:
        server.main()
    assert exit_.value.code == 0


def test_main_without_the_flag_starts_the_server(monkeypatch):
    started = []
    monkeypatch.setattr(sys, "argv", ["xete-mcp"])
    monkeypatch.setattr(kbkit_handoff, "run", lambda argv: pytest.fail("handed off without the flag"))
    monkeypatch.setattr(server.mcp, "run", lambda *a, **k: started.append(True))
    server.main()
    assert started == [True]
