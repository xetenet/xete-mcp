# DDR: `xete-mcp --kbkit` hands off to kbkit's setup without changing anything the MCP server does

Commit scope: `src/xete_mcp/kbkit_handoff.py` (new), `src/xete_mcp/server.py` (`main()` only),
`src/xete_mcp/__init__.py` (`__version__` from package metadata), `pyproject.toml` (0.1.8, sdist
include patterns anchored), `server.json`, `gemini-extension.json` (0.1.8), `README.md` (one
paragraph), `test_kbkit_handoff.py` (new), `specs/SPEC-kbkit-handoff-20260922.md` (new).

Branch `kbkit-handoff`, cut clean off `origin/main` (1687c90) in a separate worktree.

## Claim

The handoff is reachable only when the first argument is exactly `--kbkit`; it runs nothing but
uv's own `uvx.exe`/`uvx` from an absolute PATH entry, with the package `xete-kbkit`; it reads no
xete identity and passes no `XETE_*` variable to the child; every other invocation behaves as
before; the published wheel adds only `kbkit_handoff.py`; and the version bump is complete.

## Security gates

This change touches no crypto, key handling, payment, or on-chain code. The only new capability
is starting a subprocess, and the gate for that is below (assumptions 2 to 5).

## Assumptions (verified / inherited / assumed)

| # | Assumption | Status | Basis |
|---|---|---|---|
| 1 | No existing invocation reaches the handoff | **VERIFIED** | `main()` checks `argv[1] == "--kbkit"` only; `gemini-extension.json` passes `["xete-mcp"]`, `server.json` declares no arguments; `python -m xete_mcp` goes through the same `main()`; tests fail if the check is loosened to `in argv` or the exit is dropped |
| 2 | The name `xete-kbkit` cannot be registered by anyone else when 0.1.8 ships | **VERIFIED** | published by XETENET on 2026-09-22 before this release (three wheels, 0.1.6); requirement `>=0.1.6` so no older or foreign version resolves |
| 3 | A uvx planted in the working folder is never run | **VERIFIED** | `find_uvx` skips empty, relative, and (on Windows) drive-relative PATH entries and accepts only `uvx.exe` on Windows; test plants `uvx`, `uvx.exe`, `uvx.bat`, `uvx.cmd` in the current folder and on relative entries; `shutil.which` is not used because before Python 3.12 it searches the current folder first on Windows |
| 4 | Arguments cannot change which package runs | **VERIFIED** | list argv, no shell; everything after `setup` goes to the command, not to uv (reviewer tested `--from`, `--with`, `--index-url` after `setup`, and a `&` argument stayed literal) |
| 5 | No xete secret reaches the child | **VERIFIED** | `child_env()` drops every variable whose upper-cased name starts with `XETE_`; tested with mixed case |
| 6 | Importing the server for `--kbkit` reads no identity | **VERIFIED** | module level only reads environment variables and builds paths; `load_or_create_identity` runs inside tool functions; end-to-end run from an empty folder created nothing |
| 7 | The packages ship nothing new but the module | **VERIFIED** | wheel = the 0.1.7 module set plus `kbkit_handoff.py`; sdist lists `src/xete_mcp/*`, `README.md`, `pyproject.toml`, `LICENSE`, `PKG-INFO`, and `.gitignore`, which hatchling always adds and which is already public in this repository. The unanchored include had matched every `LICENSE` in an untracked test venv; anchored with `/`, and releases are built from a clean clone |
| 8 | The version bump is complete | **VERIFIED** | `pyproject.toml`, both places in `server.json`, `gemini-extension.json` agree (manifest test); `__version__` had said 0.1.0 since the first release and now reads package metadata |
| 9 | uv's project config in the working folder can redirect the index | **INHERITED, accepted** | true of `uvx xete-mcp` itself today; `--no-config` would also drop a user's legitimate global config (corporate mirrors), so it is not passed |

## Doubts raised

**Fresh-context adversarial review, round 1** — a separate agent with no prior context, given the
claim, the diff and five lenses (correctness, argument injection and PATH hijack, supply chain,
packaging, test quality). Verdict **BLOCK**:

- HIGH: `xete-kbkit` was not yet on PyPI, so the name could be squatted and every `--kbkit` user
  would run the squatter's code. → Published first (assumption 2).
- HIGH: the sdist carried 37 `LICENSE` files from an untracked `.venv-test`. → Includes anchored;
  release built from a clean clone (assumption 7).
- MED: on Python 3.10/3.11 for Windows, `shutil.which` returned a `uvx.bat` from the current
  folder ahead of the real uvx; a hostile repository is exactly where kbkit setup runs. → Own
  PATH walk (assumption 3).
- LOW: child inherited `XETE_*` variables → stripped. Ctrl-C killed the setup mid-write → waits.
  `__version__` stale → metadata. Project uv config → accepted (assumption 9).

**Fresh-context adversarial review, round 2** — a second separate agent, given the round-1
findings and the fixes, asked to verify each is closed and look for regressions. Verdict
**SHIP**; every round-1 finding closed with evidence, and an end-to-end run with stdin not a
terminal reached kb setup from PyPI, which refused with its "asks questions at a terminal"
message and exit code 2. Two new LOW findings:

- A PATH entry like `\tools` is absolute to `os.path.isabs` on Windows but relative to the current
  drive. → Entries without a drive or UNC prefix are skipped on Windows; added to the test.
- `.gitignore` in the sdist → hatchling adds it regardless of `exclude`; already public; recorded
  in assumption 7.

## Tests

- `test_kbkit_handoff.py`: 8 tests (flag position, command line, `XETE_*` stripped, missing uvx,
  planted and relative uvx, drive-relative entry, Ctrl-C, server not started / started).
- Full suite on Linux (WSL Ubuntu), Python 3.10 and 3.12: 846 passed, 9 skipped, 0 failed.
- Full suite on Windows, Python 3.12: all pass except two tests that also fail on `origin/main`
  there (POSIX file modes and the local hook check under Git for Windows); CI runs Ubuntu.

## Verdict: SHIP
