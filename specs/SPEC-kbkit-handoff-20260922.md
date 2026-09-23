# SPEC: `xete-mcp --kbkit` hands off to kbkit's setup

Status: BUILT on branch `kbkit-handoff`; review in `reviews/DDR-kbkit-handoff-20260922.md`.

## Problem

kbkit (github.com/xetenet/kbkit, PyPI `xete-kbkit`) is a separate tool from the same publisher:
a project record for AI coding sessions plus a local search index. People who already run
`uvx xete-mcp` should reach its setup with one flag, without learning a second install line.

## Behaviour

- `xete-mcp --kbkit [args...]` runs `uvx --from "xete-kbkit>=0.1.6" xete-kbkit setup [args...]`
  with the terminal passed through, and exits with its code. It never starts the MCP server.
- The flag counts only as the first argument. Any other invocation starts the server as before.
- uvx is taken only from an absolute, drive-qualified PATH entry; on Windows only `uvx.exe`.
  Without it, the command prints how to install uv and the command to run, and exits 127.
- The child gets the environment minus every `XETE_*` variable.
- Ctrl-C waits for the setup to exit instead of killing it partway through a write.

## Non-goals

- No kbkit code in this package, no dependency on it, no download at install time.
- No MCP tool for kbkit. kbkit serves its own read-only MCP tools.

## Release order

`xete-kbkit` must be live on PyPI under the XETENET account before 0.1.8 ships, so the name the
flag resolves cannot be registered by anyone else. Done 2026-09-22 (xete-kbkit 0.1.6).
