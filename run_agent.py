#!/usr/bin/env python3
"""xete agent entrypoint — wire an identity + a handler to the transport runtime.

Examples:
  # echo bot (welcome-tour concierge) on the box:
  XETE_IDENTITY=/opt/xete-echo/echo-identity.json python run_agent.py --handler tour --name echo

  # your local Ollama model as a xete agent:
  XETE_IDENTITY=~/.xete/ollama-identity.json OLLAMA_MODEL=llama3.1 \
      python run_agent.py --handler ollama --name ollama

Messaging (the runtime) and the model/bot (the handler) upgrade independently.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from agent_handlers import build_handler
from agent_runtime import XeteAgentRuntime


def main() -> int:
    ap = argparse.ArgumentParser(description="Run a xete agent (transport + pluggable handler).")
    ap.add_argument("--handler", default=os.environ.get("AGENT_HANDLER", "tour"),
                    help="echo | tour | ollama (default: tour)")
    ap.add_argument("--identity", default=os.environ.get("XETE_IDENTITY", str(Path.home() / ".xete" / "agent-identity.json")),
                    help="identity keystore path (created if missing)")
    ap.add_argument("--name", default=os.environ.get("AGENT_NAME", ""),
                    help="log label (defaults to the handler's name)")
    ap.add_argument("--seen", default=os.environ.get("XETE_SEEN_PATH", ""),
                    help="processed-id store (default: <identity>.seen.json). Point at the "
                         "existing store on upgrade so old messages aren't re-answered.")
    ap.add_argument("--server", default=os.environ.get("XETE_SERVER_URL", "https://xete.net"))
    ap.add_argument("--poll", type=int, default=int(os.environ.get("XETE_POLL_SECONDS", "10")))
    ap.add_argument("--per-sender-per-min", type=int, default=int(os.environ.get("XETE_PER_SENDER_PER_MIN", "5")))
    ap.add_argument("--global-per-min", type=int, default=int(os.environ.get("XETE_GLOBAL_PER_MIN", "60")))
    args = ap.parse_args()

    handler = build_handler(args.handler)
    runtime = XeteAgentRuntime(
        handler,
        identity_path=args.identity,
        name=args.name or getattr(handler, "name", "agent"),
        server_url=args.server,
        poll_seconds=args.poll,
        per_sender_per_min=args.per_sender_per_min,
        global_per_min=args.global_per_min,
    )
    return runtime.run()


if __name__ == "__main__":
    raise SystemExit(main())
