#!/bin/bash
# Launch the %ollama xete agent (your local Ollama model on xete messaging).
# Idempotent: refuses to start a 2nd copy (a duplicate would split-brain the inbox),
# and makes sure `ollama serve` is up first. Change OLLAMA_MODEL to switch models.
set -u
export OLLAMA_MODEL=${OLLAMA_MODEL:-llama3.1:8b}
export OLLAMA_URL=${OLLAMA_URL:-http://localhost:11434}
export XETE_IDENTITY=${XETE_IDENTITY:-$HOME/.xete/ollama-identity.json}
export XETE_SEEN_PATH=${XETE_SEEN_PATH:-$HOME/.xete/ollama.seen.json}

# SECURITY GATE: only these sender ids can drive the local tools (list/read files,
# run shell). Everyone else who messages %ollama gets plain chat, no tools. xete
# sender ids are cryptographically authenticated, so this gate is the real boundary.
# Keep this to people you trust with a shell on THIS machine.
#   ONLY you: 96fe5e88... (%hugeballs / your personal wallet). No one else can drive the tools.
export OLLAMA_ALLOWED_SENDERS=${OLLAMA_ALLOWED_SENDERS:-96fe5e88-7e39-4f98-b428-8312210dc588}

if pgrep -f "run_agent.py --handler ollama" >/dev/null 2>&1; then
  echo "ollama agent already running (pid $(pgrep -f 'run_agent.py --handler ollama' | head -1)) — not starting a second."
  exit 0
fi
if ! pgrep -x ollama >/dev/null 2>&1; then
  setsid nohup ollama serve >>"$HOME/.ollama-serve.log" 2>&1 &
  for _ in $(seq 1 20); do curl -s --max-time 2 http://localhost:11434/api/tags >/dev/null 2>&1 && break; sleep 1; done
fi
cd "$(cd "$(dirname "$0")" && pwd)"
exec "$HOME/.xete-agent-venv/bin/python" run_agent.py --handler ollama-tools --name ollama
