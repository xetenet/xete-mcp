#!/usr/bin/env python3
"""xete agent HANDLERS — the bot/model layer (transport-agnostic).

Each handler implements `handle(sender_id, text) -> Optional[str]` and may add
`tick(runtime)` for periodic chores. They know NOTHING about keys, crypto, or the
inbox — agent_runtime.py owns all of that. Swap or upgrade a handler without
touching the messaging, and upgrade the messaging without touching these.
"""
from __future__ import annotations

import collections
import os
import time
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
class ReflectorHandler:
    """Plain end-to-end echo: proves the encrypted round trip and nothing more.
    The cold-start killer — one new agent can message it and instantly get a real
    encrypted reply with no counterparty."""
    name = "echo"
    reply_marker = "echo: "   # runtime prefixes replies + skips inbound starting with it (anti-loop)

    def __init__(self, max_chars: int = 400):
        self.max_chars = max_chars

    def handle(self, sender_id: str, text: Optional[str]) -> Optional[str]:
        if text is None:
            body = "(your message arrived but couldn't be decrypted)"
        elif len(text) > self.max_chars:
            body = text[: self.max_chars] + " ...(truncated)"
        else:
            body = text
        return (
            f"{body}\n\n"
            "That was a real end-to-end-encrypted round trip on xete (x25519 + AES-256-GCM). "
            "The server only ever saw ciphertext and could not read this. You're live."
        )


# ─────────────────────────────────────────────────────────────────────────────
class TourHandler:
    """Welcome-tour concierge: wraps the existing stateful echo_tour engine
    (per-sender state machine + invite-code reward). Pure bot logic; the runtime
    moves the bytes. tick() tops-up-alerts a human when the invite pool runs low."""
    name = "echo"
    reply_marker = ""

    def __init__(self, alert_to: Optional[str] = None, alert_cooldown_s: int = 3600):
        import echo_tour  # imported here so the reflector/ollama paths don't need it
        self._tour = echo_tour
        self.alert_to = alert_to or os.environ.get(
            "XETE_ECHO_ALERT_TO", "3e2460a6-d3b1-4819-a7e9-c2c653279bfb"  # lead
        )
        self.alert_cooldown_s = alert_cooldown_s
        self._last_alert = 0.0

    def handle(self, sender_id: str, text: Optional[str]) -> Optional[str]:
        return self._tour.advance(sender_id, text)

    def tick(self, runtime) -> None:
        # Echo distributes codes, never mints them — when the pool is low it just
        # asks a human (lead) to top it up. Cooldown so it doesn't nag.
        left = self._tour.check_low_pool()
        if left is None:
            return
        now = time.time()
        if now - self._last_alert < self.alert_cooldown_s:
            return
        self._last_alert = now
        try:
            runtime.send(self.alert_to, f"echo: invite pool low — {left} codes left. Please top it up.", subject="xete ops")
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
class OllamaHandler:
    """Routes each incoming message to a LOCAL Ollama model and returns its reply.
    Lets you message the agent over xete and have your own model act on it. Keeps a
    short per-sender history for coherence. Single dependency: a running Ollama.

    Env:
      OLLAMA_URL     default http://localhost:11434
      OLLAMA_MODEL   REQUIRED — e.g. 'llama3.1' / 'qwen2.5' (whatever you've pulled)
      OLLAMA_SYSTEM  optional system prompt
      OLLAMA_NUM_CTX optional context window (default model default)
    """
    name = "ollama"
    reply_marker = ""

    def __init__(self, model: Optional[str] = None, url: Optional[str] = None,
                 system: Optional[str] = None, history_turns: int = 6, timeout_s: int = 120):
        self.url = (url or os.environ.get("OLLAMA_URL", "http://localhost:11434")).rstrip("/")
        self.model = model or os.environ.get("OLLAMA_MODEL", "")
        if not self.model:
            raise SystemExit("OllamaHandler: set OLLAMA_MODEL to a model you've pulled (`ollama list`).")
        self.system = system or os.environ.get(
            "OLLAMA_SYSTEM",
            "You are a helpful assistant reachable over xete's encrypted messaging. "
            "Be concise and direct. The person messaging you may ask you to do or explain things.",
        )
        self.timeout_s = timeout_s
        self.history_turns = history_turns
        self._hist: dict[str, collections.deque] = {}

    def handle(self, sender_id: str, text: Optional[str]) -> Optional[str]:
        import requests  # lazy import; only the ollama path needs it
        if not text:
            return "(your message arrived but couldn't be decrypted)"
        hist = self._hist.setdefault(sender_id, collections.deque(maxlen=self.history_turns * 2))
        messages = [{"role": "system", "content": self.system}]
        messages += list(hist)
        messages.append({"role": "user", "content": text})
        try:
            r = requests.post(
                f"{self.url}/api/chat",
                json={"model": self.model, "messages": messages, "stream": False},
                timeout=self.timeout_s,
            )
            r.raise_for_status()
            reply = (r.json().get("message", {}) or {}).get("content", "").strip()
        except Exception as e:
            return f"(local model unreachable: {str(e)[:140]})"
        if not reply:
            return "(the model returned an empty response)"
        hist.append({"role": "user", "content": text})
        hist.append({"role": "assistant", "content": reply})
        return reply


# ─────────────────────────────────────────────────────────────────────────────
class OllamaToolHandler(OllamaHandler):
    """Ollama with HANDS: a tool-calling agent that can actually act on the local
    machine (list/read files, run shell) on behalf of its owner.

    *** SECURITY: tool execution is GATED to an allowlist of sender ids. *** %ollama is
    reachable by anyone on xete; without the gate this would be remote shell-for-the-world.
    Allowed senders get the full agentic loop; everyone else gets plain chat (no tools).
    xete sender ids are cryptographically authenticated by the relay, so the gate holds.

    Env:
      OLLAMA_ALLOWED_SENDERS  comma-separated agent_ids (and/or %aliases) allowed to run
                              tools. REQUIRED to enable tools — empty => plain chat for all.
      OLLAMA_TOOL_TIMEOUT     per-shell-command timeout seconds (default 60)
      OLLAMA_TOOL_OUT_CAP     max chars of tool output fed back to the model (default 6000)
      OLLAMA_MAX_STEPS        max tool round-trips per message (default 6)
    """
    name = "ollama"

    _TOOLS = [
        {"type": "function", "function": {
            "name": "list_dir", "description": "List the entries in a directory.",
            "parameters": {"type": "object", "properties": {"path": {"type": "string", "description": "directory path"}}, "required": ["path"]}}},
        {"type": "function", "function": {
            "name": "read_file", "description": "Read and return the contents of a text file.",
            "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
        {"type": "function", "function": {
            "name": "run_shell", "description": "Run a shell command on the local machine and return its stdout+stderr.",
            "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}}},
    ]

    def __init__(self, **kw):
        super().__init__(**kw)
        import subprocess  # noqa
        self._subprocess = subprocess
        raw = os.environ.get("OLLAMA_ALLOWED_SENDERS", "")
        self.allowed = {s.strip() for s in raw.split(",") if s.strip()}
        self.tool_timeout = int(os.environ.get("OLLAMA_TOOL_TIMEOUT", "60"))
        self.tool_out_cap = int(os.environ.get("OLLAMA_TOOL_OUT_CAP", "6000"))
        self.max_steps = int(os.environ.get("OLLAMA_MAX_STEPS", "6"))
        self.system = os.environ.get(
            "OLLAMA_SYSTEM",
            "You are a capable assistant running ON the owner's local machine, reachable over "
            "xete's encrypted messaging. You have tools: list_dir, read_file, run_shell. Use them "
            "to actually inspect the filesystem and run commands when asked — do not claim you "
            "can't access files; you can, via your tools. Be concise; report what you did and found.",
        )

    # ── tools ────────────────────────────────────────────────────────────────
    def _exec_tool(self, name: str, args: dict) -> str:
        try:
            if name == "list_dir":
                p = os.path.expanduser(str(args.get("path", ".")))
                return "\n".join(sorted(os.listdir(p))) or "(empty)"
            if name == "read_file":
                p = os.path.expanduser(str(args.get("path", "")))
                with open(p, "r", errors="replace") as f:
                    return f.read(self.tool_out_cap)
            if name == "run_shell":
                cmd = str(args.get("command", ""))
                r = self._subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.tool_timeout)
                out = (r.stdout or "") + (("\n[stderr]\n" + r.stderr) if r.stderr else "")
                return (out.strip() or f"(exit {r.returncode}, no output)")[: self.tool_out_cap]
            return f"(unknown tool {name})"
        except Exception as e:
            return f"(tool error: {str(e)[:200]})"

    def _chat(self, messages: list, tools=None) -> dict:
        import requests
        body = {"model": self.model, "messages": messages, "stream": False}
        if tools:
            body["tools"] = tools
        r = requests.post(f"{self.url}/api/chat", json=body, timeout=self.timeout_s)
        r.raise_for_status()
        return r.json().get("message", {}) or {}

    def handle(self, sender_id: str, text: Optional[str]) -> Optional[str]:
        if not text:
            return "(your message arrived but couldn't be decrypted)"
        # Not allowlisted -> plain chat, NO tools (the security boundary).
        if sender_id not in self.allowed:
            return super().handle(sender_id, text)
        hist = self._hist.setdefault(sender_id, collections.deque(maxlen=self.history_turns * 2))
        messages = [{"role": "system", "content": self.system}] + list(hist) + [{"role": "user", "content": text}]
        steps_log = []
        try:
            for _ in range(self.max_steps):
                msg = self._chat(messages, tools=self._TOOLS)
                calls = msg.get("tool_calls") or []
                if not calls:
                    reply = (msg.get("content") or "").strip()
                    hist.append({"role": "user", "content": text})
                    hist.append({"role": "assistant", "content": reply})
                    if steps_log:
                        print(f"[ollama] tools run for {sender_id[:8]}: {', '.join(steps_log)}", flush=True)
                    return reply or "(empty response)"
                messages.append(msg)  # assistant turn that requested the tools
                for tc in calls:
                    fn = tc.get("function", {}) or {}
                    fname = fn.get("name", "")
                    fargs = fn.get("arguments", {}) or {}
                    if isinstance(fargs, str):
                        try:
                            import json as _json
                            fargs = _json.loads(fargs)
                        except Exception:
                            fargs = {}
                    result = self._exec_tool(fname, fargs)
                    steps_log.append(f"{fname}({list(fargs.values())[:1]})")
                    messages.append({"role": "tool", "content": result})
            return "(stopped after the tool-step limit; ask me to continue)"
        except Exception as e:
            return f"(local model/tool error: {str(e)[:160]})"


def build_handler(kind: str):
    """Factory used by run_agent.py. kind: echo|reflect|tour|ollama|ollama-tools."""
    kind = (kind or "").lower()
    if kind in ("echo", "reflect", "reflector"):
        return ReflectorHandler()
    if kind == "tour":
        return TourHandler()
    if kind == "ollama":
        return OllamaHandler()
    if kind in ("ollama-tools", "ollama-agent", "ollama_tools"):
        return OllamaToolHandler()
    raise SystemExit(f"unknown handler '{kind}' (use: echo | tour | ollama | ollama-tools)")
