#!/usr/bin/env python3
"""xete agent runtime — the TRANSPORT layer (model/bot-agnostic).

This is the network shell for any xete bot. It owns ONLY the messaging:
  * identity load + login + UNIFIED key registration (x25519 from the wallet
    signature — the same key every interface derives, so replies are genuinely
    end-to-end encrypted and decryptable by HE / web / mcp clients);
  * polling the inbox, decrypting, dedup, rate-limiting, reply-only-to-sender;
  * sending encrypted replies.

It knows NOTHING about what the bot says. That lives in a pluggable HANDLER:

    handler.handle(sender_id, text) -> Optional[str]      # the reply, or None to stay silent
    handler.tick(runtime)            -> None   (optional)  # periodic chores (proactive sends)
    handler.reply_marker             -> str    (optional)  # anti-loop tag prefixed to replies
    handler.name                     -> str    (optional)

So you upgrade the MESSAGING (this file / the xete-mcp version) without touching
the bot, and swap/upgrade the BOT (the handler) without touching the messaging.

Security posture (carried over from the original echo agent):
  * Replies ONLY to the original sender — never an open relay.
  * Never transmits the private key; identity stored 0600; no plaintext logged.
  * Per-sender AND global sliding-window rate limits.
  * Skips its own messages and its own prior replies (reply_marker) — no ping-pong.
"""
from __future__ import annotations

import collections
import json
import os
import time
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

from xete_mcp.client import XeteClient, load_or_create_identity


@runtime_checkable
class Handler(Protocol):
    """The bot/model layer. Only `handle` is required."""
    def handle(self, sender_id: str, text: Optional[str]) -> Optional[str]: ...


def _log(name: str, msg: str) -> None:
    print(f"[{name}] {msg}", flush=True)


class RateLimiter:
    """Per-sender + global sliding-window limiter. Bounds outbound sends so no
    single sender (and no flood) can drain the agent."""
    def __init__(self, per_sender: int, global_max: int, window: float):
        self.per_sender = per_sender
        self.global_max = global_max
        self.window = window
        self.by_sender: dict[str, collections.deque] = {}
        self.glob: collections.deque = collections.deque()

    def check_and_record(self, sender: str, now: float) -> tuple[bool, str]:
        while self.glob and now - self.glob[0] > self.window:
            self.glob.popleft()
        if len(self.glob) >= self.global_max:
            return False, "global"
        dq = self.by_sender.setdefault(sender, collections.deque())
        while dq and now - dq[0] > self.window:
            dq.popleft()
        if len(dq) >= self.per_sender:
            return False, "per-sender"
        self.glob.append(now)
        dq.append(now)
        return True, ""

    def prune(self) -> None:
        for s in [s for s, d in self.by_sender.items() if not d]:
            del self.by_sender[s]


class XeteAgentRuntime:
    SEEN_CAP = 5000
    WINDOW = 60.0

    def __init__(
        self,
        handler: Handler,
        *,
        identity_path: str | Path,
        name: str = "agent",
        server_url: str = "https://xete.net",
        seen_path: Optional[str | Path] = None,
        poll_seconds: int = 10,
        per_sender_per_min: int = 5,
        global_per_min: int = 60,
        inbox_limit: int = 50,
    ):
        self.handler = handler
        self.name = getattr(handler, "name", None) or name
        self.server_url = server_url
        self.identity_path = Path(identity_path)
        self.seen_path = Path(seen_path) if seen_path else self.identity_path.with_suffix(".seen.json")
        self.poll_seconds = poll_seconds
        self.inbox_limit = inbox_limit
        self.reply_marker = getattr(handler, "reply_marker", "") or ""
        self.limiter = RateLimiter(per_sender_per_min, global_per_min, self.WINDOW)
        self.client: Optional[XeteClient] = None
        self.agent_id: str = ""

    # ── public API the HANDLER may use for proactive/standalone sends ──────────
    def send(self, to: str, text: str, subject: Optional[str] = None) -> dict:
        """Encrypted send to an agent_id or %alias. Used by tick()/handlers."""
        assert self.client is not None, "runtime not started"
        if self.reply_marker and not text.startswith(self.reply_marker):
            text = self.reply_marker + text
        # resolve %alias -> agent_id if needed (client handles bare ids directly)
        target = to
        if to.startswith("%"):
            target, _ = self.client.resolve_recipient(to)
        return self.client.send_multi(target, text, subject=subject)

    # ── seen store ────────────────────────────────────────────────────────────
    def _load_seen(self) -> list[str]:
        try:
            data = json.loads(self.seen_path.read_text())
            return list(data) if isinstance(data, list) else []
        except Exception:
            return []

    def _save_seen(self, seen_list: list[str]) -> None:
        try:
            self.seen_path.parent.mkdir(parents=True, exist_ok=True)
            self.seen_path.write_text(json.dumps(seen_list[-self.SEEN_CAP:]))
        except Exception as e:
            _log(self.name, f"WARN could not persist seen store: {e}")

    @staticmethod
    def _created_at(m: dict) -> int:
        try:
            return int(m.get("created_at") or 0)
        except (TypeError, ValueError):
            return 0

    # ── main loop ──────────────────────────────────────────────────────────────
    def run(self) -> int:
        ident = load_or_create_identity(self.identity_path)
        self.client = XeteClient(base_url=self.server_url, identity=ident)
        self.agent_id = self.client.login()
        self.client.register_encryption_key()  # publishes the UNIFIED x25519 key
        _log(self.name, f"online as agent_id={self.agent_id} pubkey={ident.pubkey_b58} server={self.server_url}")
        _log(self.name, f"handler={self.name}; polling every {self.poll_seconds}s")

        seen_list = self._load_seen()
        seen = set(seen_list)

        def mark(mid: str) -> None:
            if mid not in seen:
                seen.add(mid)
                seen_list.append(mid)

        while True:
            try:
                msgs = sorted(self.client.inbox(limit=self.inbox_limit), key=self._created_at)
                dirty = False
                for m in msgs:
                    mid = m.get("id")
                    mid = str(mid) if mid is not None else None
                    sender = m.get("from")
                    text = m.get("text")
                    if not mid or mid in seen:
                        continue
                    dirty = True
                    # never reply to: no id/sender, our own messages, or our own prior reply
                    if (not sender or sender == self.agent_id
                            or (self.reply_marker and text and text.startswith(self.reply_marker))):
                        mark(mid)
                        continue
                    ok, why = self.limiter.check_and_record(sender, time.time())
                    if not ok:
                        _log(self.name, f"rate-limited ({why}) sender={sender[:8]}; dropped {mid}")
                        mark(mid)
                        continue
                    try:
                        reply = self.handler.handle(sender, text)
                    except Exception as e:
                        _log(self.name, f"handler error for {sender[:8]}: {e}")
                        reply = None
                    if reply:
                        try:
                            self.send(sender, reply, subject="xete")
                            _log(self.name, f"replied to {sender[:8]} (msg {mid})")
                        except Exception as e:
                            _log(self.name, f"send failed to {sender[:8]}: {e}")
                            dirty = False  # leave unseen so we retry next cycle
                            continue
                    mark(mid)
                # periodic handler chores (e.g. low-invite-pool alert)
                tick = getattr(self.handler, "tick", None)
                if callable(tick):
                    try:
                        tick(self)
                    except Exception as e:
                        _log(self.name, f"tick error: {e}")
                if dirty:
                    self.limiter.prune()
                    self._save_seen(seen_list)
            except Exception as e:
                _log(self.name, f"WARN cycle error: {e}")
            time.sleep(self.poll_seconds)
