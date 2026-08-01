#!/usr/bin/env python3
"""Wake-on-message — the push primitive for the agent fleet.

A polling LOOP never wakes a Claude Code agent; the harness only wakes an agent when a
background task COMPLETES. So this script blocks until either:
  - a NEW xete message arrives  -> prints it and EXITS 0 (the agent is woken to handle it), or
  - --timeout / XETE_WAKE_TIMEOUT_S elapses with nothing -> EXITS 0 with a RE-ARM marker
    (so the loop refreshes its token/state and the session doesn't sit on a stale wait).

THE CONTRACT (every agent, including the lead):
  Run this in the BACKGROUND. When it exits, the harness wakes you. Read its output:
    * "=== NEW from ... ===" -> act on the message (reply / do the task), THEN re-arm.
    * "RE-ARM" (timeout)     -> just re-arm.
  RE-ARM = launch this script again in the background. That single discipline makes a
  message from any agent WAKE its recipient — including workers waking the lead on
  completion, and the lead waking a worker with the next assignment.

  Run:  XETE_IDENTITY=~/.xete/<you>-identity.json XETE_AGENT_NAME=<you> python wait_for_message.py
"""
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))  # use the repo's client (sig-derived keys)
from xete_mcp.client import XeteClient, load_or_create_identity

IDENTITY = Path(os.environ.get("XETE_IDENTITY", str(Path.home() / ".xete" / "CHANGE-ME-identity.json")))
SERVER = os.environ.get("XETE_SERVER_URL", "https://xete.net")
MY_NAME = os.environ.get("XETE_AGENT_NAME", "worker")
POLL_S = int(os.environ.get("XETE_POLL_S", "15"))
TIMEOUT_S = int(os.environ.get("XETE_WAKE_TIMEOUT_S", "1500"))  # 25m re-arm cadence

c = XeteClient(base_url=SERVER, identity=load_or_create_identity(IDENTITY))
c.login()
seen = {m.get("id") for m in c.inbox(limit=50)}
print(f"wait-for-message armed: {MY_NAME} ({c.identity.agent_id}); wakes on new msg, re-arms after {TIMEOUT_S // 60}m", flush=True)
start = time.time()

while True:
    time.sleep(POLL_S)
    try:
        msgs = c.inbox(limit=50)
    except Exception as e:
        print("poll error:", str(e)[:120], flush=True)
        try:
            c.token = ""
            c.login()
        except Exception:
            pass
        continue
    new = [m for m in msgs if m.get("id") not in seen]
    if new:
        print(f"WAKE: {len(new)} new message(s) for {MY_NAME}", flush=True)
        for m in new:
            body = m.get("text") if m.get("text") is not None else f"[undecryptable: {m.get('decrypt_error')}]"
            print(f"\n=== NEW from {m.get('from_alias') or m.get('from')} ===\n{body}\n", flush=True)
        print(">> handle these, then RE-ARM: relaunch wait_for_message.py in the background.", flush=True)
        sys.exit(0)
    if time.time() - start > TIMEOUT_S:
        print("RE-ARM: no new messages this window; relaunch wait_for_message.py in the background.", flush=True)
        sys.exit(0)
