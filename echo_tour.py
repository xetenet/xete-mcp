#!/usr/bin/env python3
"""echo_tour - the xete welcome-tour concierge engine.

Turns the echo bot from a dumb reflector into a stateful concierge that guides a
brand-new user through onboarding and rewards them with invite codes at the end.
The growth loop: finish setup -> earn invites -> bring others in (xete is
invite-gated, not an open waitlist). Design: memory [[mobile-auth-onboarding-design]].

This module is PURE LOGIC + small JSON files - no network, no model - so it is
fully unit-testable and cheap. echo_agent.py calls `advance()` for each inbound
message and sends back whatever text it returns; it also calls `check_low_pool()`
once per poll to know when to ping lead about a draining invite pool.

Tour (light, agent-led, reply-driven - every reply is itself a real E2E round trip):
  0 WELCOME   first contact: confirm the round trip + offer the tour
  1 AREAS     broad strokes of what xete is (not details)
  2 WORDS     the 3-word app pass (set it; back it up - no recovery)
  3 PLATFORM  ask phone-or-computer so the install step fits (auto-detect if a
              signal is available; else ask once, then default to the mobile path)
  4 PWA_MOBILE  mobile only: firm, guided add-to-home-screen step
  5 COMPLETE  congratulate + ISSUE invite codes (the reward)
              (DESKTOP skips PWA_MOBILE: a one-line optional mention that
               auto-advances straight to COMPLETE - desktop users live in House Elf.)

State (per sender agent_id) persists to a JSON file so it survives restarts and is
idempotent: re-entering COMPLETE re-sends the SAME already-issued codes, never new
ones. Invite codes are REAL admin-minted codes drawn from a pre-minted pool file
(echo is not admin and cannot mint - John mints a batch via the relay admin endpoint
and feeds this pool); a failed/empty pool degrades gracefully without breaking the
tour, and a draining pool raises a one-shot low alert (see check_low_pool).

Files (override via env):
  XETE_ECHO_TOUR_STATE  per-user tour progress   (default ~/.xete/echo-tour-state.json)
  XETE_ECHO_INVITE_POOL pre-minted code pool      (default ~/.xete/echo-invite-pool.json)
  XETE_ECHO_TOUR_CODES  codes granted per finish  (default 3)
  XETE_ECHO_POOL_LOW    low-pool alert threshold  (default 10)
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

STATE_PATH = Path(os.environ.get("XETE_ECHO_TOUR_STATE", str(Path.home() / ".xete" / "echo-tour-state.json")))
POOL_PATH = Path(os.environ.get("XETE_ECHO_INVITE_POOL", str(Path.home() / ".xete" / "echo-invite-pool.json")))
CODES_PER_FINISH = int(os.environ.get("XETE_ECHO_TOUR_CODES", "3"))
POOL_LOW_THRESHOLD = int(os.environ.get("XETE_ECHO_POOL_LOW", "10"))

# Words that mean "move me forward" - tolerant, case/punctuation-insensitive.
_ADVANCE = {
    "next", "ready", "yes", "y", "ok", "okay", "k", "continue", "go", "start",
    "done", "yep", "yeah", "sure", "begin", "tour",
}
# Words that re-send the current step (user is lost / wants it again).
_REPEAT = {"help", "repeat", "again", "what", "huh", "?", "back"}
# Platform signals for the install step (substring match on the raw reply).
_MOBILE_KW = ("phone", "mobile", "ios", "iphone", "android", "cell", "smartphone", "tablet", "ipad")
_DESKTOP_KW = ("computer", "desktop", "laptop", "pc", "mac", "windows", "linux")

# step indices (persisted as integers)
WELCOME_I, AREAS_I, WORDS_I, PLATFORM_I, PWA_MOBILE_I, COMPLETE_I = 0, 1, 2, 3, 4, 5

# ---- step content -----------------------------------------------------------
# Plain, confident, no emoji (brand rules). Short on purpose. No internals.

WELCOME = (
    "That was a real end-to-end-encrypted round trip on xete (x25519 + AES-256-GCM). "
    "The server only ever saw ciphertext - it could not read this. You're live.\n\n"
    "I'm echo, your concierge. xete is sovereign, end-to-end-encrypted messaging and "
    "settlement for agents and people - and your own agent handles the hard parts for you.\n\n"
    "Want the 2-minute tour? It ends with your invite codes. Reply NEXT to start "
    "(or just keep messaging me - every reply is another encrypted round trip)."
)

AREAS = (
    "Here's the whole map - broad strokes, no homework:\n\n"
    "- MESSAGING: end-to-end encrypted DMs; the relay only ever holds ciphertext.\n"
    "- ALIASES: claim a %name so people reach you without a wallet address.\n"
    "- PAYMENTS & TIPS: attach value to a message; pay-to-reply spam gates.\n"
    "- SWAP: atomic token-for-token trades, on-chain.\n"
    "- SETTLEMENT (\"the tab\"): confidential escrow that settles on a public record.\n"
    "- DESKTOP VAULT: the House Elf app keeps your keys and files encrypted at rest.\n"
    "- TXN TOOL: signed-transaction messages - COMING SOON.\n\n"
    "That's what exists. Reply NEXT and we'll lock in your account."
)

WORDS = (
    "Your keys, your account - we hold nothing and cannot recover anything for you.\n\n"
    "So you get a private pass: THREE RANDOM WORDS the app generates. They unlock xete "
    "on your devices (a separate pass, not your phone's face/fingerprint - so it protects "
    "you even if someone has your unlocked phone).\n\n"
    "In the app: generate your 3 words, then WRITE THEM DOWN somewhere safe. Lose them and "
    "the account is gone for good - by design, no workaround on our end.\n\n"
    "Reply NEXT once you've saved your words."
)

PLATFORM_ASK = (
    "Quick one so I tailor the last step: are you setting up on a PHONE or a COMPUTER?\n\n"
    "Reply \"phone\" or \"computer\"."
)
PLATFORM_REASK = (
    "No rush - just reply \"phone\" or \"computer\" and I'll finish you up."
)

PWA_MOBILE = (
    "Last step - put xete on your home screen (this is the point on mobile: a persistent "
    "token and no re-login):\n\n"
    "- Open xete in your phone's browser and choose \"Add to Home Screen\" - it installs "
    "like an app and you'll get message alerts (toggle them off anytime).\n"
    "- It pairs to this account with your 3 words; no re-login each time.\n\n"
    "The fact that you've been reading my messages means decryption already works on your "
    "device - that's the whole proof. Reply NEXT to finish and claim your invites."
)

DESKTOP_MENTION = (
    "On a computer you're already set - the House Elf desktop app is your home base here. "
    "(You can add xete to a phone's home screen later, totally optional.)"
)

COMPLETE_HEADER = (
    "You're fully set up. Welcome to xete.\n\n"
    "xete is invite-only, and finishing onboarding is how you earn the right to bring others in. "
)
COMPLETE_WITH_CODES = (
    COMPLETE_HEADER + "Here are your invite codes - each works once, share them with people you trust:\n\n{codes}\n\n"
    "Send anyone you like a message here anytime. You're done - go build."
)
COMPLETE_NO_CODES = (
    COMPLETE_HEADER + "Your invite codes are being minted and will arrive here shortly - message me "
    "\"codes\" anytime to check. You're done - go build."
)


# message used when the user says something off-script mid-tour
def _nudge(echo_back: Optional[str]) -> str:
    tail = "Reply NEXT to keep going, or 'help' to see this step again."
    if echo_back and echo_back.strip():
        snippet = echo_back.strip()
        if len(snippet) > 200:
            snippet = snippet[:200] + " ..."
        return f"echo: {snippet}\n\n(Encrypted round trip - still working.) {tail}"
    return tail


def _step_message(step: int) -> str:
    return {
        WELCOME_I: WELCOME, AREAS_I: AREAS, WORDS_I: WORDS,
        PLATFORM_I: PLATFORM_ASK, PWA_MOBILE_I: PWA_MOBILE,
    }.get(step, WELCOME)


# ---- persistence ------------------------------------------------------------
def _load_state() -> dict:
    try:
        d = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=0), encoding="utf-8")
        tmp.replace(STATE_PATH)
    except Exception:
        pass


def _norm(text: Optional[str]) -> str:
    if not text:
        return ""
    return text.strip().lower().strip(".!,? ")


def _parse_platform(text: Optional[str]) -> Optional[str]:
    """'mobile' | 'desktop' | None from a free-text reply. Ambiguous (both or
    neither) -> None so the caller re-asks."""
    t = (text or "").lower()
    has_m = any(k in t for k in _MOBILE_KW)
    has_d = any(k in t for k in _DESKTOP_KW)
    if has_d and not has_m:
        return "desktop"
    if has_m and not has_d:
        return "mobile"
    return None


# ---- invite pool ------------------------------------------------------------
def _read_pool() -> Optional[dict]:
    """Return the pool dict ({'codes':[...], ...}) or None if no pool file/parse
    error. A missing file = pool not configured yet (no alert); an empty list = a
    configured-but-drained pool (alert-worthy)."""
    try:
        raw = json.loads(POOL_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None
    if isinstance(raw, list):
        return {"codes": raw}
    if isinstance(raw, dict):
        if not isinstance(raw.get("codes"), list):
            raw["codes"] = []
        return raw
    return None


def _write_pool(pool: dict) -> None:
    tmp = POOL_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(pool, indent=0), encoding="utf-8")
    tmp.replace(POOL_PATH)


def _pop_codes(n: int) -> list[str]:
    """Atomically remove up to n codes from the pool file and return them.
    Preserves any other keys in the pool dict (e.g. low_alerted). [] if none."""
    pool = _read_pool()
    if not pool or not pool["codes"]:
        return []
    codes = pool["codes"]
    taken = [str(c) for c in codes[:n]]
    pool["codes"] = codes[len(taken):]
    try:
        _write_pool(pool)
    except Exception:
        return []
    return taken


def check_low_pool() -> Optional[int]:
    """Once-per-low-state pool watchdog (echo_agent calls this each poll).

    Returns the remaining code count (int) exactly ONCE when a CONFIGURED pool
    first drops below POOL_LOW_THRESHOLD, so echo can ping lead a single time per
    low episode. Returns None otherwise. Auto-resets when the pool is topped back
    up to/above the threshold, so a later drain alerts again. A missing pool file
    (not yet seeded) never alerts.
    """
    pool = _read_pool()
    if pool is None:
        return None
    remaining = len(pool["codes"])
    alerted = bool(pool.get("low_alerted", False))
    if remaining < POOL_LOW_THRESHOLD and not alerted:
        pool["low_alerted"] = True
        try:
            _write_pool(pool)
        except Exception:
            return None
        return remaining
    if remaining >= POOL_LOW_THRESHOLD and alerted:
        pool["low_alerted"] = False
        try:
            _write_pool(pool)
        except Exception:
            pass
    return None


# ---- the engine -------------------------------------------------------------
def _finish(rec: dict, desktop: bool) -> str:
    """Move rec to COMPLETE, issue codes once, and render the closing message."""
    codes = _pop_codes(CODES_PER_FINISH)
    rec["codes"] = codes
    rec["step"] = COMPLETE_I
    body = COMPLETE_WITH_CODES.format(codes="\n".join(codes)) if codes else COMPLETE_NO_CODES
    return (DESKTOP_MENTION + "\n\n" + body) if desktop else body


def advance(sender: str, text: Optional[str], now: Optional[float] = None,
            platform: Optional[str] = None) -> str:
    """Process one inbound message from `sender`; return the reply text.

    `platform` ('mobile'|'desktop') is an OPTIONAL auto-detected hint (e.g. from a
    relay device-class signal). When absent, the PLATFORM step asks once and falls
    back to the mobile path. Pure w.r.t. the network - echo_agent.py sends the result.
    """
    if now is None:
        now = time.time()
    state = _load_state()
    rec = state.get(sender)
    word = _norm(text)

    # ---- first contact: start the tour at WELCOME ----
    if rec is None:
        state[sender] = {"step": WELCOME_I, "started_at": now, "updated_at": now, "codes": []}
        _save_state(state)
        return WELCOME

    step = int(rec.get("step", WELCOME_I))
    rec["updated_at"] = now
    hint = platform or rec.get("platform")

    # ---- already finished: re-engagement (idempotent codes) ----
    if step >= COMPLETE_I:
        if word in ("codes", "code", "invite", "invites") and not rec.get("codes"):
            codes = _pop_codes(CODES_PER_FINISH)
            if codes:
                rec["codes"] = codes
                state[sender] = rec
                _save_state(state)
                return COMPLETE_WITH_CODES.format(codes="\n".join(codes))
            return COMPLETE_NO_CODES
        if rec.get("codes"):
            return COMPLETE_WITH_CODES.format(codes="\n".join(rec["codes"]))
        return COMPLETE_NO_CODES

    # ---- help / repeat current step ----
    if word in _REPEAT:
        _save_state(state)
        return _step_message(step)

    # ---- PLATFORM step: decide phone vs computer ----
    if step == PLATFORM_I:
        choice = platform or _parse_platform(text)
        if choice == "desktop":
            rec["platform"] = "desktop"
            body = _finish(rec, desktop=True)      # one-line mention + auto-advance to COMPLETE
            state[sender] = rec
            _save_state(state)
            return body
        if choice == "mobile":
            rec["platform"] = "mobile"
            rec["step"] = PWA_MOBILE_I
            state[sender] = rec
            _save_state(state)
            return PWA_MOBILE
        # ambiguous: ask once more, then default to the (non-blocking) mobile path
        asks = int(rec.get("platform_asks", 0))
        if asks < 1:
            rec["platform_asks"] = asks + 1
            state[sender] = rec
            _save_state(state)
            return PLATFORM_REASK
        rec["platform"] = "mobile"
        rec["step"] = PWA_MOBILE_I
        state[sender] = rec
        _save_state(state)
        return PWA_MOBILE

    # ---- advance on an affirmative keyword ----
    if word in _ADVANCE:
        if step == WORDS_I:
            # entering the install decision: auto-branch if we already know platform
            if hint == "desktop":
                rec["platform"] = "desktop"
                body = _finish(rec, desktop=True)
                state[sender] = rec
                _save_state(state)
                return body
            if hint == "mobile":
                rec["platform"] = "mobile"
                rec["step"] = PWA_MOBILE_I
                state[sender] = rec
                _save_state(state)
                return PWA_MOBILE
            rec["step"] = PLATFORM_I
            state[sender] = rec
            _save_state(state)
            return PLATFORM_ASK
        if step == PWA_MOBILE_I:
            body = _finish(rec, desktop=False)
            state[sender] = rec
            _save_state(state)
            return body
        # WELCOME -> AREAS -> WORDS
        nxt = step + 1
        rec["step"] = nxt
        state[sender] = rec
        _save_state(state)
        return _step_message(nxt)

    # ---- off-script mid-tour: gentle nudge, keep the round trip ----
    _save_state(state)
    return _nudge(text)


if __name__ == "__main__":  # tiny manual REPL for eyeballing the flow
    import sys
    who = sys.argv[1] if len(sys.argv) > 1 else "demo-user"
    print("(type messages as the user; Ctrl-C to quit)\n")
    print("echo>", advance(who, None))
    try:
        while True:
            line = input("you> ")
            print("echo>", advance(who, line), "\n")
    except (KeyboardInterrupt, EOFError):
        print("\nbye")
