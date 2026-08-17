"""Guided-workflow text for xete-mcp's MCP prompts.

SPEC-mcp-prompts-resources-20260817. Each function returns plain text sequencing the
existing @mcp.tool() functions in server.py — it never calls a tool itself, signs
anything, or submits anything on-chain. server.py registers these as @mcp.prompt()
wrappers; the functions here are kept tool-free and pure so they're testable without
FastMCP or network access.
"""
from __future__ import annotations


def send_encrypted_message(recipient_agent_id: str = "", message: str = "") -> str:
    """Guide for the identity + messaging workflow."""
    who = recipient_agent_id or "<recipient_agent_id>"
    what = message or "<your message>"
    return (
        "To send an end-to-end-encrypted xete message:\n"
        "1. Call xete_my_identity to confirm your own agent id and check spend_limits "
        "(sending costs a small amount against your window).\n"
        f"2. Call xete_lookup_agent(\"{who}\") to confirm the recipient exists and has "
        "published an encryption key.\n"
        f"3. Call xete_send_message(recipient_agent_id=\"{who}\", message=\"{what}\") — "
        "the message is encrypted in-process; the server only ever sees ciphertext.\n"
        "4. Later, call xete_check_inbox to read and decrypt any reply."
    )


def claim_a_name(name: str = "", max_price_lamports: int | None = None) -> str:
    """Guide for claiming a %name."""
    n = name or "<%name>"
    ceiling = (f"max_price_lamports={max_price_lamports}" if max_price_lamports is not None
               else "a max_price_lamports ceiling you choose")
    return (
        f"To claim {n} as this agent's human-readable identity:\n"
        f"1. Call xete_alias_quote(\"{n}\") to get the itemized, provable price "
        "(floor + land_rush + your_rush).\n"
        f"2. Decide {ceiling} — the claim refuses to pay more than this, so quote first.\n"
        f"3. Call xete_alias_claim(\"{n}\", {'max_price_lamports=' + str(max_price_lamports) if max_price_lamports is not None else 'max_price_lamports=<your ceiling>'}) "
        "to run the full claim flow (challenge, sign, submit).\n"
        f"4. Call xete_alias_resolve(\"{n}\") afterward to confirm on-chain ownership — "
        "this reads the Solana registry directly, not the permit server's word."
    )


def settle_a_payment(recipient: str = "", amount_sol: float | None = None,
                      human_supervised: bool = True) -> str:
    """Guide for paying another agent, split by who is authorizing the spend."""
    who = recipient or "<recipient wallet, %alias, or .sol name>"
    amt = f"{amount_sol}" if amount_sol is not None else "<amount_sol>"
    if human_supervised:
        return (
            f"To pay {who} {amt} SOL with a HUMAN signing (recommended for anything the "
            "agent itself decided the amount or recipient of):\n"
            f"1. Call xete_draft_settlement_tx(recipient=\"{who}\", amount_sol={amt}) — "
            "this returns an UNSIGNED transaction. It holds no key and cannot move funds.\n"
            "2. Hand the unsigned transaction to the human, along with the recipient "
            "*they* expect (not the draft's own output).\n"
            f"3. Call xete_verify_settlement_tx(unsigned_tx_b64=<from step 1>, "
            f"expect_recipient=<the human's own expectation, out of band>, amount_sol={amt}, "
            "salt=<from step 1>) — verified: false means do not sign.\n"
            "4. Only if verified: true, the human signs it in their own wallet."
        )
    return (
        f"To pay {who} {amt} SOL directly, within this agent's own configured spend "
        "limits (no separate human signature):\n"
        "1. Call xete_my_identity and check spend_limits.window_remaining_lamports "
        "covers this payment.\n"
        f"2. Call xete_settle_create(recipient=\"{who}\", amount_sol={amt}) — funds lock "
        "in a non-custodial on-chain account with the beneficiary hidden until claimed.\n"
        "3. The recipient claims with xete_settle_claim using the escrow_id + salt you "
        "were given (send it to their inbox with xete_send_message, or hand it over).\n"
        "4. If they never claim, you can call xete_settle_reclaim(escrow_id) to get the "
        "funds and rent back."
    )


def resolve_identity(identifier: str = "") -> str:
    """Guide for resolving a wallet, %alias, or .sol name to one identity view."""
    who = identifier or "<wallet address, %alias, or .sol name>"
    return (
        f"To resolve {who} to a single identity view:\n"
        f"1. Call xete_resolve(\"{who}\") — returns the wallet it points to, the best "
        "%name for it, and whether the wallet also holds the matching .sol name.\n"
        "2. If you need chain-verified (not server-claimed) ownership specifically, call "
        "xete_alias_resolve for a %name → wallet lookup, or xete_alias_reverse for a "
        "wallet → best %name lookup — both read the Solana registry directly."
    )
