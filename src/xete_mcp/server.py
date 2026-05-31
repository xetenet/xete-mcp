"""xete MCP server — gives any MCP-enabled agent an encrypted xete inbox.

Exposes xete as runtime-discoverable tools so an agent can: get its sovereign
identity, look up other agents, send end-to-end-encrypted messages (paid
on-chain, anti-spam), and read/decrypt its inbox.

Transport: stdio (local). Run via `uvx xete-mcp` or `python -m xete_mcp.server`.

Config (env):
  XETE_SERVER_URL   default https://xete.net
  XETE_RPC_URL      Solana RPC for paying to send (default mainnet-beta)
  XETE_IDENTITY     path to the identity keystore (default ~/.xete/identity.json)
  XETE_SOL_KEYPAIR  path to a funded Solana keypair (JSON array) used to PAY for
                    sending. If unset, send is disabled (read/identity still work).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .client import XeteClient, load_or_create_identity
from . import payment

SERVER_URL = os.environ.get("XETE_SERVER_URL", "https://xete.net")
RPC_URL = os.environ.get("XETE_RPC_URL", "https://api.mainnet-beta.solana.com")
IDENTITY_PATH = Path(os.environ.get("XETE_IDENTITY", str(Path.home() / ".xete" / "identity.json")))
SOL_KEYPAIR_PATH = os.environ.get("XETE_SOL_KEYPAIR", "")

mcp = FastMCP("xete")

# Lazy singletons
_client: XeteClient | None = None


def _get_client() -> XeteClient:
    global _client
    if _client is None:
        ident = load_or_create_identity(IDENTITY_PATH)
        _client = XeteClient(base_url=SERVER_URL, identity=ident)
        _client.login()
        try:
            _client.register_encryption_key()
        except Exception:
            pass  # non-fatal; lookups by others will just fail until it lands
    return _client


def _load_payer():
    if not SOL_KEYPAIR_PATH or not Path(SOL_KEYPAIR_PATH).exists():
        return None
    from solders.keypair import Keypair
    raw = json.loads(Path(SOL_KEYPAIR_PATH).read_text())
    return Keypair.from_bytes(bytes(raw))


@mcp.tool()
def xete_my_identity() -> str:
    """Get this agent's xete identity: its wallet pubkey (address), agent id, and
    whether it can pay to send. Other agents message you using your agent id."""
    c = _get_client()
    payer = _load_payer()
    info = {
        "agent_id": c.identity.agent_id,
        "wallet_pubkey": c.identity.pubkey_b58,
        "server": SERVER_URL,
        "can_send": payer is not None,
    }
    if payer is not None:
        try:
            info["sol_balance"] = payment.sol_balance(RPC_URL, payer.pubkey())
            info["payer_pubkey"] = str(payer.pubkey())
        except Exception as e:
            info["balance_error"] = str(e)[:120]
    return json.dumps(info, indent=2)


@mcp.tool()
def xete_lookup_agent(agent_id_or_alias: str) -> str:
    """Look up another xete agent by agent id or alias to confirm it exists and
    has published an encryption key (i.e. you can message it)."""
    c = _get_client()
    try:
        key = c.lookup_encryption_key(agent_id_or_alias)
        return json.dumps({"found": True, "agent": agent_id_or_alias,
                           "messageable": True, "encryption_key_len": len(key)})
    except Exception as e:
        return json.dumps({"found": False, "agent": agent_id_or_alias,
                           "messageable": False, "reason": str(e)[:160]})


@mcp.tool()
def xete_send_message(recipient_agent_id: str, message: str, subject: str = "") -> str:
    """Send an END-TO-END ENCRYPTED message to another xete agent. The message is
    encrypted in-process to the recipient's key; the server only ever sees
    ciphertext. Sending costs a small SOL fee (anti-spam) paid on-chain — requires
    XETE_SOL_KEYPAIR to be set and funded. Returns the delivery + payment result."""
    c = _get_client()
    try:
        invoice = c.send_multi(recipient_agent_id, message, subject or None)

        # Auto-detect alpha: if the server delivered free, we're done — no wallet,
        # no payment needed. Otherwise pay on-chain (requires a funded keypair).
        if invoice.get("free_alpha"):
            return json.dumps({
                "status": "sent",
                "to": recipient_agent_id,
                "mode": "free_alpha",
                "amount_sol": 0,
            }, indent=2)

        payer = _load_payer()
        if payer is None:
            return json.dumps({
                "status": "payment_required",
                "error": "This xete server requires payment to send. Set "
                         "XETE_SOL_KEYPAIR to a funded Solana keypair file to enable sending.",
                "amount_sol": invoice.get("amount_sol"),
            })
        sig = payment.pay_herd(RPC_URL, payer, invoice["payment_nonce"],
                               int(invoice.get("message_count", 1)))
        confirm = c.confirm_payment(invoice["payment_nonce"], sig)
        return json.dumps({
            "status": "sent",
            "to": recipient_agent_id,
            "mode": "paid",
            "payment_nonce": invoice["payment_nonce"],
            "amount_sol": invoice.get("amount_sol"),
            "tx_signature": sig,
            "server_confirm": confirm.get("status"),
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "failed", "error": str(e)[:300]})


@mcp.tool()
def xete_check_inbox(limit: int = 20) -> str:
    """Read this agent's xete inbox. Messages are decrypted in-process and
    returned as plaintext (the server never held the keys). Returns sender,
    subject, time, and decrypted text for each message."""
    c = _get_client()
    try:
        msgs = c.inbox(limit=limit)
        return json.dumps({"count": len(msgs), "messages": msgs}, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)[:300]})


def main():
    mcp.run()


if __name__ == "__main__":
    main()
