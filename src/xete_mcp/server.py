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

import requests
from mcp.server.fastmcp import FastMCP

from .client import XeteClient, load_or_create_identity
from . import payment

SERVER_URL = os.environ.get("XETE_SERVER_URL", "https://xete.net")
RPC_URL = os.environ.get("XETE_RPC_URL", "https://api.mainnet-beta.solana.com")
IDENTITY_PATH = Path(os.environ.get("XETE_IDENTITY", str(Path.home() / ".xete" / "identity.json")))
SOL_KEYPAIR_PATH = os.environ.get("XETE_SOL_KEYPAIR", "")
# The %alias permit server. Separate service from the messaging relay, though in prod it may be
# proxied under the same host — so it defaults to SERVER_URL and is overridable.
PERMIT_URL = os.environ.get("XETE_PERMIT_URL", SERVER_URL)

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


# ── %alias registry tools ────────────────────────────────────────────────────
# Names that resolve to a wallet (%alex). quote/resolve/reverse are read-only (no signing,
# no cost). claim runs the full on-chain flow and is paid by THIS agent's identity wallet.

def _permit_url(path: str) -> str:
    return f"{PERMIT_URL.rstrip('/')}{path}"


@mcp.tool()
def xete_alias_quote(name: str, wallet: str = "") -> str:
    """Get the one-time price to claim a xete %name, itemized and provable. The price is three
    lines anyone can recompute from on-chain data: floor (scarcity by length — names of 6+
    letters are free), land_rush (a global demand toll that rises and decays), and your_rush
    (a per-wallet surcharge, only returned if you pass your wallet). Lamports; 1 SOL = 1e9
    lamports. Read-only — costs nothing to ask. Call this before xete_alias_claim."""
    try:
        params = {"name": name}
        if wallet:
            params["wallet"] = wallet
        r = requests.get(_permit_url("/alias/quote"), params=params, timeout=15)
        return json.dumps(r.json(), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)[:300]})


@mcp.tool()
def xete_alias_resolve(name: str) -> str:
    """Resolve a xete %name: its on-chain owner, whether a matching .sol exists, and whether the
    SAME wallet holds both (owns_both — the verified-identity condition). Use it to confirm a
    name points where you expect before you trust or pay it. Read-only."""
    try:
        r = requests.get(_permit_url("/alias/resolve"), params={"name": name}, timeout=15)
        return json.dumps(r.json(), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)[:300]})


@mcp.tool()
def xete_alias_reverse(wallet: str) -> str:
    """Reverse-resolve a wallet to its best xete %name — the identity to show for a raw address —
    plus whether it also holds the matching .sol. Returns name:null when the wallet holds no
    name (callers then fall back to the truncated address). Read-only."""
    try:
        r = requests.get(_permit_url("/alias/reverse"), params={"wallet": wallet}, timeout=15)
        return json.dumps(r.json(), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)[:300]})


@mcp.tool()
def xete_alias_claim(name: str) -> str:
    """Claim a xete %name for THIS agent — its identity wallet (see xete_my_identity →
    wallet_pubkey) becomes the owner. Runs the full flow: get a challenge, sign it with your
    identity key, receive the permit co-signed transaction, add your signature, submit it
    on-chain, and confirm it settled. Your identity wallet is the fee payer, so it must hold a
    little SOL — it pays the one-time price (0 for ordinary 6+ letter names, or in grace) plus a
    small network rent + gas. Check the price first with xete_alias_quote. Returns the price
    paid, the tx signature, and the settlement status. You must already have a xete identity
    registered (claiming binds the name to your agent)."""
    # Load the identity directly: claim depends on the permit server + its relay DB, NOT on the
    # messaging relay being reachable — so don't force a messaging-server login here.
    ident = load_or_create_identity(IDENTITY_PATH)
    pubkey = ident.pubkey_b58
    try:
        import base64 as _b64
        import base58

        ch = requests.post(_permit_url("/alias/claim/challenge"), json={"pubkey": pubkey}, timeout=15).json()
        if "message" not in ch or "nonce" not in ch:
            return json.dumps({"status": "failed", "stage": "challenge", "detail": ch})
        # sign the challenge with the identity ed25519 key. NOTE: the permit server verifies sigs as
        # BASE58 (bs58::decode in auth.rs) — unlike the messaging relay, which uses base64. Different
        # services, different convention; send base58 here.
        sig = base58.b58encode(ident.signing_key.sign(ch["message"].encode("utf-8")).signature).decode()
        claim = requests.post(
            _permit_url("/alias/claim"),
            json={"pubkey": pubkey, "nonce": ch["nonce"], "signature": sig, "name": name},
            timeout=20,
        ).json()
        if claim.get("status") != "approved":
            reason = claim.get("reason") or claim.get("error")
            hint = ("register a xete identity first (send a message, or call xete_my_identity), then claim"
                    if reason == "no_agent_for_wallet" else None)
            return json.dumps(
                {"status": claim.get("status", "denied"), "reason": reason, "hint": hint, "name": name},
                indent=2,
            )
        # add our claimer signature (we are the fee payer) and submit on-chain
        from solders.keypair import Keypair
        from solders.transaction import Transaction
        from solana.rpc.api import Client

        claimer = Keypair.from_seed(ident.ed_seed)
        tx = Transaction.from_bytes(_b64.b64decode(claim["transaction"]))
        tx.partial_sign([claimer], tx.message.recent_blockhash)
        rpc = Client(RPC_URL)
        onchain = rpc.send_raw_transaction(bytes(tx)).value
        # wait for settlement, then ask the permit server to verify the on-chain owner
        import time as _t
        for _ in range(30):
            _t.sleep(0.5)
            st = rpc.get_signature_statuses([onchain]).value[0]
            if st and st.confirmation_status:
                break
        conf = requests.post(_permit_url("/alias/claim/confirm"),
                             json={"pubkey": pubkey, "name": name}, timeout=20).json()
        return json.dumps({
            "status": "claimed" if conf.get("status") == "confirmed" else conf.get("status", "submitted"),
            "name": name,
            "owner": pubkey,
            "price_lamports": claim.get("price_lamports"),
            "free_grace": claim.get("free_grace"),
            "tx_signature": str(onchain),
            "settled": conf.get("status"),
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "failed", "error": str(e)[:300]})


def main():
    mcp.run()


if __name__ == "__main__":
    main()
