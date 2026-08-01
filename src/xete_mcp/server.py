"""xete MCP server — gives any MCP-enabled agent an encrypted xete inbox.

Exposes xete as runtime-discoverable tools so an agent can: get its sovereign
identity, look up other agents, send end-to-end-encrypted messages, and
read/decrypt its inbox.

Transport: stdio (local). Run via `uvx xete-mcp` or `python -m xete_mcp.server`.

Config (env):
  XETE_SERVER_URL   default https://xete.net
  XETE_RPC_URL      Solana RPC, used only when a spend actually happens
                    (default mainnet-beta)
  XETE_IDENTITY     path to the identity keystore (default ~/.xete/identity.json)
  XETE_SOL_KEYPAIR  path to a funded Solana keypair (JSON array). Used to pay only on
                    a server that charges to send; messaging on xete.net is free, and
                    identity and inbox never need it.

Spend limits (env) — enforced on this side, before anything is signed, on every path
that can spend: xete_send_message, xete_alias_claim, xete_settle_create. There is no
"unlimited" setting and no off switch; an unset limit means a conservative default,
never no limit. Full reasoning in src/xete_mcp/spendguard.py.
  XETE_SPEND_MAX_LAMPORTS     most a single spend may cost      (default 10000000)
  XETE_SPEND_WINDOW_LAMPORTS  most spendable per window         (default 50000000)
  XETE_SPEND_WINDOW_SECONDS   rolling window length             (default 86400)
  XETE_SPEND_FLOOR_LAMPORTS   minimum charged per on-chain action, covering the rent
                              and fees a quote excludes         (default 2000000)
  XETE_SPEND_LEDGER           ledger path      (default ~/.xete/spend-ledger.json)
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import requests
from mcp.server.fastmcp import FastMCP

from .client import XeteClient, load_or_create_identity
from . import payment, settlement

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
    """Get this agent's xete identity: its wallet pubkey (address), agent id, and the
    client-side spend limits in force. Other agents message you using your agent id.

    `can_send` reports only whether a funded payer keypair is CONFIGURED. It is not a
    prerequisite for messaging on a server that does not charge to send (xete.net does
    not), so `can_send: false` does not mean you are unable to send.

    `spend_limits` is the ceiling this server enforces on itself before signing
    anything: the most one transaction may cost, the most that may be spent inside the
    rolling window, and how much of that window is left."""
    c = _get_client()
    payer = _load_payer()
    info = {
        "agent_id": c.identity.agent_id,
        "wallet_pubkey": c.identity.pubkey_b58,
        "server": SERVER_URL,
        "can_send": payer is not None,
    }
    try:
        from .spendguard import status as _spend_status

        info["spend_limits"] = _spend_status()
    except Exception as e:
        # Never let a reporting problem hide the identity; the limits themselves fail
        # closed at spend time regardless of what this read says.
        info["spend_limits"] = {"enforced": True, "error": str(e)[:200]}
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
    ciphertext. Messaging on xete.net is free. A funded XETE_SOL_KEYPAIR is only
    needed if the xete server you are connected to charges for sending; when it does,
    the charge is checked against this agent's spend limits before anything is signed
    (see xete_my_identity → spend_limits). Returns the delivery result."""
    c = _get_client()
    try:
        invoice = c.send_multi(recipient_agent_id, message, subject or None)

        # Whether a send is charged is a property of the server being talked to, not of
        # this client. `free_alpha` is that server's WIRE FIELD NAME, kept as-is for
        # compatibility; it is not user-facing wording. No invoice means nothing to pay.
        if invoice.get("free_alpha"):
            return json.dumps({
                "status": "sent",
                "to": recipient_agent_id,
                "mode": "free",
                "amount_sol": 0,
            }, indent=2)

        payer = _load_payer()
        if payer is None:
            return json.dumps({
                "status": "payment_required",
                "error": "This xete server charges to send. Set XETE_SOL_KEYPAIR to a "
                         "funded Solana keypair file to enable sending.",
                "amount_sol": invoice.get("amount_sol"),
            })
        # SPEND GATE: enforced inside payment.pay_herd, before a key is touched. The
        # server's quote is passed in only as a floor on what gets checked — pay_herd
        # independently derives a cost from the blob count that goes into the signed
        # instruction and gates on whichever figure is larger. An unparseable quote
        # therefore weakens nothing; the derived figure still applies.
        try:
            quoted_lamports = int(round(float(invoice.get("amount_sol") or 0) * 1_000_000_000))
        except (TypeError, ValueError):
            quoted_lamports = 0
        sig = payment.pay_herd(RPC_URL, payer, invoice["payment_nonce"],
                               int(invoice.get("message_count", 1)),
                               declared_lamports=quoted_lamports)
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
        # SPEND GATE — before our signature exists. Be clear about what this can see:
        # `price_lamports` is DECLARED by the permit server, and the transaction we are
        # about to sign was BUILT by that same server, so this bounds the price we were
        # quoted, not the lamports the transaction is able to move. The claim also costs
        # on-chain rent and gas that the quote excludes, which is what
        # XETE_SPEND_FLOOR_LAMPORTS covers. See reviews/DDR-spend-caps-20260731.md, D2.
        from .spendguard import authorize as _authorize_spend

        _authorize_spend(int(claim.get("price_lamports") or 0), "xete_alias_claim",
                         detail=f"name=%{name}")

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


# ── unified resolver ─────────────────────────────────────────────────────────────────
# One call to turn any xete identifier (wallet | %alias | .sol) into a single identity view.
# Pure addressing over the alias permit server — no messaging, no inbox, no decryption.

def _classify_identifier(identifier: str):
    """(kind, query) — kind in {handle, wallet, sol, alias}; query is the lookup key (a wallet
    pubkey, or a bare name with any %/.sol stripped). Pure, no I/O."""
    import base58

    r = identifier.strip()
    if r.startswith("@"):
        return "handle", r[1:]
    try:
        if len(base58.b58decode(r)) == 32:
            return "wallet", r
    except Exception:
        pass
    name = r.lstrip("%")
    if name.lower().endswith(".sol"):
        return "sol", name[:-4]
    return "alias", name


@mcp.tool()
def xete_resolve(identifier: str) -> str:
    """Resolve any xete identifier to one identity view. Pass a wallet address, a %alias, or a .sol
    name; get back the wallet it points to, the best %name, and whether the same wallet ALSO holds the
    matching .sol (the verified-identity / owns_both badge). Read-only addressing — it does not send,
    receive, or decrypt anything. (@handle is not yet supported.)"""
    kind, query = _classify_identifier(identifier)
    if kind == "handle":
        return json.dumps({"input": identifier, "kind": "handle", "supported": False,
                           "note": "@handle resolution is not yet available"}, indent=2)
    try:
        if kind == "wallet":
            rev = requests.get(_permit_url("/alias/reverse"), params={"wallet": query}, timeout=15).json()
            return json.dumps({"input": identifier, "kind": "wallet", "wallet": query,
                               "name": rev.get("name"), "owns_both": rev.get("owns_both", False),
                               "names_count": rev.get("names_count")}, indent=2)
        res = requests.get(_permit_url("/alias/resolve"), params={"name": query}, timeout=15).json()
        wallet = res.get("sol_owner") if kind == "sol" else res.get("alias_owner")
        return json.dumps({"input": identifier, "kind": kind, "name": query, "wallet": wallet,
                           "alias_owner": res.get("alias_owner"), "sol_owner": res.get("sol_owner"),
                           "owns_both": res.get("owns_both", False),
                           "sol_mismatch": res.get("sol_mismatch")}, indent=2)
    except Exception as e:
        return json.dumps({"input": identifier, "error": str(e)[:300]})


# ── confidential settlement tools (the "tab": agent->agent value transfer) ───────────
# Deposit funds for a recipient (hidden on-chain), notify them encrypted over xete, they claim.
# Non-custodial: only the depositor (reclaim) or beneficiary (claim) keys move funds. THIS agent's
# identity wallet is the depositor/claimant + fee payer, so it must hold SOL.

def _resolve_recipient_wallet(recipient: str):
    """(wallet Pubkey, messageable_handle | None). Accepts a base58 wallet pubkey directly, or a
    %alias / name resolved via the permit server to its on-chain owner wallet."""
    import base58
    from solders.pubkey import Pubkey

    r = recipient.strip()
    try:
        if len(base58.b58decode(r)) == 32:
            return Pubkey.from_string(r), None  # raw wallet; not messageable by itself
    except Exception:
        pass
    name = r.lstrip("%")
    resp = requests.get(_permit_url("/alias/resolve"), params={"name": name}, timeout=15).json()
    owner = resp.get("alias_owner")
    if not owner:
        raise RuntimeError(f"could not resolve recipient '{recipient}' to a wallet (no %{name} owner on-chain)")
    return Pubkey.from_string(owner), f"%{name}"


@mcp.tool()
def xete_settle_create(recipient: str, amount_sol: float, notify: bool = True) -> str:
    """Open a confidential SETTLEMENT (a "tab") that pays `recipient` `amount_sol` — agent-to-agent
    value transfer, not a message fee. Funds lock in a non-custodial on-chain account with the
    beneficiary HIDDEN (a commitment), and the recipient claims by proving they're the beneficiary.
    Recipient may be a wallet address or a %alias. Your identity wallet is the depositor + fee payer
    (must hold amount_sol + a little for rent/gas). If notify is true and the recipient is messageable,
    the claim ticket (escrow_id + salt) is sent to them END-TO-END ENCRYPTED over xete. ALWAYS returns
    the ticket so you can deliver it yourself too — the recipient needs escrow_id + salt to claim. You
    can xete_settle_reclaim it any time before they claim."""
    ident = load_or_create_identity(IDENTITY_PATH)
    try:
        from solders.keypair import Keypair

        recipient_wallet, handle = _resolve_recipient_wallet(recipient)
        depositor = Keypair.from_seed(ident.ed_seed)
        lamports = int(round(amount_sol * 1_000_000_000))
        if lamports <= 0:
            return json.dumps({"status": "failed", "error": "amount_sol must be > 0"})
        eid_hex, salt_hex, pda, sig = settlement.deposit(RPC_URL, depositor, recipient_wallet, lamports)
        ticket = {"escrow_id": eid_hex, "salt": salt_hex, "amount_sol": amount_sol,
                  "program": str(settlement.program_id()), "claim_with": "xete_settle_claim"}
        notified = None
        if notify and handle:
            try:
                c = _get_client()
                msg = ("You've received a xete settlement of "
                       f"{amount_sol} SOL. Claim it with xete_settle_claim:\n"
                       f"escrow_id: {eid_hex}\nsalt: {salt_hex}")
                c.send_multi(handle, msg, "xete settlement")
                notified = handle
            except Exception as e:
                notified = f"send failed: {str(e)[:120]}"
        return json.dumps({
            "status": "open", "to": recipient, "recipient_wallet": str(recipient_wallet),
            "amount_sol": amount_sol, "pda": pda, "deposit_sig": sig,
            "ticket": ticket, "notified": notified,
            "note": "give the recipient escrow_id + salt to claim; reclaimable until then",
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "failed", "error": str(e)[:300]})


@mcp.tool()
def xete_settle_claim(escrow_id: str, salt: str) -> str:
    """Claim a confidential settlement addressed to you — using the escrow_id + salt from the claim
    ticket (sent to your inbox, or handed to you). Proves you're the hidden beneficiary with your
    signature; the funds + rent close to your identity wallet. Returns the tx and the amount received."""
    ident = load_or_create_identity(IDENTITY_PATH)
    try:
        from solders.keypair import Keypair

        beneficiary = Keypair.from_seed(ident.ed_seed)
        sig, received = settlement.claim(RPC_URL, beneficiary, escrow_id, salt)
        return json.dumps({"status": "claimed", "escrow_id": escrow_id, "tx_signature": sig,
                           "received_sol": received / 1e9, "to": ident.pubkey_b58}, indent=2)
    except Exception as e:
        return json.dumps({"status": "failed", "error": str(e)[:300]})


@mcp.tool()
def xete_settle_reclaim(escrow_id: str) -> str:
    """Cancel a settlement YOU opened and get the funds + rent back, as long as the recipient hasn't
    claimed yet (depositor-only). Returns the tx signature."""
    ident = load_or_create_identity(IDENTITY_PATH)
    try:
        from solders.keypair import Keypair

        depositor = Keypair.from_seed(ident.ed_seed)
        sig = settlement.reclaim(RPC_URL, depositor, escrow_id)
        return json.dumps({"status": "reclaimed", "escrow_id": escrow_id, "tx_signature": sig,
                           "to": ident.pubkey_b58}, indent=2)
    except Exception as e:
        return json.dumps({"status": "failed", "error": str(e)[:300]})


@mcp.tool()
def xete_settle_status(escrow_id: str) -> str:
    """Check whether a settlement is still open (unclaimed and unreclaimed). A closed account means it
    already settled. While open, returns the depositor and locked amount. Read-only."""
    try:
        return json.dumps(settlement.status(RPC_URL, escrow_id), indent=2)
    except Exception as e:
        return json.dumps({"status": "failed", "error": str(e)[:300]})


def main():
    mcp.run()


if __name__ == "__main__":
    main()
