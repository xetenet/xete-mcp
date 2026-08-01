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

Settlement confirmation (env):
  XETE_CONFIRM_SECONDS        how long to keep asking the cluster about a submitted settlement
                              before reporting it as UNKNOWN (never as failed) (default 90)
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import requests
from mcp.server.fastmcp import FastMCP

from .client import XeteClient, load_or_create_identity
from . import alias_chain, draft, payment, settlement

SERVER_URL = os.environ.get("XETE_SERVER_URL", "https://xete.net")
RPC_URL = os.environ.get("XETE_RPC_URL", "https://api.mainnet-beta.solana.com")
IDENTITY_PATH = Path(os.environ.get("XETE_IDENTITY", str(Path.home() / ".xete" / "identity.json")))
SOL_KEYPAIR_PATH = os.environ.get("XETE_SOL_KEYPAIR", "")
# The %alias permit server. Separate service from the messaging relay, though in prod it may be
# proxied under the same host — so it defaults to SERVER_URL and is overridable.
PERMIT_URL = os.environ.get("XETE_PERMIT_URL", SERVER_URL)
# Custody-T1 draft path (SPEC-unsigned-settlement-draft-20260729). The depositor is read from
# operator config and NEVER from a tool argument — a tool argument is attacker-reachable through
# any message the agent reads, and it decides who pays.
DEPOSITOR_WALLET = os.environ.get("XETE_DEPOSITOR_WALLET", "")
NONCE_ACCOUNT = os.environ.get("XETE_NONCE_ACCOUNT", "")
NONCE_AUTHORITY = os.environ.get("XETE_NONCE_AUTHORITY", "")

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

def _escrow_id_error(escrow_id: str) -> str | None:
    """None if `escrow_id` is well formed, otherwise the error JSON the tool should return.

    Called as the FIRST statement of every tool that takes an escrow_id — before the identity
    keystore is opened, before the RPC client exists, before anything reaches solders. An
    over-length id makes solders raise a Rust PanicException, which derives from BaseException
    and so is NOT caught by the `except Exception` these tools wrap themselves in: it unwinds
    out of the tool, out of the MCP dispatch loop, and kills the stdio session. The agent then
    has no xete tools at all — including xete_settle_reclaim for its own open escrows. And
    escrow_ids come from claim tickets, which come from the inbox, which is anyone.
    """
    try:
        settlement.parse_escrow_id(escrow_id)
    except ValueError as e:
        return json.dumps({"status": "failed", "error": f"invalid escrow_id: {e}"}, indent=2)
    return None


def _salt_error(salt: str) -> str | None:
    """Same boundary, same reason, for the other half of a claim ticket."""
    try:
        settlement.parse_salt(salt)
    except ValueError as e:
        return json.dumps({"status": "failed", "error": f"invalid salt: {e}"}, indent=2)
    return None


def _resolve_recipient_wallet(recipient: str):
    """(wallet Pubkey, messageable_handle | None) — a %alias resolved ON CHAIN, never by asking.

    This function decides where money goes. It used to answer by GETting /alias/resolve and
    trusting the `alias_owner` field, which handed that decision to the permit server: a hostile
    or MITM'd one returns an attacker's pubkey and every tool downstream — including the draft
    verifier whose entire job is to catch exactly this — agrees the payment is correct, because
    the "independent" recipient it compares against came from the same lying answer. That was
    demonstrated end to end: a 1 SOL draft to an attacker returned `verified: true`,
    "SAFE TO REVIEW AND SIGN", zero failed checks.

    The %name registry is a public Solana account. There is no reason to take a server's word
    for it and no safe way to. alias_chain reads it directly and raises rather than guessing when
    the chain cannot be read, so a resolution failure fails these tools closed instead of
    falling back to the server.
    """
    import base58
    from solders.pubkey import Pubkey

    r = recipient.strip()
    try:
        if len(base58.b58decode(r)) == 32:
            return Pubkey.from_string(r), None  # raw wallet; not messageable by itself
    except Exception:
        pass
    name = alias_chain.normalize_name(r)
    owner = alias_chain.resolve_owner(name)
    if not owner:
        raise RuntimeError(f"could not resolve recipient '{recipient}': the on-chain %alias "
                           f"registry has no registration for %{name}")
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
    can xete_settle_reclaim it any time before they claim.

    If confirmation times out the ticket still comes back, under `ticket`, with status
    `submitted_unconfirmed` — the deposit may well have landed, so KEEP IT."""
    ident = load_or_create_identity(IDENTITY_PATH)
    # Filled in by settlement.deposit BEFORE it submits. The salt lives nowhere else — only its
    # hash goes on chain — so this is the copy that survives a confirmation timeout.
    early_ticket: dict = {}
    try:
        from solders.keypair import Keypair

        recipient_wallet, handle = _resolve_recipient_wallet(recipient)
        depositor = Keypair.from_seed(ident.ed_seed)
        lamports = int(round(amount_sol * 1_000_000_000))
        if lamports <= 0:
            return json.dumps({"status": "failed", "error": "amount_sol must be > 0"})
        eid_hex, salt_hex, pda, sig = settlement.deposit(
            RPC_URL, depositor, recipient_wallet, lamports, on_ticket=early_ticket.update)
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
    except settlement.SettlementSubmitError as e:
        # The transaction was submitted. Whether it landed is unknown (or, for outcome
        # "dropped"/"failed", known not to have) — but the ticket is the ONLY copy of the salt,
        # so it goes back to the caller either way. Losing it makes a deposit that did land
        # unclaimable forever.
        return json.dumps({
            "status": "failed" if e.outcome in ("failed", "dropped") else "submitted_unconfirmed",
            "submit_outcome": e.outcome,
            "error": str(e)[:400],
            "tx_signature": e.signature,
            "ticket": e.ticket or early_ticket or None,
            "amount_sol": amount_sol,
            "KEEP_THIS_TICKET": "The salt is not on chain — only sha256(recipient || salt) is. "
                                "If you discard it and the deposit did land, nobody can ever "
                                "claim or identify it.",
            "next_step": "Call xete_settle_status with this escrow_id. If it is open, the "
                         "deposit landed: deliver the ticket to the recipient, or "
                         "xete_settle_reclaim to take the funds back. If it is not open, the "
                         "deposit did not happen and your funds never left.",
        }, indent=2)
    except Exception as e:
        out = {"status": "failed", "error": str(e)[:300]}
        if early_ticket:
            out["ticket"] = early_ticket
            out["KEEP_THIS_TICKET"] = ("a deposit may have been submitted; check "
                                       "xete_settle_status with this escrow_id before discarding")
        return json.dumps(out, indent=2)


@mcp.tool()
def xete_settle_claim(escrow_id: str, salt: str) -> str:
    """Claim a confidential settlement addressed to you — using the escrow_id + salt from the claim
    ticket (sent to your inbox, or handed to you). Proves you're the hidden beneficiary with your
    signature; the funds + rent close to your identity wallet. Returns the tx and the amount received."""
    bad = _escrow_id_error(escrow_id) or _salt_error(salt)
    if bad:
        return bad
    ident = load_or_create_identity(IDENTITY_PATH)
    try:
        from solders.keypair import Keypair

        beneficiary = Keypair.from_seed(ident.ed_seed)
        sig, received = settlement.claim(RPC_URL, beneficiary, escrow_id, salt)
        return json.dumps({"status": "claimed", "escrow_id": escrow_id, "tx_signature": sig,
                           "received_sol": received / 1e9, "to": ident.pubkey_b58}, indent=2)
    except settlement.SettlementSubmitError as e:
        # "Out of patience" is NOT "failed" — and this tool inherits the same 90s budget as
        # xete_settle_create, so it reaches this path routinely. Reporting `failed` here tells
        # the agent it was not paid on a claim that may well have landed; the agent then tells
        # the counterparty to reclaim, and a settled payment gets unwound. Hand back the
        # signature and the way to resolve it instead of asserting an outcome we do not know.
        return json.dumps({
            "status": "failed" if e.outcome in ("failed", "dropped") else "submitted_unconfirmed",
            "submit_outcome": e.outcome,
            "escrow_id": escrow_id,
            "error": str(e)[:400],
            "tx_signature": e.signature,
            "DO_NOT_ASSUME_YOU_WERE_NOT_PAID":
                "The claim was submitted. Unless submit_outcome is 'failed' or 'dropped' it may "
                "still land. Do not re-claim, and do not tell the depositor to reclaim, until "
                "you have checked.",
            "next_step": "Call xete_settle_status with this escrow_id. open=false means the "
                         "escrow closed — your claim landed and the funds are in your wallet. "
                         "open=true means it did not land and you can safely retry.",
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "failed", "error": str(e)[:300]})


@mcp.tool()
def xete_settle_reclaim(escrow_id: str) -> str:
    """Cancel a settlement YOU opened and get the funds + rent back, as long as the recipient hasn't
    claimed yet (depositor-only). Returns the tx signature."""
    bad = _escrow_id_error(escrow_id)
    if bad:
        return bad
    ident = load_or_create_identity(IDENTITY_PATH)
    try:
        from solders.keypair import Keypair

        depositor = Keypair.from_seed(ident.ed_seed)
        sig = settlement.reclaim(RPC_URL, depositor, escrow_id)
        return json.dumps({"status": "reclaimed", "escrow_id": escrow_id, "tx_signature": sig,
                           "to": ident.pubkey_b58}, indent=2)
    except settlement.SettlementSubmitError as e:
        # Same reasoning as xete_settle_claim: reporting `failed` on a reclaim that landed
        # leaves the agent believing its funds are still locked in an escrow that no longer
        # exists, and it will keep retrying an instruction the chain will keep rejecting.
        return json.dumps({
            "status": "failed" if e.outcome in ("failed", "dropped") else "submitted_unconfirmed",
            "submit_outcome": e.outcome,
            "escrow_id": escrow_id,
            "error": str(e)[:400],
            "tx_signature": e.signature,
            "DO_NOT_ASSUME_YOUR_FUNDS_ARE_STILL_LOCKED":
                "The reclaim was submitted. Unless submit_outcome is 'failed' or 'dropped' it "
                "may still land.",
            "next_step": "Call xete_settle_status with this escrow_id. open=false means the "
                         "escrow closed — the reclaim landed and the funds are back in your "
                         "wallet. open=true means it did not land and you can safely retry.",
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "failed", "error": str(e)[:300]})


@mcp.tool()
def xete_settle_status(escrow_id: str, expect_recipient: str = "", salt: str = "") -> str:
    """Check whether a settlement is still open (unclaimed and unreclaimed), and — if you pass the
    rest of the claim ticket — whether it is actually FOR the wallet you think. A closed account
    means it already settled. Read-only.

    "Open" on its own proves nothing about who gets paid. The beneficiary is hidden on-chain as
    sha256(wallet || salt), so an attacker can open a genuine escrow naming themselves, send you
    its id, and the depositor, amount and pda will all look exactly right. Pass `expect_recipient`
    (normally your own wallet, from xete_my_identity) and the `salt` from the ticket: this
    re-derives the commitment and tells you plainly whether it matches. Without them,
    `beneficiary_verified` comes back null and you have verified nothing."""
    bad = _escrow_id_error(escrow_id)
    if bad:
        return bad
    if salt:
        bad = _salt_error(salt)
        if bad:
            return bad
    try:
        expect_commitment = None
        checked_against = None
        if expect_recipient and salt:
            wallet, _ = _resolve_recipient_wallet(expect_recipient)
            expect_commitment = settlement.commitment(wallet, settlement.parse_salt(salt)).hex()
            checked_against = str(wallet)
        out = settlement.status(RPC_URL, escrow_id, expect_commitment_hex=expect_commitment)
        if checked_against:
            out["checked_against_wallet"] = checked_against
        elif expect_recipient or salt:
            # Half a claim ticket verifies NOTHING, and silence about that is worse than not
            # offering the argument: a caller who passed their own wallet reasonably reads a
            # clean response as confirmation that the escrow is theirs. The beneficiary is on
            # chain only as sha256(wallet || salt); one half of that pair proves nothing.
            missing = "salt" if expect_recipient else "expect_recipient"
            out["WARNING_NOTHING_WAS_VERIFIED"] = (
                f"You supplied only half a claim ticket — {missing} is missing. BOTH are "
                "required: the beneficiary is stored on chain only as sha256(wallet || salt), "
                "so neither half proves anything alone. beneficiary_verified is null, and "
                "nothing about who this escrow pays has been verified.")
        elif out.get("open"):
            out["how_to_verify"] = ("call again with expect_recipient=<your wallet> and "
                                    "salt=<the salt from the claim ticket>")
        return json.dumps(out, indent=2)
    except Exception as e:
        return json.dumps({"status": "failed", "error": str(e)[:300]})


@mcp.tool()
def xete_draft_settlement_tx(recipient: str, amount_sol: float) -> str:
    """Draft an UNSIGNED settlement transaction paying `recipient` `amount_sol` — for review and
    signing by a HUMAN in their own wallet. This tool CANNOT move funds: it holds no key and
    submits nothing. Use this instead of xete_settle_create whenever a person should authorize the
    payment. Recipient may be a wallet address or a %alias. Returns base64 unsigned transaction, a
    plain-English summary, the claim ticket (escrow_id + salt) the recipient will need, and the
    exact arguments to pass to xete_verify_settlement_tx. The beneficiary is HIDDEN on-chain as a
    hash, so the raw transaction does not show who gets paid — always verify before signing."""
    try:
        from solders.pubkey import Pubkey

        if not DEPOSITOR_WALLET:
            return json.dumps({"status": "unconfigured", "error":
                               "XETE_DEPOSITOR_WALLET is not set. The operator must configure the "
                               "wallet that will sign; it is deliberately not a tool argument."})
        depositor = Pubkey.from_string(DEPOSITOR_WALLET)
        recipient_wallet, handle = _resolve_recipient_wallet(recipient)
        lamports = int(round(amount_sol * 1_000_000_000))
        if lamports <= 0:
            return json.dumps({"status": "failed", "error": "amount_sol must be > 0"})

        nonce_acct = Pubkey.from_string(NONCE_ACCOUNT) if NONCE_ACCOUNT else None
        nonce_auth = Pubkey.from_string(NONCE_AUTHORITY) if NONCE_AUTHORITY else None
        d = draft.draft_deposit(RPC_URL, depositor, recipient_wallet, lamports,
                                nonce_account=nonce_acct, nonce_authority=nonce_auth)

        summary = (f"Pay {amount_sol} SOL to {recipient}"
                   f"{'' if str(recipient_wallet) == recipient else f' ({recipient_wallet})'} "
                   f"from {depositor}. The beneficiary is hidden on-chain behind commitment "
                   f"{d.commitment_hex[:16]}…; funds sit in escrow {d.pda} until the recipient "
                   f"claims with the ticket below, and you can reclaim them until they do. "
                   f"{d.expires_note}")
        return json.dumps({
            "status": "drafted", "signed": False, "custody": "T1 — no key held; a human signs",
            "unsigned_tx_b64": d.unsigned_tx_b64,
            "summary": summary,
            "depositor": d.depositor, "recipient_wallet": d.recipient, "amount_sol": amount_sol,
            "amount_lamports": d.amount_lamports, "pda": d.pda, "program": d.program,
            "blockhash_kind": d.blockhash_kind, "nonce_account": d.nonce_account,
            "ticket": {"escrow_id": d.escrow_id_hex, "salt": d.salt_hex,
                       "deliver_to": handle or "recipient (no xete handle found)"},
            "verify_with": {
                "tool": "xete_verify_settlement_tx",
                "unsigned_tx_b64": "<the value above>",
                # NOT pre-filled with d.recipient, deliberately. A verifier handed the draft's
                # own answer is not an independent check of that answer — it re-derives the
                # commitment from the same wallet that built it and agrees with itself. Whoever
                # is authorising the payment must supply the destination from their own
                # knowledge for this tool to mean anything.
                "expect_recipient": "<SUPPLY THIS YOURSELF — do not copy recipient_wallet from "
                                    "this response. The point of verifying is to compare the "
                                    "transaction against a destination this draft did not "
                                    "choose; fed its own answer the verifier always passes.>",
                "expect_escrow_id": d.escrow_id_hex,
                "salt": d.salt_hex,
                "amount_sol": amount_sol,
            },
            "next_step": "Have a human verify — supplying expect_recipient themselves — then "
                         "sign and submit from their own wallet. Do not deliver the claim "
                         "ticket until the deposit confirms on-chain.",
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "failed", "error": str(e)[:300]})


@mcp.tool()
def xete_verify_settlement_tx(unsigned_tx_b64: str, expect_recipient: str, salt: str,
                              amount_sol: float, expect_escrow_id: str = "") -> str:
    """Independently check that an unsigned settlement transaction really pays who you think it
    pays — and ONLY that — before a human signs it. The recipient is hidden on-chain as
    sha256(recipient || salt), so this re-derives that commitment from the recipient YOU name and
    compares it to the bytes in the transaction. It also decodes the data of every instruction,
    itemises every lamport that would leave the signer (`lamport_movements`), totals them, and
    prices the compute-budget priority fee — so a bolted-on system transfer or an inflated fee
    cannot hide behind a familiar program id. Returns a per-check pass/fail table. A
    `verified: false` result means DO NOT SIGN — the transaction does not match the stated intent.

    `expect_recipient` MUST come from whoever is authorising the payment, not from the draft's
    own `recipient_wallet` output. Copying the draft's answer back in makes every check pass by
    construction and verifies nothing. Pass `expect_escrow_id` from the claim ticket too, so a
    transaction that funds a different escrow than the ticket names is caught rather than
    certified — the recipient could never claim that one."""
    try:
        from solders.pubkey import Pubkey

        if not DEPOSITOR_WALLET:
            return json.dumps({"status": "unconfigured",
                               "error": "XETE_DEPOSITOR_WALLET is not set; nothing to verify against."})
        recipient_wallet, _ = _resolve_recipient_wallet(expect_recipient)
        r = draft.verify_draft(
            unsigned_tx_b64,
            expect_recipient=recipient_wallet,
            expect_salt_hex=salt,
            expect_amount_lamports=int(round(amount_sol * 1_000_000_000)),
            expect_depositor=Pubkey.from_string(DEPOSITOR_WALLET),
            expect_escrow_id_hex=expect_escrow_id or None,
        )
        return json.dumps({
            "verified": r.ok,
            "verdict": "SAFE TO REVIEW AND SIGN" if r.ok else "DO NOT SIGN — verification failed",
            "failed_checks": r.failures,
            "lamport_movements": r.movements,
            "total_lamports_out": r.total_lamports_out,
            "total_sol_out": r.total_lamports_out / 1e9,
            "max_fee_lamports": r.fee_lamports,
            "escrow_id_funded": r.escrow_id_hex,
            "checks": r.checks,
            "recipient_checked": str(recipient_wallet),
            "recipient_resolved_from": ("the base58 wallet you supplied"
                                        if str(recipient_wallet) == expect_recipient.strip()
                                        else "the on-chain %alias registry"),
        }, indent=2)
    except Exception as e:
        return json.dumps({"verified": False, "verdict": "DO NOT SIGN — verifier errored",
                           "error": str(e)[:300]})

def main():
    mcp.run()


if __name__ == "__main__":
    main()
