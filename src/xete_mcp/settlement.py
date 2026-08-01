"""Confidential settlement — the "tab": agent->agent value transfer on the live, IMMUTABLE
settlement program (GPCsJ6kvrQ61wDG8bpP8315ge7AHfmsUHdxTD7LQ6CoJ).

Deposit hides the beneficiary on-chain as a commitment H(recipient_pubkey || salt); the recipient
claims by proving it (their signature + the salt). Non-custodial: only the depositor's key (reclaim)
or the beneficiary's key (claim) can move the funds — the program can never freeze or seize. "Rent
follows the funds": claiming/reclaiming closes the account, returning its rent with the amount, so no
SOL is stranded.

Wire format mirrors settlement_runner.py / the lean contract exactly:
  deposit(tag 0): escrow_id[32] amount(u64) commitment[32] unlock(i64)   accts [depositor(s,w), pda(w), system]
  claim  (tag 1): escrow_id[32] salt_len(u32) salt[..]                   accts [beneficiary(s,w), pda(w)]
  reclaim(tag 2): escrow_id[32]                                          accts [depositor(s,w), pda(w)]
  state (81B): depositor[0:32] amount[32:40] commitment[40:72] unlock[72:80] bump[80]

Money-critical: the program id is hardcoded to the mainnet deployment so a malicious server can't
redirect it. It may be overridden ONLY via XETE_SETTLEMENT_PROGRAM, which exists for local-validator
testing — never point it at an untrusted program with real funds.
"""
from __future__ import annotations

import hashlib
import os
import struct
import time

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.instruction import AccountMeta, Instruction
from solders.message import Message
from solders.transaction import Transaction
from solders.transaction_status import TransactionConfirmationStatus
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts

try:                                     # the JSON-RPC error type, as distinct from transport
    from solana.rpc.core import RPCException
except Exception:                        # pragma: no cover — layout drift in solana-py
    class RPCException(Exception):       # never raised by anything; the guard below then falls
        """Placeholder so the endpoint-answered branch simply never matches."""

SYS = Pubkey.from_string("11111111111111111111111111111111")
CB = Pubkey.from_string("ComputeBudget111111111111111111111111111111")
MAINNET_PROGRAM = "GPCsJ6kvrQ61wDG8bpP8315ge7AHfmsUHdxTD7LQ6CoJ"

ESCROW_ID_BYTES = 32
ESCROW_ID_HEX_LEN = ESCROW_ID_BYTES * 2
MAX_SALT_BYTES = 64
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

# depositor[0:32] amount[32:40] commitment[40:72] unlock[72:80] bump[80]. An account at the
# escrow PDA that is not EXACTLY this long is not this program's state, whatever else it is.
#
# VERIFIED AGAINST THE DEPLOYED PROGRAM, 2026-08-01, not inherited from a docstring. This
# constant gates "did my money land", so an unchecked value would be a hard dependency on a
# comment. Read-only from mainnet, via getSignaturesForAddress on the program id:
#   deposit  4zAVuxHQ3ve3NkzTbr1Nvb4AAUEXoKo5ZXkX45VegGy5cXmhoWVR724aMtZrimhqErU9SA4Eq2GxxJrrcAPSyqig
#            inner CPI createAccount -> {"newAccount": "27hLEGELtNKbQTqKfcV2YcRLj9FLHf3j3DCUBEpMs311",
#                                        "owner": "GPCsJ6kv...", "space": 81}
#   claim    5fwM657mN3n3LXbMeGSttmUG3N147sHcmn775i3kZ92Afrx3iVGStXMnSyVzpD39t6H3L7e3mz8Sb4zP4iTc4MM7
#            closed it; getAccountInfo on that PDA now returns null.
# The program is IMMUTABLE, so this cannot drift underneath us — the deployment that allocated
# 81 bytes is the only deployment there will ever be. If that ever stops being true, `status()`
# answers `open: null` (indeterminate) rather than `open: false`, so a layout change costs a
# refusal to conclude, never a discarded claim ticket.
STATE_LEN = 81

# How long to keep asking the cluster about a submitted transaction. RPC nodes rebroadcast a
# transaction for roughly 60-90s (until its blockhash dies); a client that gives up sooner is
# not observing a failure, it is looking away while the transaction is still alive.
ENV_CONFIRM_SECONDS = "XETE_CONFIRM_SECONDS"
DEFAULT_CONFIRM_SECONDS = 90.0

# A SECOND, independently-operated Solana RPC. Optional, and the only thing on this path that can
# turn "an endpoint told me" into "the chain says". Every field `status()` reads — including the
# `owner` field it uses to decide whether the bytes are this program's state — arrives inside one
# JSON document from one endpoint, so a hostile endpoint sets all of them together. Owner checks
# do not fix that; a second source that has to agree does. Set it to a different provider than
# XETE_RPC_URL, or it is the same source twice and buys nothing.
ENV_SECOND_RPC = "XETE_RPC_URL_2"
_POLL_SECONDS = 0.3
# Per-request ceiling for the corroborating endpoint. solana-py's default is 10s per request and
# _corroborate_dropped makes two, from inside a loop that promises the confirmation budget bounds
# the whole call. It is clamped again against the remaining budget at the call site.
_CORROBORATION_TIMEOUT = 5.0
# Only these are durable. `Processed` is one validator's opinion and can still be forked away.
_DURABLE = (TransactionConfirmationStatus.Confirmed, TransactionConfirmationStatus.Finalized)


class InvalidEscrowId(ValueError):
    """An escrow_id (or salt) that is not well-formed. Raised INSTEAD of letting solders panic."""


class SettlementSubmitError(RuntimeError):
    """A transaction was submitted but did not reach a durable status in the time we waited.

    Carries what is needed to recover instead of guessing:
      signature — look the transaction up; it may well have landed after we stopped watching.
      ticket    — for a deposit, the escrow_id + salt. The salt is NEVER written on chain (only
                  its hash is), so if this object is dropped the beneficiary can never prove the
                  commitment and the funds are unclaimable.
      outcome   — "unconfirmed": may still land, DO NOT assume it failed. This is the default,
                  and it is where anything that cannot be established belongs.
                  "dropped":     the blockhash died before the cluster ever saw it; it cannot
                  land. Requires TWO endpoints to say so — the tools turn this into a flat
                  "failed", so one endpoint's word is not enough to earn it.
                  "failed":      it did not take effect. Either the chain executed it and it
                  errored (at a DURABLE commitment — a `Processed` error is still forkable and
                  is not accepted as proof), or the endpoint simulated it at submit and refused
                  to forward it. The signature is carried in both cases anyway.
    """

    def __init__(self, message: str, *, signature: str | None = None,
                 outcome: str = "unconfirmed", ticket: dict | None = None):
        super().__init__(message)
        self.signature = signature
        self.outcome = outcome
        self.ticket = ticket


def program_id() -> Pubkey:
    return Pubkey.from_string(os.environ.get("XETE_SETTLEMENT_PROGRAM", MAINNET_PROGRAM))


def parse_escrow_id(escrow_id_hex) -> bytes:
    """Attacker-reachable text -> 32 raw bytes, or InvalidEscrowId.

    This is the boundary between a counterparty's string and the Rust FFI. Escrow ids arrive in
    claim tickets, and claim tickets arrive in the agent's INBOX, so the value is chosen by
    whoever wants to talk to this agent.

    It matters because solders' find_program_address raises pyo3 PanicException on a seed that is
    too long, and PanicException derives from BaseException, NOT Exception. A 66-character id
    therefore sails straight through the `except Exception` in every settlement tool and kills the
    stdio session — the agent loses every xete tool at once, including the reclaim tool for its
    own open escrows. Nothing unvalidated may reach solders.
    """
    if not isinstance(escrow_id_hex, str):
        raise InvalidEscrowId(f"escrow_id must be a string, got {type(escrow_id_hex).__name__}")
    s = escrow_id_hex.strip()
    if len(s) != ESCROW_ID_HEX_LEN:
        raise InvalidEscrowId(f"escrow_id must be exactly {ESCROW_ID_HEX_LEN} hex characters "
                              f"({ESCROW_ID_BYTES} bytes); got {len(s)}")
    if not all(c in _HEX_DIGITS for c in s):
        raise InvalidEscrowId("escrow_id must be hex (0-9a-f); refusing to pass it to solders")
    return bytes.fromhex(s)


def parse_salt(salt_hex) -> bytes:
    """Claim-ticket salt -> raw bytes, or InvalidEscrowId. Same untrusted source as the escrow id;
    the length also goes into instruction data as a u32, so it is bounded here."""
    if not isinstance(salt_hex, str):
        raise InvalidEscrowId(f"salt must be a string, got {type(salt_hex).__name__}")
    s = salt_hex.strip()
    if not s or len(s) % 2 or len(s) > MAX_SALT_BYTES * 2:
        raise InvalidEscrowId(f"salt must be 1-{MAX_SALT_BYTES} bytes of hex (an even number of "
                              f"hex characters); got {len(s)} characters")
    if not all(c in _HEX_DIGITS for c in s):
        raise InvalidEscrowId("salt must be hex (0-9a-f)")
    return bytes.fromhex(s)


def escrow_pda(program: Pubkey, escrow_id: bytes) -> Pubkey:
    """Derive the escrow PDA. Guarded because find_program_address is the one call in this module
    that can PANIC out of Rust rather than raise a Python Exception (see parse_escrow_id). Every
    path to it goes through here, so this guard is what makes that panic unreachable."""
    if not isinstance(escrow_id, (bytes, bytearray)):
        raise InvalidEscrowId(f"escrow_id seed must be bytes, got {type(escrow_id).__name__}")
    if len(escrow_id) != ESCROW_ID_BYTES:
        raise InvalidEscrowId(f"escrow_id seed must be exactly {ESCROW_ID_BYTES} bytes, "
                              f"got {len(escrow_id)}")
    return Pubkey.find_program_address([b"escrow", bytes(escrow_id)], program)[0]


def commitment(recipient: Pubkey, salt: bytes) -> bytes:
    return hashlib.sha256(bytes(recipient) + salt).digest()


def _cb_price(u: int) -> Instruction:
    return Instruction(program_id=CB, data=bytes([3]) + struct.pack("<Q", u), accounts=[])


def _cb_limit(u: int) -> Instruction:
    return Instruction(program_id=CB, data=bytes([2]) + struct.pack("<I", u), accounts=[])


def confirm_seconds() -> float:
    try:
        v = float(os.environ.get(ENV_CONFIRM_SECONDS) or DEFAULT_CONFIRM_SECONDS)
    except (TypeError, ValueError):
        return DEFAULT_CONFIRM_SECONDS
    return v if v > 0 else DEFAULT_CONFIRM_SECONDS


def _blockhash_alive(client: Client, bh) -> bool | None:
    """True / False / None when the RPC cannot tell us. Never raises — this is a nicety that
    turns a guess into a definite answer, and it must not itself become a failure mode."""
    try:
        return bool(client.is_blockhash_valid(bh).value)
    except Exception:
        return None


def _send(client: Client, signers, ixs, payer: Keypair, label: str,
          ticket: dict | None = None, rpc_url: str | None = None) -> str:
    bh = client.get_latest_blockhash().value.blockhash
    tx = Transaction(signers, Message.new_with_blockhash([_cb_limit(60_000), _cb_price(1_000)] + ixs, payer.pubkey(), bh), bh)
    # THE SIGNATURE IS KNOWN HERE, BEFORE ANYTHING IS SUBMITTED. It is ed25519 over the signed
    # message, computed locally by Transaction() — it is the id the cluster will index this
    # transaction under, and it does not depend on any endpoint answering. Every recovery story
    # on this path ("check signature X on chain") needs it, so it is captured before the one call
    # that can lose it instead of being read off the RPC's reply afterwards.
    sig = tx.signatures[0]
    sig_local = str(sig)
    # ── FROM HERE ON THE TRANSACTION IS OR MAY BE LIVE ON THE CLUSTER ──────────────────────
    # The boundary is the send CALL, not its return. An endpoint that read the request and
    # forwarded it has already made the transaction live; a read timeout, a proxy 502 or a
    # dropped socket on the RESPONSE leaves it landing while this client raises. An endpoint
    # that failed before forwarding is INDISTINGUISHABLE from that, from here. Unguarded, the
    # raise unwound past every SettlementSubmitError handler into the tools' bare
    # `except Exception`, which reported {"status": "failed"} AND discarded the signature —
    # telling the caller they were not paid for a transaction the cluster may be confirming.
    # NOTE ON MESSAGE ORDER, here and in every SettlementSubmitError below: OUR signature is
    # stated before any endpoint-controlled text. The tools truncate `str(e)` at 400 characters,
    # and the endpoint chooses the exception text — so a message that ends with "check signature
    # X" can have X cut off while an attacker-supplied signature-shaped string survives at the
    # front. The recovery string leads.
    try:
        returned = client.send_transaction(
            tx, opts=TxOpts(skip_preflight=False, preflight_commitment=Confirmed)).value
    except SettlementSubmitError:
        raise
    except RPCException as e:
        # THE ENDPOINT ANSWERED, and its answer is a refusal. With skip_preflight=False the node
        # simulates the transaction and declines to forward what fails, so this is the ordinary
        # deterministic rejection — a wrong salt, an escrow already claimed, not enough lamports
        # — and calling it "may be live" would tell the agent not to retry the very thing it
        # should fix. It is reported as the failure it is, but WITH the signature: if this
        # endpoint is lying about not forwarding, that string is the only way to find out.
        raise SettlementSubmitError(
            f"{label} was REJECTED at submit: signature {sig_local}. The endpoint "
            f"{rpc_url or '(unnamed)'} simulated it and refused to forward it, so it did not "
            f"execute and nothing moved. Fix the cause and retry. (If you have reason to doubt "
            f"that endpoint, check the signature on chain — a node that refused a transaction it "
            f"had already forwarded would look the same.) Endpoint said: "
            f"{type(e).__name__}: {str(e)[:160]}",
            signature=sig_local, outcome="failed", ticket=ticket) from e
    except Exception as e:                      # noqa: BLE001 — deliberate, see above
        raise SettlementSubmitError(
            f"{label} MAY ALREADY BE LIVE: check signature {sig_local} on chain before retrying "
            f"or discarding anything. The transaction is SIGNED and the submit call itself "
            f"failed without an answer from the endpoint — one that forwarded it and then failed "
            f"to reply looks exactly like one that never forwarded it. This is NOT a confirmed "
            f"failure. Transport error: {type(e).__name__}: {str(e)[:160]}",
            signature=sig_local, outcome="unconfirmed", ticket=ticket) from e
    # The endpoint does not get to name our transaction. The signature is deterministic and we
    # computed it above, so an endpoint returning anything else is handing back a receipt for a
    # DIFFERENT transaction — and the whole recovery story ("look up signature X") would then
    # confirm a stranger's transaction as ours. Free check, so make it; and poll on the local
    # signature regardless of what came back.
    if str(returned) != sig_local:
        raise SettlementSubmitError(
            f"{label}: SIGNATURE MISMATCH — this client signed {sig_local}, and that is the only "
            f"transaction to look for. The endpoint {rpc_url or '(unnamed)'} answered with a "
            f"different signature, so nothing it says about either transaction can be trusted. "
            f"The transaction MAY BE LIVE — check ours against a different endpoint before "
            f"retrying or discarding anything. It returned: {str(returned)[:96]}",
            signature=sig_local, outcome="unconfirmed", ticket=ticket)
    # Everything below only WATCHES it. No failure of the watching can un-submit it, so no
    # failure of the watching may be reported as a failure of the transaction. This try/except
    # is the whole guarantee: without it, the very first `get_signature_statuses` call raising —
    # a 429 from api.mainnet-beta, which is this repo's default RPC and rate-limits routinely, a
    # dropped socket, a DNS blip — unwound past every SettlementSubmitError handler into the
    # tools' bare `except Exception`, which reported {"status": "failed"} AND discarded the
    # signature, leaving the caller with no way to find a transaction that was already landing.
    # Catching it here fixes create, claim and reclaim at one site and keeps the signature.
    try:
        return _await_confirmation(client, sig, bh, label, ticket, rpc_url=rpc_url)
    except SettlementSubmitError:
        raise
    except Exception as e:                      # noqa: BLE001 — deliberate, see above
        raise SettlementSubmitError(
            f"{label} was SUBMITTED and MAY WELL HAVE LANDED: check signature {sig_local} on "
            f"chain before retrying or discarding anything. The RPC stopped answering after the "
            f"submit, which says nothing about the transaction. Endpoint error: "
            f"{type(e).__name__}: {str(e)[:160]}",
            signature=sig_local, outcome="unconfirmed", ticket=ticket) from e


def _corroborate_dropped(sig, bh, primary: str | None,
                         timeout: float = _CORROBORATION_TIMEOUT) -> tuple[str, str]:
    """Ask a SECOND, independently-operated endpoint about a suspected drop. Never raises.

    Returns ("dropped" | "seen" | "unknown", detail). "dropped" is the only answer that licenses
    the definitive verdict, and it needs a second endpoint that has ALSO never seen the signature
    and ALSO calls the blockhash dead.

    TIME-BOUNDED, and the bound is the caller's business: solana-py's default is 10 SECONDS PER
    REQUEST, and this makes two of them from inside a loop whose whole contract is that the
    confirmation budget bounds the total. An unbounded corroboration would let a merely-slow
    second endpoint add ~20s to a tool call that promised not to.

    Whether the endpoints are genuinely independent is `second_rpc_url`'s judgement, and it is a
    raw string comparison — two spellings of one host still count as two. That is findings
    [G10]/[G16], owned elsewhere; this function is no stronger than the answer it gets there.
    """
    try:
        url = second_rpc_url(primary) if primary else None
    except Exception:
        url = None
    if not url:
        return "unknown", ("no second endpoint is configured, so this rests on one source — set "
                           + ENV_SECOND_RPC + " to a DIFFERENT provider")
    try:
        c = Client(url, timeout=max(1.0, float(timeout)))
        st = c.get_signature_statuses([sig]).value[0]
    except Exception as e:
        return "unknown", f"the second endpoint ({url}) did not answer: {type(e).__name__}"
    if st is not None:
        return "seen", f"the second endpoint ({url}) HAS a status for this signature"
    if _blockhash_alive(c, bh) is not False:
        return "unknown", f"the second endpoint ({url}) does not agree the blockhash is dead"
    return "dropped", f"corroborated by a second, independently-configured endpoint ({url})"


def _await_confirmation(client: Client, sig, bh, label: str, ticket: dict | None,
                        rpc_url: str | None = None) -> str:
    """Poll until `sig` reaches a durable status, or raise SettlementSubmitError describing what
    is and is not known. Split out of `_send` so the submit boundary is a syntactic one: every
    line in here runs with a live transaction on the cluster.

    `budget` bounds the polling. At most ONE corroboration excursion may run on top of it (two
    requests to a second endpoint, each clamped to what is left of the budget, never more than
    _CORROBORATION_TIMEOUT) — it happens only on a suspected drop, and it happens exactly once
    because every branch out of it either raises or stops asking."""
    budget = confirm_seconds()

    # A WALL CLOCK, not a poll count. The previous shape was
    #     for i in range(int(budget / _POLL_SECONDS)): sleep(_POLL_SECONDS); <rpc round trip>
    # which spends `budget` seconds sleeping PLUS one RPC round trip per iteration — and the
    # round trip is timed by the RPC, which is the untrusted party here. At the 90s default that
    # is 300 iterations; against a 0.5s RPC it blocks the agent's stdio session for 240s, and
    # claim/reclaim inherit it. `budget` must be the total time this function can take, so the
    # deadline is fixed once, up front, and the RPC's latency is spent out of it rather than
    # added to it. A slow RPC now costs polls, never extra seconds.
    deadline = time.monotonic() + budget
    seen = False
    i = 0
    while True:
        st = client.get_signature_statuses([sig]).value[0]
        if st is not None:
            # Compare the enum; do NOT test it for truth. Every variant of
            # TransactionConfirmationStatus is truthy, so `if st.confirmation_status` reports
            # `Processed` — one validator's opinion, still forkable — as settled.
            durable = st.confirmation_status in _DURABLE
            if st.err and durable:
                raise SettlementSubmitError(f"{label} failed on-chain: {st.err}",
                                            signature=str(sig), outcome="failed", ticket=ticket)
            if durable:
                return str(sig)
            # SYMMETRY, and it is the point: `Processed` is refused as proof of success because
            # it can still be forked away, so it cannot be proof of FAILURE either. Taking an
            # `err` at that level was the cheaper twin of the single-source `dropped` verdict
            # below — one poll, one endpoint, and the tools turn it into a flat
            # {"status": "failed"} their own guidance reads as "you were not paid". Keep
            # watching: a real error reaches Confirmed within a poll or two and is reported
            # then; anything that never does times out as `unconfirmed`, with the signature.
            seen = True
        elif not seen and i % 20 == 19 and _blockhash_alive(client, bh) is False:
            # Never seen by the cluster AND the blockhash is dead: it can no longer land. That
            # would be a definite answer — but BOTH halves of it are chosen by the same endpoint,
            # and `dropped` is the one outcome the tools turn into a flat {"status": "failed"}
            # whose own guidance reads it as proof the transaction did not land. This module
            # refuses single-source conclusions everywhere else (see `status()`); it must refuse
            # this one too. Same bargain: one source buys a caveated answer, two agreeing sources
            # buy the verdict.
            verdict, detail = _corroborate_dropped(
                sig, bh, rpc_url,
                timeout=min(_CORROBORATION_TIMEOUT, max(1.0, deadline - time.monotonic())))
            if verdict == "dropped":
                raise SettlementSubmitError(
                    f"{label} was dropped: its blockhash expired before the cluster ever saw it "
                    f"({detail})",
                    signature=str(sig), outcome="dropped", ticket=ticket)
            if verdict == "seen":
                # The endpoints disagree about whether the cluster has this transaction. Stop
                # asking the drop question and keep watching for a durable status — the one
                # thing that must not happen is concluding "it cannot land" from the endpoint
                # that is contradicted.
                seen = True
            else:
                raise SettlementSubmitError(
                    f"{label} MAY NOT HAVE BEEN DELIVERED: check signature {sig} on chain before "
                    f"retrying or discarding anything. One endpoint reports no status for it and "
                    f"says its blockhash has already expired, which would mean it can never "
                    f"land — but both of those facts came from that same endpoint and could not "
                    f"be corroborated ({detail}), so this is NOT a confirmed failure.",
                    signature=str(sig), outcome="unconfirmed", ticket=ticket)
        i += 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(_POLL_SECONDS, remaining))
    # Out of patience is NOT the same as failed, and saying "failed" here is what makes a
    # congestion spike destructive: the caller retries or discards state for a transaction that
    # then lands anyway. Report it as unknown and hand back the signature to resolve it with.
    raise SettlementSubmitError(
        f"{label} not confirmed within {budget:.0f}s — it MAY STILL LAND. Do not assume it "
        f"failed: check signature {sig} on chain before retrying or discarding anything.",
        signature=str(sig), outcome="unconfirmed", ticket=ticket)


def deposit_ix(program: Pubkey, depositor: Pubkey, escrow_id: bytes, amount_lamports: int,
               commitment_bytes: bytes, unlock: int = 0) -> Instruction:
    """The deposit (tag 0) instruction, on its own. Factored out so the signing path (`deposit`)
    and the unsigned-draft path (draft.py) build byte-identical instruction data from one source —
    a drift between them would be a silent-loss bug on an IMMUTABLE program."""
    if len(escrow_id) != 32:
        raise ValueError(f"escrow_id must be 32 bytes, got {len(escrow_id)}")
    if len(commitment_bytes) != 32:
        raise ValueError(f"commitment must be 32 bytes, got {len(commitment_bytes)}")
    if amount_lamports <= 0:
        raise ValueError("amount_lamports must be > 0")
    data = (bytes([0]) + escrow_id + struct.pack("<Q", amount_lamports)
            + commitment_bytes + struct.pack("<q", unlock))
    return Instruction(
        program_id=program,
        data=data,
        accounts=[
            AccountMeta(depositor, True, True),
            AccountMeta(escrow_pda(program, escrow_id), False, True),
            AccountMeta(SYS, False, False),
        ],
    )


def deposit(rpc_url: str, depositor: Keypair, recipient: Pubkey, amount_lamports: int,
            on_ticket=None):
    """Open a settlement: lock `amount_lamports` for `recipient` (hidden as a commitment). Returns
    (escrow_id_hex, salt_hex, pda_str, sig). The recipient needs escrow_id + salt to claim.

    SPEND GATE. The client-side limits are checked HERE, before the depositor key is used,
    so every caller is covered — not only the MCP tool. `amount_lamports` is the whole value
    being locked away, and once it is locked only the depositor (reclaim) or the hidden
    beneficiary (claim) can move it again.

    `on_ticket(ticket_dict)` is called with {escrow_id, salt, pda, program} BEFORE the transaction
    is submitted, and it is not optional in spirit: the salt exists nowhere else in the universe.
    Only sha256(recipient || salt) goes on chain, so if this process discards the salt — because
    confirmation timed out during a congestion spike, say — the beneficiary can never prove the
    commitment and the deposit is unclaimable forever. Handing the ticket over first means a
    timeout can lose the confirmation but never the money."""
    from .spendguard import authorize

    authorize(int(amount_lamports), "xete_settle_create", detail=f"recipient={recipient}")

    client = Client(rpc_url)
    prog = program_id()
    eid = bytes(Keypair().pubkey())        # random 32-byte escrow id (never derived from the recipient)
    salt = bytes(Keypair().pubkey())[:16]  # random salt; shared with the recipient out-of-band
    pda = escrow_pda(prog, eid)
    ix = deposit_ix(prog, depositor.pubkey(), eid, amount_lamports, commitment(recipient, salt))
    ticket = {"escrow_id": eid.hex(), "salt": salt.hex(), "pda": str(pda), "program": str(prog)}
    if on_ticket is not None:
        on_ticket(dict(ticket))            # before send_transaction, deliberately
    sig = _send(client, [depositor], [ix], depositor, "deposit", ticket=dict(ticket),
                rpc_url=rpc_url)
    return eid.hex(), salt.hex(), str(pda), sig


def claim(rpc_url: str, beneficiary: Keypair, escrow_id_hex: str, salt_hex: str):
    """Claim a settlement: prove you're the hidden beneficiary (signature + salt) and receive the
    funds + rent. Returns (sig, lamports_received)."""
    eid = parse_escrow_id(escrow_id_hex)   # untrusted: came from a claim ticket, i.e. the inbox
    salt = parse_salt(salt_hex)
    client = Client(rpc_url)
    prog = program_id()
    pda = escrow_pda(prog, eid)
    data = bytes([1]) + eid + struct.pack("<I", len(salt)) + salt
    ix = Instruction(
        program_id=prog,
        data=data,
        accounts=[AccountMeta(beneficiary.pubkey(), True, True), AccountMeta(pda, False, True)],
    )
    try:
        b0 = client.get_balance(beneficiary.pubkey(), Confirmed).value
    except Exception:
        b0 = None                    # pre-submit, so a failure here costs only the receipt
    sig = _send(client, [beneficiary], [ix], beneficiary, "claim", rpc_url=rpc_url)
    # The claim is CONFIRMED. This read is a receipt, nothing more, and a 429 on it must not be
    # allowed to become "your claim failed" — the money is already in the wallet. Same rule as
    # _send's post-submit guard: never let a reporting failure be reported as a money failure.
    try:
        received = None if b0 is None else client.get_balance(
            beneficiary.pubkey(), Confirmed).value - b0
    except Exception:
        received = None
    return sig, received


def reclaim(rpc_url: str, depositor: Keypair, escrow_id_hex: str) -> str:
    """Cancel a settlement you opened and get the funds + rent back (depositor-only). Returns sig."""
    eid = parse_escrow_id(escrow_id_hex)
    client = Client(rpc_url)
    prog = program_id()
    pda = escrow_pda(prog, eid)
    data = bytes([2]) + eid
    ix = Instruction(
        program_id=prog,
        data=data,
        accounts=[AccountMeta(depositor.pubkey(), True, True), AccountMeta(pda, False, True)],
    )
    return _send(client, [depositor], [ix], depositor, "reclaim", rpc_url=rpc_url)


UNVERIFIED_NOTE = (
    "UNVERIFIED — 'open' only means an account exists at the address this escrow_id derives to. "
    "It does NOT mean this settlement pays you. Anyone can open a real escrow naming THEMSELVES "
    "as the hidden beneficiary and hand you its id; depositor, amount and pda would all read back "
    "perfectly. Pass expect_commitment_hex = sha256(your_wallet || salt) to actually check."
)

# Appended to any positive answer that rests on a single endpoint. It is not boilerplate: it is
# the difference between what this function can prove and what it used to claim.
_ONE_SOURCE_CAVEAT = (
    " Only ONE endpoint ({endpoint}) answered, so this is that endpoint's account of the chain, "
    "not the chain. Every field it rests on — the account bytes, and the `owner` field used to "
    "decide those bytes are this program's state — came out of the same JSON document, so an "
    "endpoint that wanted to lie would set them together. Set " + ENV_SECOND_RPC + " to a "
    "DIFFERENT provider and this becomes a two-source answer that a single hostile or MITM'd "
    "endpoint cannot forge.")


def second_rpc_url(primary: str | None = None) -> str | None:
    """The corroborating endpoint, or None. Same endpoint twice is not two sources, so a value
    equal to the primary is treated as unset rather than silently counted as agreement."""
    v = (os.environ.get(ENV_SECOND_RPC) or "").strip()
    if not v or (primary is not None and v == str(primary).strip()):
        return None
    return v


def _read_account(rpc: str, pda: Pubkey) -> tuple[tuple[bool, str | None, bytes | None], int | None]:
    """((exists, owner, data), lamports) for one endpoint. Raises whatever the client raises.

    The first element is the AUTHENTICATED part — what two endpoints have to agree on. lamports
    is reported but deliberately excluded from that comparison: the balance at a PDA can move
    under rent-epoch sweeps and a fresh deposit, so requiring it to match would turn ordinary
    endpoint skew into a false "ENDPOINTS DISAGREE" and make the corroboration useless.
    """
    info = Client(rpc).get_account_info(pda, commitment=Confirmed).value
    if info is None:
        return (False, None, None), None
    owner = getattr(info, "owner", None)
    return (True, (None if owner is None else str(owner)), bytes(info.data)), info.lamports


def status(rpc_url: str, escrow_id_hex: str, expect_commitment_hex: str | None = None,
           second_rpc: str | None = None) -> dict:
    """Is a settlement still open (unclaimed/unreclaimed)? Reads the PDA.

    THREE-VALUED, DELIBERATELY. `open` is True, False, or None, and `determinate` says which
    kind of answer you are holding:

        open=True,  determinate=True   an escrow this program owns is sitting there, unclaimed.
        open=False, determinate=True   nothing is there: it settled, or was never opened.
        open=None,  determinate=False  THE READ COULD NOT BE AUTHENTICATED. Not "no", not "yes".

    The third state is the whole point of this signature. `open` is what the agent branches on,
    and the guidance around it says an escrow that is not open means the deposit never happened
    and the ticket can be discarded. Two branches used to reach `open=False` without knowing
    anything of the sort — an account whose length is not STATE_LEN, and an account whose owner
    the endpoint reports as something else. A funded, genuinely-open escrow that hit either
    branch (layout drift, a mis-set XETE_SETTLEMENT_PROGRAM, a lying or stale endpoint) told the
    agent its money never left, and the agent then discarded the only copy of the salt. The salt
    is not on chain — only sha256(recipient || salt) is — so that deposit becomes unclaimable by
    anyone, forever. "I could not authenticate what I read" and "it settled" must never be the
    same value.

    WHAT THE OWNER CHECK IS AND IS NOT. `owner` is a field of the same JSON the endpoint
    returned. Requiring it to equal the settlement program stops a stale or buggy endpoint, a
    mis-set program id, and an unrelated account genuinely squatting the PDA. It does NOT stop a
    hostile endpoint, which simply writes the settlement program into the field it controls — an
    earlier version of this docstring claimed the check "turns 'these bytes say so' into 'the
    chain says so'", and that was false. The only thing here that constrains a hostile endpoint
    is `second_rpc`: two independently-operated endpoints that must agree. Without one, positive
    answers are labelled "ONE ENDPOINT SAYS" and carry _ONE_SOURCE_CAVEAT, because that is what
    they are worth. Defaults to XETE_RPC_URL_2; pass "" to suppress it explicitly.

    `beneficiary_verified` stays None unless you supply `expect_commitment_hex` (use
    `commitment(you, salt)`) — the commitment is the only field that says who is paid, and
    everything else about an attacker's escrow is indistinguishable from yours.
    """
    eid = parse_escrow_id(escrow_id_hex)
    # Echo the canonical form, never the caller's raw string. parse_escrow_id tolerates
    # surrounding space and upper case, so echoing the input back hands a caller who is string
    # comparing this field against their ticket a spurious mismatch.
    escrow_id_norm = eid.hex()
    prog = program_id()
    pda = escrow_pda(prog, eid)

    second = second_rpc_url(rpc_url) if second_rpc is None else (second_rpc or None)
    authenticated, lamports = _read_account(rpc_url, pda)
    exists, owner, data = authenticated

    out: dict = {"escrow_id": escrow_id_norm, "pda": str(pda),
                 "open": False, "determinate": True, "is_escrow": False,
                 "account_owner": owner, "beneficiary_verified": None, "commitment": None,
                 "endpoints_asked": [rpc_url] + ([second] if second else []),
                 "corroborated": False}
    if exists:
        out["lamports"] = lamports

    # ── corroboration, before anything is concluded from the bytes ──────────────────────────
    if second:
        try:
            second_authenticated, _ = _read_account(second, pda)
        except Exception as e:
            out["second_endpoint_error"] = f"{type(e).__name__}: {str(e)[:160]}"
        else:
            if second_authenticated == authenticated:
                out["corroborated"] = True
            else:
                e2, o2, d2 = second_authenticated
                out["open"] = None
                out["determinate"] = False
                out["verdict"] = (
                    f"ENDPOINTS DISAGREE — {rpc_url} and {second} returned different accounts for "
                    f"{pda}, so at least one of them is wrong or lying and there is no way to "
                    "tell which from here. NOTHING is concluded: do not treat this settlement as "
                    "open, do not treat it as settled, and DO NOT DISCARD A CLAIM TICKET over "
                    "it. Retry, or ask an endpoint you control.")
                out["disagreement"] = {
                    rpc_url: {"exists": exists, "owner": owner,
                              "len": None if data is None else len(data)},
                    second: {"exists": e2, "owner": o2,
                             "len": None if d2 is None else len(d2)}}
                return out

    if not exists:
        out["note"] = "settled or never opened"
        if not out["corroborated"]:
            out["note"] += _ONE_SOURCE_CAVEAT.format(endpoint=rpc_url)
        return out

    if owner is None or owner != str(prog):
        out["open"] = None
        out["determinate"] = False
        out["verdict"] = (
            f"INDETERMINATE — the account at {pda} is reported as owned by "
            f"{'no program the endpoint would name' if owner is None else owner}, not the "
            f"settlement program {prog}. No depositor, amount or commitment is read out of it. "
            "This is NOT 'your deposit never happened': a stale or hostile endpoint, or a "
            "mis-set XETE_SETTLEMENT_PROGRAM, reaches this same answer while a real escrow sits "
            "at that address. KEEP YOUR CLAIM TICKET and re-check against an endpoint you trust.")
        return out
    if len(data) != STATE_LEN:
        out["open"] = None
        out["determinate"] = False
        out["verdict"] = (
            f"INDETERMINATE — UNKNOWN ACCOUNT: {len(data)} bytes at this address, and this "
            f"program's escrow state is {STATE_LEN}. The settlement program owns it, so it is "
            "not an unrelated squatter, but nothing here can be decoded as escrow state. This is "
            "NOT 'your deposit never happened' — a funded, claimable escrow whose layout this "
            "client does not know reads exactly like this. KEEP YOUR CLAIM TICKET.")
        return out

    out["open"] = True
    out["is_escrow"] = True
    out["depositor"] = str(Pubkey.from_bytes(data[0:32]))
    out["amount_lamports"] = struct.unpack("<Q", data[32:40])[0]
    out["commitment"] = data[40:72].hex()
    if expect_commitment_hex is None:
        out["verdict"] = UNVERIFIED_NOTE
        if not out["corroborated"]:
            out["verdict"] += _ONE_SOURCE_CAVEAT.format(endpoint=rpc_url)
        return out
    expected = str(expect_commitment_hex).strip().lower()
    out["expected_commitment"] = expected
    out["beneficiary_verified"] = (expected == out["commitment"])
    if not out["beneficiary_verified"]:
        # A mismatch is the safe direction — it tells you not to release anything — so it is
        # stated plainly whether or not a second endpoint confirmed it.
        out["verdict"] = (
            "MISMATCH — this escrow DOES NOT pay the wallet you named. Its on-chain commitment "
            "is for someone else, so the id you were given is not a settlement you can claim. Do "
            "not treat it as money owed to you, and do not release anything in exchange for it.")
    elif out["corroborated"]:
        out["verdict"] = (
            f"VERIFIED — the hidden beneficiary of this escrow is the wallet you named. Two "
            f"independently-configured endpoints ({rpc_url} and {second}) returned the same "
            "account, so no single endpoint chose this answer.")
    else:
        out["verdict"] = (
            "ONE ENDPOINT SAYS the hidden beneficiary of this escrow is the wallet you named."
            + _ONE_SOURCE_CAVEAT.format(endpoint=rpc_url))
    return out
