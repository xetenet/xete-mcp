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

SYS = Pubkey.from_string("11111111111111111111111111111111")
CB = Pubkey.from_string("ComputeBudget111111111111111111111111111111")
MAINNET_PROGRAM = "GPCsJ6kvrQ61wDG8bpP8315ge7AHfmsUHdxTD7LQ6CoJ"

ESCROW_ID_BYTES = 32
ESCROW_ID_HEX_LEN = ESCROW_ID_BYTES * 2
MAX_SALT_BYTES = 64
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

# depositor[0:32] amount[32:40] commitment[40:72] unlock[72:80] bump[80]. An account at the
# escrow PDA that is not EXACTLY this long is not this program's state, whatever else it is.
STATE_LEN = 81

# How long to keep asking the cluster about a submitted transaction. RPC nodes rebroadcast a
# transaction for roughly 60-90s (until its blockhash dies); a client that gives up sooner is
# not observing a failure, it is looking away while the transaction is still alive.
ENV_CONFIRM_SECONDS = "XETE_CONFIRM_SECONDS"
DEFAULT_CONFIRM_SECONDS = 90.0
_POLL_SECONDS = 0.3
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
      outcome   — "unconfirmed": may still land, DO NOT assume it failed.
                  "dropped":     the blockhash died before the cluster ever saw it; it cannot land.
                  "failed":      the chain executed it and it errored.
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
          ticket: dict | None = None) -> str:
    bh = client.get_latest_blockhash().value.blockhash
    tx = Transaction(signers, Message.new_with_blockhash([_cb_limit(60_000), _cb_price(1_000)] + ixs, payer.pubkey(), bh), bh)
    sig = client.send_transaction(tx, opts=TxOpts(skip_preflight=False, preflight_commitment=Confirmed)).value
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
            if st.err:
                raise SettlementSubmitError(f"{label} failed on-chain: {st.err}",
                                            signature=str(sig), outcome="failed", ticket=ticket)
            # Compare the enum; do NOT test it for truth. Every variant of
            # TransactionConfirmationStatus is truthy, so `if st.confirmation_status` reports
            # `Processed` — one validator's opinion, still forkable — as settled.
            if st.confirmation_status in _DURABLE:
                return str(sig)
            seen = True
        elif not seen and i % 20 == 19 and _blockhash_alive(client, bh) is False:
            # Never seen by the cluster AND the blockhash is dead: it can no longer land. That is
            # a definite answer, so give it instead of waiting out the clock.
            raise SettlementSubmitError(
                f"{label} was dropped: its blockhash expired before the cluster ever saw it",
                signature=str(sig), outcome="dropped", ticket=ticket)
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
    sig = _send(client, [depositor], [ix], depositor, "deposit", ticket=dict(ticket))
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
    b0 = client.get_balance(beneficiary.pubkey(), Confirmed).value
    sig = _send(client, [beneficiary], [ix], beneficiary, "claim")
    received = client.get_balance(beneficiary.pubkey(), Confirmed).value - b0
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
    return _send(client, [depositor], [ix], depositor, "reclaim")


UNVERIFIED_NOTE = (
    "UNVERIFIED — 'open' only means an account exists at the address this escrow_id derives to. "
    "It does NOT mean this settlement pays you. Anyone can open a real escrow naming THEMSELVES "
    "as the hidden beneficiary and hand you its id; depositor, amount and pda would all read back "
    "perfectly. Pass expect_commitment_hex = sha256(your_wallet || salt) to actually check."
)


def status(rpc_url: str, escrow_id_hex: str, expect_commitment_hex: str | None = None) -> dict:
    """Is a settlement still open (unclaimed/unreclaimed)? Reads the PDA. A closed account == settled
    (claimed or reclaimed). Returns the depositor + amount + commitment while it's open.

    The commitment is the ONLY field that says who the escrow pays, and it is the reason this
    function will not call an escrow yours on its own: everything else about an attacker's escrow
    is indistinguishable from yours. Supply `expect_commitment_hex` (use `commitment(you, salt)`)
    and `beneficiary_verified` becomes a real True/False; leave it out and it stays None, meaning
    nothing has been verified.

    `open` IS THE MACHINE-READABLE ANSWER and it is only ever True for an account that this
    program owns and that is exactly the escrow layout. Two reasons that matters:

      * Agents branch on `open`, not on the English in `verdict` — and the timeout guidance in
        xete_settle_create names `open` as the "did my deposit land" signal. A field that says
        True for anything sitting at the address is not that signal. Anyone can pay the rent
        minimum to create a 0-data, system-owned account at a known PDA, and before this it read
        back as an open escrow.
      * The account is bytes from an RPC, and the RPC is the untrusted party. `owner` is what
        makes the rest of the struct mean anything: without it, `commitment` — the whole value of
        this function — is compared against 32 bytes a hostile or MITM'd endpoint chose. The
        owner check is what turns "these bytes say so" into "the chain says so".

    Both checks fail CLOSED: a response with no owner field at all is not an escrow either.
    """
    eid = parse_escrow_id(escrow_id_hex)
    # Echo the canonical form, never the caller's raw string. parse_escrow_id tolerates
    # surrounding space and upper case, so echoing the input back hands a caller who is string
    # comparing this field against their ticket a spurious mismatch.
    escrow_id_norm = eid.hex()
    client = Client(rpc_url)
    prog = program_id()
    pda = escrow_pda(prog, eid)
    info = client.get_account_info(pda, commitment=Confirmed).value
    if info is None:
        return {"escrow_id": escrow_id_norm, "pda": str(pda), "open": False, "is_escrow": False,
                "beneficiary_verified": None, "note": "settled or never opened"}
    data = bytes(info.data)
    owner = getattr(info, "owner", None)
    out = {"escrow_id": escrow_id_norm, "pda": str(pda), "open": False, "is_escrow": False,
           "lamports": info.lamports, "account_owner": None if owner is None else str(owner),
           "beneficiary_verified": None, "commitment": None}

    if owner is None or str(owner) != str(prog):
        out["verdict"] = (
            f"NOT AN ESCROW — the account at {pda} is owned by "
            f"{'no program the RPC would name' if owner is None else str(owner)}, not the "
            f"settlement program {prog}. Its contents are NOT this program's state, so no "
            "depositor, amount or commitment is read out of them. Anyone can put an account at a "
            "known address; only the program can put escrow state in one.")
        return out
    if len(data) != STATE_LEN:
        out["verdict"] = (f"UNKNOWN ACCOUNT — {len(data)} bytes at this address, which is not a "
                          f"settlement escrow ({STATE_LEN} expected). Treat it as unrelated, not "
                          "as yours.")
        return out

    out["open"] = True
    out["is_escrow"] = True
    out["depositor"] = str(Pubkey.from_bytes(data[0:32]))
    out["amount_lamports"] = struct.unpack("<Q", data[32:40])[0]
    out["commitment"] = data[40:72].hex()
    if expect_commitment_hex is None:
        out["verdict"] = UNVERIFIED_NOTE
        return out
    expected = str(expect_commitment_hex).strip().lower()
    out["expected_commitment"] = expected
    out["beneficiary_verified"] = (expected == out["commitment"])
    out["verdict"] = (
        "VERIFIED — the hidden beneficiary of this escrow is the wallet you named."
        if out["beneficiary_verified"] else
        "MISMATCH — this escrow DOES NOT pay the wallet you named. Its on-chain commitment is for "
        "someone else, so the id you were given is not a settlement you can claim. Do not treat "
        "it as money owed to you, and do not release anything in exchange for it."
    )
    return out
