"""TRANSACTION GUARD — decode a server-built transaction before signing it.

`xete_alias_claim` receives a transaction BUILT AND CO-SIGNED BY THE PERMIT SERVER and
adds this agent's signature as the fee payer. Signing bytes you have not decoded is
signing a blank cheque: an adversarial audit demonstrated that a full-balance
SystemProgram transfer, served in place of the alias claim, was signed and submitted
without a single check.

`inspect_alias_claim` is the allow-list that closes that. It answers one question —
"is this, positively, the alias claim I asked for, and nothing else?" — and refuses
everything it cannot answer yes to.

WHY AN ALLOW-LIST AND NOT A BLOCK-LIST
The obvious version of this check ("no unexpected programs") is what draft.py's
verify_draft does, and it is not enough: it asks WHICH programs are touched, not WHAT
they do, so a SystemProgram transfer — SystemProgram being an expected participant in
almost any transaction — sails through. Here every instruction must be decoded to a
named, bounded operation. An unrecognised System instruction, an unrecognised program,
an undecodable instruction: all rejections, not warnings.

THE SHAPE OF A REAL CLAIM (read off mainnet, not guessed)
Every claim the registry has ever accepted — all 11 in the program's history at the
time of writing — has exactly this shape, and the checks below pin all of it:

    instruction data:  02 | u8 name_len | name | 32-byte record key | u64 price (LE)
    accounts (6, positional):
        0  payer            = us, signer, writable
        1  claim authority  = a required signer of the transaction (the permit co-sign)
        2  alias PDA        = find_program_address(["alias", name]), writable
        3  config PDA       = find_program_address(["config"])
        4  treasury         = where the price lands
        5  SystemProgram

The price is moved by an INNER (CPI) System transfer payer -> treasury, and the PDA
rent by an inner CreateAccount. A genuine claim therefore contains ZERO top-level
System instructions, and the earlier version of this module — which read no
discriminator and summed only top-level transfers — computed a "visible debit" of
10,000 lamports (the fee) on every real claim while a `u64` in the data moved three
SOL. That is the hole this version closes: the discriminator is pinned to 0x02, the
name bytes are compared against the name the USER typed, the trailing u64 must EQUAL
the quoted price, and the account POSITIONS are checked rather than merely "our
wallet appears somewhere in the list".

WHAT IS CHECKED
  * legacy transaction only — a v0 message with address lookup tables hides which
    accounts an instruction really touches, so it is refused outright;
  * the fee payer is us, appears exactly once, and our signature slot is still empty;
  * every other required signer has ALREADY signed (the permit server co-signature),
    so we are not the missing piece of some other party's transaction;
  * exactly one alias-registry instruction, it is discriminator 0x02 (claim) and
    nothing else, it names the name we asked for IN ITS DATA — the ONE canonical byte
    string, not a family of spellings — its trailing price u64 equals the price we were
    quoted, its 32-byte record key is the agent_id THIS agent owns, and its six accounts
    are in the positions a claim puts them in — including the treasury the money
    lands in;
  * NO top-level SystemProgram instruction of any kind. A real claim has none, so
    permitting one buys zero compatibility and costs an unrestricted transfer to an
    address of the server's choosing. Transfer, CreateAccount, Assign, the nonce
    family: all refused, each with the reason it is dangerous;
  * AdvanceNonceAccount is refused anywhere in the transaction. That is the complete
    fix for durable nonces: a durable-nonce transaction is only valid if its FIRST
    instruction advances the nonce, so refusing the instruction refuses the
    construction, and what we sign therefore expires with the blockhash instead of
    sitting in someone's pocket indefinitely;
  * compute-budget instructions are decoded and the worst-case PRIORITY FEE they
    authorise is computed and counted. SetComputeUnitPrice is a lamport-draining
    instruction wearing a harmless-looking hat: price is in micro-lamports per compute
    unit, so an unbounded price times a 1.4M compute-unit limit empties a wallet
    without a single "transfer" appearing anywhere. That fee is ALSO bounded on its
    own, not merely counted towards the price tolerance: a fee is not rent, simulation
    cannot see it (simulateTransaction charges no fees), and every real claim on
    mainnet paid exactly 10,000 lamports with no compute-budget instruction at all;
  * the total this transaction can debit from us — the claim price the data itself
    declares, plus the worst-case fee — is bounded by the quoted price plus a
    tolerance.

WHERE THE TREASURY COMES FROM
It is `config.names_wallet` — bytes 64..96 of the registry's config PDA — read from
chain, NOT a constant in this file. An earlier version pinned a hardcoded address and
justified it with "the config account does not carry a treasury field". That was simply
wrong: the account is `admin(32) | permit_authority(32) | names_wallet(32) | bump(1)`,
the program rejects any other account in slot 4 (mainnet simulateTransaction:
`InstructionError InvalidArgument` for the old address, `err: None` for
`config.names_wallet`), and the value was rotated on 2026-07-30 — so the constant
turned the guard into a total outage of `xete_alias_claim` rather than a protection.
`XETE_ALIAS_TREASURY` remains as an explicit override and is how offline tests pin.

WHAT STATIC DECODING CANNOT SEE
The PDA rent is funded by a cross-program invocation and is not visible in the
instruction list. `simulated_debit()` closes that gap by asking an RPC node what the
transaction actually does to our balance. Simulation is MANDATORY by default on this
path (`bounded_simulated_debit`): an RPC that 429s is not evidence of safety, and the
public endpoint 429s routinely. If an operator explicitly turns the requirement off,
`spend_charge()` charges the spend limits the full CEILING rather than the static
figure, so the unsimulated path can never look cheaper than the simulated one.

SIGNING IS OWNED BY THIS MODULE
`approve_and_sign()` refuses to put a signature on any message whose bytes are not the
exact bytes `inspect_alias_claim` returned. `xete_alias_claim` signs the transaction
with a raw `Keypair.from_seed(ident.ed_seed)` — the guarded wrapper in signguard
cannot cover that, because a serialized Solana message is binary and the guard's job
is to refuse binary. So the binding is done here instead: inspected bytes, or no
signature.

THREAT MODEL, STATED PLAINLY
The alias program itself is trusted by policy: it is the product's own on-chain
registry. This module bounds what a malicious PERMIT SERVER can do; it cannot bound a
malicious alias program, which is why the program id is pinned here rather than taken
from the server. Note also that `XETE_PERMIT_URL` defaults to `XETE_SERVER_URL`, so
in the default configuration the permit server and the messaging relay are THE SAME
PARTY: "hostile relay" and "hostile permit server" are one adversary, not two.
Finally, the RPC is a single trusted party — simulation, and therefore the only view
of CPI-moved lamports, rests on one host's word.

CONFIGURATION (environment)
  XETE_ALIAS_PROGRAM                  alias registry program id. Exists for
                                      local-validator testing. Never point it at an
                                      untrusted program with a funded key.
  XETE_ALIAS_TREASURY                 override for the account a claim's price is
                                      allowed to land in. Unset (the normal case) the
                                      treasury is read from `config.names_wallet` on
                                      chain.
  XETE_ALIAS_TX_TOLERANCE_LAMPORTS    how much ABOVE the quoted price the claim
                                      transaction may debit, covering the account rent
                                      and network fees a quote excludes.
                                      default 5000000 (0.005 SOL)
  XETE_ALIAS_MAX_PRIORITY_FEE_LAMPORTS  hard ceiling on the priority fee a claim may
                                      authorise, applied independently of the price
                                      tolerance. default 100000 (0.0001 SOL); every
                                      real mainnet claim paid 0.
  XETE_ALIAS_REQUIRE_SIMULATION       0 to allow a claim to proceed when the RPC could
                                      not answer — simulation, and the config read that
                                      supplies the treasury. Default 1 (fail closed).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import math
import os
import string
import struct
from dataclasses import dataclass, field

from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import Transaction

SYSTEM_PROGRAM = Pubkey.from_string("11111111111111111111111111111111")
COMPUTE_BUDGET = Pubkey.from_string("ComputeBudget111111111111111111111111111111")

# The live %alias registry. Hardcoded so a compromised permit server cannot redirect
# the claim at a program of its choosing.
MAINNET_ALIAS_PROGRAM = "AXTREGuYbpgcWFbZy124jcWDN2nd7mtmrCDsUojktZrd"

# The registry's config account: admin(32) | permit_authority(32) | names_wallet(32) |
# bump(1). `names_wallet` is the treasury — the ONLY account the program will let a
# claim pay — and it is rotatable by the admin (it was rotated on 2026-07-30). It is
# therefore READ, never hardcoded. Offsets mirror xete-alias-client's config_layout.
CONFIG_ACCOUNT_LEN = 97
CONFIG_NAMES_WALLET_OFFSET = 64

ENV_ALIAS_PROGRAM = "XETE_ALIAS_PROGRAM"
ENV_TREASURY = "XETE_ALIAS_TREASURY"
ENV_TOLERANCE = "XETE_ALIAS_TX_TOLERANCE_LAMPORTS"
ENV_MAX_PRIORITY_FEE = "XETE_ALIAS_MAX_PRIORITY_FEE_LAMPORTS"
ENV_REQUIRE_SIMULATION = "XETE_ALIAS_REQUIRE_SIMULATION"
DEFAULT_TOLERANCE_LAMPORTS = 5_000_000   # 0.005 SOL — alias PDA rent is ~0.00163 SOL
# Every claim in the registry's history paid a 10,000-lamport fee (two signatures, zero
# compute-budget instructions), so this ceiling costs nothing in compatibility and takes
# away the one drain the mandatory simulation cannot see.
DEFAULT_MAX_PRIORITY_FEE_LAMPORTS = 100_000

# ── the claim instruction, as it appears on mainnet ──────────────────────────────────
# 02 | u8 name_len | name | 32-byte record key | u64 price (little-endian)
CLAIM_DISCRIMINATOR = 0x02
_CLAIM_FIXED_BYTES = 1 + 1 + 32 + 8      # disc + name_len + record key + price
MAX_ALIAS_NAME_BYTES = 32                # the on-chain record's name field is 32 bytes
# Account positions in the claim instruction. Roles, not "appears somewhere in the list".
IX_PAYER, IX_AUTHORITY, IX_ALIAS_PDA, IX_CONFIG, IX_TREASURY, IX_SYSTEM = range(6)
CLAIM_ACCOUNT_COUNT = 6

# SystemProgram instruction discriminators (u32 little-endian, first 4 bytes of data).
_SYS_CREATE_ACCOUNT = 0
_SYS_TRANSFER = 2
_SYS_ADVANCE_NONCE = 4
_SYS_NAMES = {
    0: "CreateAccount", 1: "Assign", 2: "Transfer", 3: "CreateAccountWithSeed",
    4: "AdvanceNonceAccount", 5: "WithdrawNonceAccount", 6: "InitializeNonceAccount",
    7: "AuthorizeNonceAccount", 8: "Allocate", 9: "AllocateWithSeed",
    10: "AssignWithSeed", 11: "TransferWithSeed", 12: "UpgradeNonceAccount",
}

# ComputeBudget instruction discriminators (u8, first byte of data).
_CB_REQUEST_HEAP = 1
_CB_SET_UNIT_LIMIT = 2
_CB_SET_UNIT_PRICE = 3
_CB_SET_DATA_SIZE = 4

_DEFAULT_CU_PER_IX = 200_000
_MAX_CU_LIMIT = 1_400_000
_LAMPORTS_PER_SIGNATURE = 5_000

MAX_INSTRUCTIONS = 8
MAX_ACCOUNT_KEYS = 32
MAX_IX_DATA_BYTES = 512

# Default for `inspect_alias_claim(treasury=...)`: "resolve XETE_ALIAS_TREASURY and
# nothing else". Distinct from None, which means "genuinely unpinned, and say so".
TREASURY_FROM_ENV = object()


class TransactionRejected(RuntimeError):
    """A server-supplied transaction failed inspection and was NOT signed.

    Raised before `partial_sign`, so when this is raised no signature over the
    transaction exists and nothing reached the network.
    """


# ── configuration ────────────────────────────────────────────────────────────────────

def alias_program_id() -> Pubkey:
    raw = os.environ.get(ENV_ALIAS_PROGRAM, "").strip() or MAINNET_ALIAS_PROGRAM
    try:
        return Pubkey.from_string(raw)
    except Exception as e:
        raise TransactionRejected(
            f"TRANSACTION REJECTED (bad configuration): {ENV_ALIAS_PROGRAM}={raw!r} is not a "
            f"valid Solana address ({e}). Nothing was signed."
        ) from None


def tolerance_lamports() -> int:
    raw = os.environ.get(ENV_TOLERANCE, "").strip()
    if not raw:
        return DEFAULT_TOLERANCE_LAMPORTS
    try:
        value = int(raw)
    except ValueError:
        raise TransactionRejected(
            f"TRANSACTION REJECTED (bad configuration): {ENV_TOLERANCE}={raw!r} is not a whole "
            f"number of lamports. Unset it to fall back to {DEFAULT_TOLERANCE_LAMPORTS}. "
            "Nothing was signed."
        ) from None
    if value < 0:
        raise TransactionRejected(
            f"TRANSACTION REJECTED (bad configuration): {ENV_TOLERANCE}={value} is negative. "
            "Nothing was signed."
        )
    return value


def max_priority_fee_lamports() -> int:
    raw = os.environ.get(ENV_MAX_PRIORITY_FEE, "").strip()
    if not raw:
        return DEFAULT_MAX_PRIORITY_FEE_LAMPORTS
    try:
        value = int(raw)
    except ValueError:
        raise TransactionRejected(
            f"TRANSACTION REJECTED (bad configuration): {ENV_MAX_PRIORITY_FEE}={raw!r} is not a "
            f"whole number of lamports. Unset it to fall back to "
            f"{DEFAULT_MAX_PRIORITY_FEE_LAMPORTS}. Nothing was signed."
        ) from None
    if value < 0:
        raise TransactionRejected(
            f"TRANSACTION REJECTED (bad configuration): {ENV_MAX_PRIORITY_FEE}={value} is "
            "negative. Nothing was signed."
        )
    return value


def _rpc_call(rpc_url: str, method: str, params: list, *, timeout: int = 20):
    """One JSON-RPC call, retried on transport failure. Raises RuntimeError on giving up.

    The default endpoint rate-limits, and a 429 that turned an RPC-backed check off
    would be the cheapest attack on this whole module. Retry before giving up, and when
    we do give up the caller fails closed. A node that answers with an `error` object
    has answered — that is not retried.

    EVERY MESSAGE RAISED FROM HERE IS SCRUBBED, because this function talks to `requests`
    directly rather than through `safehttp`, and `requests` writes the URL it was called
    with into its own exception text: `HTTPSConnectionPool(host=…) … with url: /qn-TOKEN/`.
    That string is re-raised, and `xete_alias_claim` reports a refusal reason WITHOUT
    truncating it — deliberately, because a refusal is the most useful thing that tool can
    say. So an operator's paid RPC credential reached the agent's context on DNS failure,
    connect timeout, TLS error, connection reset, and a 401 after a key rotation. None of
    those is an attack; they are Tuesday. Scrubbing at the raise is the only place that
    covers all of them at once, because the caller cannot know a URL is in there.
    """
    import time

    import requests

    from .safehttp import scrub

    attempts, last = 3, None
    for attempt in range(attempts):
        try:
            r = requests.post(rpc_url, json={"jsonrpc": "2.0", "id": 1, "method": method,
                                             "params": params}, timeout=timeout)
            if r.status_code in (429, 502, 503, 504):
                last = f"http {r.status_code}"
            else:
                r.raise_for_status()
                body = r.json()
                if "error" in body:                      # a real answer: do not retry it
                    raise RuntimeError(
                        f"{method} rpc error: {scrub(str(body['error']))[:200]}")
                return body["result"]
        except RuntimeError:
            raise
        except Exception as e:                           # transport-level, retryable
            last = e
        if attempt < attempts - 1:
            time.sleep(0.4 * (attempt + 1))
    raise RuntimeError(f"{method}: {scrub(str(last))}")


def read_config_names_wallet(rpc_url: str, program: Pubkey, *, timeout: int = 15) -> Pubkey:
    """Read `config.names_wallet` — the only account the program lets a claim pay.

    The config PDA is DERIVED from the pinned program id, so a hostile permit server
    cannot substitute a different config; the only party that can lie here is the RPC,
    and a lie costs it nothing but a failed transaction, because the program compares
    slot 4 against the real config itself.

    Raises RuntimeError if the account cannot be read or is not the shape the registry
    writes. The caller decides whether that is fatal.
    """
    key = config_pda(program)
    result = _rpc_call(rpc_url, "getAccountInfo",
                       [str(key), {"encoding": "base64", "commitment": "confirmed"}],
                       timeout=timeout)
    value = (result or {}).get("value")
    if not value:
        raise RuntimeError(f"the registry's config account {key} does not exist")
    if str(value.get("owner")) != str(program):
        raise RuntimeError(
            f"the registry's config account {key} is owned by {value.get('owner')}, "
            f"not {program}")
    encoded = value.get("data")
    if not isinstance(encoded, list) or not encoded:
        raise RuntimeError("getAccountInfo did not return base64 account data")
    try:
        data = base64.b64decode(encoded[0], validate=True)
    except Exception as e:
        raise RuntimeError(f"config account data is not valid base64 ({e})") from None
    if len(data) != CONFIG_ACCOUNT_LEN:
        raise RuntimeError(
            f"config account {key} is {len(data)} bytes, not the {CONFIG_ACCOUNT_LEN} the "
            "registry writes (admin | permit_authority | names_wallet | bump)")
    off = CONFIG_NAMES_WALLET_OFFSET
    return Pubkey.from_bytes(data[off:off + 32])


def treasury_pubkey(program: Pubkey, *, rpc_url: str = "", read=None) -> Pubkey | None:
    """Where a claim's price is allowed to land, or None if it cannot be known.

    Resolution order:
      1. `XETE_ALIAS_TREASURY` — an explicit operator override, and how offline tests
         and the historical-claim replay pin a value without a network.
      2. `config.names_wallet`, read from chain over `rpc_url`. This is the real
         answer: the program enforces exactly this account and the admin can rotate it.
      3. None — unpinned, and reported as such, so nothing silently pretends to have
         checked. `rpc_url=""` (offline callers) lands here.

    A chain read that FAILS is fatal when RPC checks are required (the default): the
    claim is refused rather than signed against an unknown treasury. With
    XETE_ALIAS_REQUIRE_SIMULATION=0 the operator has already said an unanswering RPC
    may not stop a claim, so it degrades to None instead.
    """
    raw = os.environ.get(ENV_TREASURY, "").strip()
    if raw:
        try:
            return Pubkey.from_string(raw)
        except Exception as e:
            raise TransactionRejected(
                f"TRANSACTION REJECTED (bad configuration): {ENV_TREASURY}={raw!r} is not a "
                f"valid Solana address ({e}). Nothing was signed."
            ) from None
    if not rpc_url:
        return None
    try:
        return (read or read_config_names_wallet)(rpc_url, program)
    except Exception as e:
        if simulation_required():
            raise TransactionRejected(
                f"TRANSACTION REJECTED: the registry's config account could not be read "
                f"({str(e)[:200]}), so the account this claim is allowed to pay is unknown. "
                "The treasury is config.names_wallet, it is rotatable, and guessing it is how "
                "this client once refused every claim the live program would accept. Point "
                f"XETE_RPC_URL at a working node and retry, set {ENV_TREASURY} if you know the "
                f"current treasury, or set {ENV_REQUIRE_SIMULATION}=0 to proceed with the "
                "treasury unpinned. Nothing was signed."
            ) from None
        return None


def treasury_for_claim(rpc_url: str, program: Pubkey | None = None) -> Pubkey | None:
    """The treasury to hand `inspect_alias_claim`. One `getAccountInfo`, or the env pin."""
    return treasury_pubkey(program or alias_program_id(), rpc_url=rpc_url)


def simulation_required() -> bool:
    """Whether a claim may proceed when the RPC could not simulate it. Default: no.

    An RPC error is not evidence of safety. Simulation is the ONLY check that sees the
    lamports the alias program moves by CPI, and the default endpoint rate-limits, so
    "best effort" here means "off, on a busy afternoon".
    """
    raw = os.environ.get(ENV_REQUIRE_SIMULATION, "").strip().lower()
    if raw in ("", "1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise TransactionRejected(
        f"TRANSACTION REJECTED (bad configuration): {ENV_REQUIRE_SIMULATION}={raw!r} is not a "
        "boolean. Unset it to fail closed (the default). Nothing was signed."
    )


def alias_pda(program: Pubkey, name: str | bytes) -> Pubkey:
    """PDA of a %name in the registry — same derivation the relay resolves with."""
    seed = name if isinstance(name, bytes) else name.encode("utf-8")
    return Pubkey.find_program_address([b"alias", seed], program)[0]


def config_pda(program: Pubkey) -> Pubkey:
    """The registry's config account. Derived, not hardcoded, so it follows the program
    id and cannot be substituted by the server."""
    return Pubkey.find_program_address([b"config"], program)[0]


# A registrable name, exactly as xete-alias-client::valid_name defines it: 1..32 bytes
# of lowercase ASCII, digits and underscore. The PROGRAM enforces this (mainnet
# simulateTransaction: b'ZzAtkprobe3', b'%zzatkprobe2' and b'zz atk4' all come back
# InvalidInstructionData), so a claim of anything else can only ever burn a fee.
_NAME_CHARS = frozenset(string.ascii_lowercase + string.digits + "_")


def canonical_name(name: str) -> str:
    """THE one byte string a claim may register. Not a family of spellings.

    Identical to `alias_chain.normalize_name` (`strip().lstrip('%').strip().lower()`),
    which is what the resolver reads, and a superset of the permit server's own
    `xete_alias_client::normalize_name` (`trim().to_ascii_lowercase()`) for the inputs
    the server accepts at all.

    The previous version accepted a SET of candidate spellings. A hostile server picked
    whichever member it liked, derived the PDA from that, and every other check then
    agreed with itself: the user paid to register `%mcptestname` or `Mcptestname` at an
    address no resolver will ever look at. Only one of those strings is the name.
    """
    if not isinstance(name, str):
        raise TransactionRejected(
            f"TRANSACTION REJECTED: a %name must be text, got {type(name).__name__}. "
            "Nothing was signed."
        )
    return name.strip().lstrip("%").strip().lower()


def _registrable_name_bytes(name: str) -> bytes:
    """The canonical form of `name` as bytes, or a refusal if it is not registrable."""
    canonical = canonical_name(name)
    encoded = canonical.encode("utf-8")
    if not 1 <= len(encoded) <= MAX_ALIAS_NAME_BYTES:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: {_safe_text(name, alphabet=_SAFE_ARG_CHARS)} is not a claimable "
            f"%name — its canonical "
            f"form is {len(encoded)} bytes and the registry holds 1..{MAX_ALIAS_NAME_BYTES}. "
            "Nothing was signed."
        )
    if not all(chr(b) in _NAME_CHARS for b in encoded):
        raise TransactionRejected(
            f"TRANSACTION REJECTED: {_safe_text(name, alphabet=_SAFE_ARG_CHARS)} is not a claimable "
            f"%name — the registry "
            "accepts lowercase letters, digits and underscore only, and rejects anything else "
            "on chain, so this claim could do nothing but burn a fee. Nothing was signed."
        )
    return encoded


# The alphabet a registry NAME is allowed to use. Anything a server puts in that field
# outside this set is not a name, so it does not need to stay legible — it gets escaped.
_SAFE_NAME_CHARS = frozenset(string.ascii_lowercase + string.digits + "_")
# Looser, for echoing back the CALLER's own argument, where legibility is the point.
_SAFE_ARG_CHARS = frozenset(string.ascii_letters + string.digits + " _-.%@")


def _safe_text(raw: bytes | str, *, limit: int = 32, alphabet=_SAFE_NAME_CHARS) -> str:
    """Render SERVER-CHOSEN bytes safe to put in a message an agent will read.

    A refusal reason is deliberately not truncated — it is the most useful thing this
    tool can say — which made it a channel: up to 32 bytes of attacker-chosen text,
    newlines included, were decoded with errors='replace' and echoed verbatim into the
    `reason` field an agent then reads as instructions.

    Sanitising where the bytes ENTER the message keeps the refusal complete while making
    the server's share of it one quoted, length-bounded, control-character-free token
    that reads as data. For the name field the alphabet is the registry's own
    (`[a-z0-9_]`), so prose does not survive the trip at all.
    """
    b = raw.encode("utf-8", "replace") if isinstance(raw, str) else bytes(raw)
    head, extra = b[:limit], len(b) - limit
    shown = "".join(chr(c) if chr(c) in alphabet else f"\\x{c:02x}" for c in head)
    return f'"{shown}"' + (f" (+{extra} more bytes)" if extra > 0 else "")


# ── raw framing checks (done before handing bytes to a parser) ───────────────────────

def _read_shortvec(buf: bytes, offset: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if offset >= len(buf):
            raise TransactionRejected(
                "TRANSACTION REJECTED: the transaction bytes end inside a length prefix — "
                "this is not a well-formed Solana transaction. Nothing was signed."
            )
        byte = buf[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift > 21:
            raise TransactionRejected(
                "TRANSACTION REJECTED: malformed length prefix in the transaction bytes. "
                "Nothing was signed."
            )


def _reject_versioned(raw: bytes) -> None:
    """Refuse a v0 (or later) message.

    A versioned message can load accounts from an address lookup table, so the account
    an instruction touches is not in the bytes at all — it is a pointer into a table
    the server also controls. Every check in this module reads account_keys, so a
    versioned transaction would let a server satisfy the checks and touch something
    else. The permit server has never needed one.
    """
    count, offset = _read_shortvec(raw, 0)
    offset += 64 * count
    if offset >= len(raw):
        raise TransactionRejected(
            "TRANSACTION REJECTED: the transaction bytes end before the message begins. "
            "Nothing was signed."
        )
    if raw[offset] & 0x80:
        version = raw[offset] & 0x7F
        raise TransactionRejected(
            f"TRANSACTION REJECTED: this is a v{version} (versioned) transaction. Versioned "
            "messages can resolve accounts through an address lookup table the server also "
            "controls, so what an instruction actually touches cannot be read from the bytes. "
            "The alias claim does not need one. Nothing was signed."
        )


# ── message helpers ──────────────────────────────────────────────────────────────────

def _is_writable(index: int, header, n_keys: int) -> bool:
    nsig = header.num_required_signatures
    if index < nsig:
        return index < nsig - header.num_readonly_signed_accounts
    return index < n_keys - header.num_readonly_unsigned_accounts


@dataclass(frozen=True)
class ClaimInspection:
    """What the transaction was positively identified as. Returned only on success."""
    fee_payer: str
    required_signers: list[str]
    alias_program: str
    alias_pda: str
    claim_name: str = ""
    claim_price_lamports: int = 0
    record_key: str = ""
    record_key_pinned: bool = False
    treasury: str = ""
    treasury_pinned: bool = False
    message_sha256: str = ""
    instructions: list[dict] = field(default_factory=list)
    transfers: list[dict] = field(default_factory=list)
    priority_fee_lamports: int = 0
    worst_case_fee_lamports: int = 0
    static_debit_lamports: int = 0
    ceiling_lamports: int = 0

    def as_dict(self) -> dict:
        return {
            "fee_payer": self.fee_payer,
            "required_signers": self.required_signers,
            "alias_program": self.alias_program,
            "alias_pda": self.alias_pda,
            "claim_name": self.claim_name,
            "claim_price_lamports": self.claim_price_lamports,
            "record_key": self.record_key,
            "record_key_pinned": self.record_key_pinned,
            "treasury": self.treasury,
            "treasury_pinned": self.treasury_pinned,
            "message_sha256": self.message_sha256,
            "instructions": self.instructions,
            "transfers": self.transfers,
            "priority_fee_lamports": self.priority_fee_lamports,
            "worst_case_fee_lamports": self.worst_case_fee_lamports,
            "static_debit_lamports": self.static_debit_lamports,
            "ceiling_lamports": self.ceiling_lamports,
        }


def _decode_claim_data(data: bytes, *, position: int, expected_names: set[bytes],
                       expect_name: str, quoted_lamports: int,
                       expect_record_key: bytes | None = None) -> tuple[bytes, int, bytes]:
    """Decode ONE alias-registry instruction as a claim, or refuse.

    `02 | u8 name_len | name | 32-byte record key | u64 price`. Every field is checked
    against something known before the server was contacted: the discriminator against
    the constant, the name against what the user typed, the price against the quote.
    """
    if not data:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the alias-registry instruction at {position} has no data, so "
            "it is not a claim. Nothing was signed."
        )
    if data[0] != CLAIM_DISCRIMINATOR:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the alias-registry instruction at {position} is operation "
            f"0x{data[0]:02x}, not the claim operation 0x{CLAIM_DISCRIMINATOR:02x}. The registry "
            "exposes several operations — transferring a name away, rewriting a record, "
            "administrative calls — and this client signs exactly one of them. 'A call to the "
            "right program' is not 'the claim you asked for'. Nothing was signed."
        )
    if len(data) < 2:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the claim instruction at {position} is {len(data)} byte(s), "
            "too short to carry a name. Nothing was signed."
        )
    name_len = data[1]
    if not 1 <= name_len <= MAX_ALIAS_NAME_BYTES:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the claim instruction declares a {name_len}-byte name; the "
            f"registry's name field holds 1..{MAX_ALIAS_NAME_BYTES}. Nothing was signed."
        )
    expected_len = _CLAIM_FIXED_BYTES + name_len
    if len(data) != expected_len:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the claim instruction at {position} is {len(data)} bytes; a "
            f"claim of a {name_len}-byte name is exactly {expected_len} "
            f"(02 | name_len | name | 32-byte record key | u64 price). Trailing bytes are room "
            "for a field this client does not understand. Nothing was signed."
        )
    name_bytes = data[2:2 + name_len]
    if name_bytes not in expected_names:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the claim instruction registers the name "
            f"{_safe_text(name_bytes)}, but the canonical form of the name you asked to claim is "
            f"%{expect_name}. Exactly one byte string is the name — a different spelling is a "
            "different address, which no resolver will ever read. This check reads the name out "
            "of the instruction DATA rather than inferring it from an account. Nothing was "
            "signed."
        )
    key32 = data[2 + name_len:2 + name_len + 32]
    if expect_record_key is not None and not hmac.compare_digest(key32, bytes(expect_record_key)):
        # This 32-byte field is the on-chain agent_id (permit cosign.rs: ClaimParts
        # .agent_id -> wire::data_claim). The permit server's own rule is that a claim
        # may bind ONLY the agent_id the authenticated wallet owns — and the permit
        # server is the party this module exists to distrust, while the program does
        # not validate the field at all (mainnet simulateTransaction with 0xAB*32
        # returns err: None). Unpinned, %name -> {owner, agent_id} is forgeable to
        # point at somebody else's agent, paid for and signed by us.
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the claim would bind %{expect_name} to agent id "
            f"{Pubkey.from_bytes(key32)}, not this agent's "
            f"{Pubkey.from_bytes(bytes(expect_record_key))}. That 32-byte field is the "
            "on-chain agent identity the name resolves to, nothing on chain checks it, and "
            "writing someone else's there is exactly the impersonation the registry's design "
            "forbids — at our expense and under our signature. Nothing was signed."
        )
    price = struct.unpack("<Q", data[-8:])[0]
    if price != quoted_lamports:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the claim instruction will move {price} lamports, but the "
            f"price quoted for %{expect_name} was {quoted_lamports}. The registry moves the price "
            "by a program call, so it never shows up as a transfer in the instruction list — this "
            "u64 inside the instruction data is the only place it is visible before signing, and "
            "it must equal what we were told we would pay. Nothing was signed."
        )
    return name_bytes, price, key32


def _check_claim_accounts(indexes, accounts, *, header, n_keys: int, position: int,
                          expect_fee_payer: Pubkey, program: Pubkey,
                          treasury: Pubkey | None, claim_name: bytes, nsig: int) -> Pubkey:
    """Pin the claim's accounts by POSITION. Returns the alias PDA.

    `expect_fee_payer in accounts` proves presence, not role: it is satisfied by a
    transaction that names our wallet as a bystander while registering the name to
    someone else. Positions are the role.
    """
    if len(accounts) != CLAIM_ACCOUNT_COUNT:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the claim instruction at {position} names {len(accounts)} "
            f"accounts; a claim names exactly {CLAIM_ACCOUNT_COUNT} (payer, claim authority, "
            "alias account, config, treasury, System). Nothing was signed."
        )
    if accounts[IX_PAYER] != expect_fee_payer or indexes[IX_PAYER] != 0:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the claim instruction's payer slot holds "
            f"{accounts[IX_PAYER]}, not this agent's wallet {expect_fee_payer}. The registry "
            "writes the payer in as the owner, so a claim that does not put us there is a claim "
            "we would pay for and someone else would own. Nothing was signed."
        )
    if not _is_writable(indexes[IX_PAYER], header, n_keys):
        raise TransactionRejected(
            "TRANSACTION REJECTED: the claim instruction marks this agent's wallet read-only, so "
            "it cannot be the account being registered. Nothing was signed."
        )
    if indexes[IX_AUTHORITY] >= nsig:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the claim authority slot holds {accounts[IX_AUTHORITY]}, "
            "which is not a required signer of this transaction. A claim is authorised by the "
            "permit server's co-signature; without one, nothing has approved this but us. "
            "Nothing was signed."
        )
    # Derived from the NAME BYTES that were matched, never from a decoded-and-re-encoded
    # string, so no round-trip can change what the PDA is checked against.
    shown = _safe_text(claim_name)
    want_pda = alias_pda(program, claim_name)
    if accounts[IX_ALIAS_PDA] != want_pda:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the claim instruction writes account "
            f"{accounts[IX_ALIAS_PDA]}, but the registry account for the name {shown} is "
            f"{want_pda}. Nothing was signed."
        )
    if not _is_writable(indexes[IX_ALIAS_PDA], header, n_keys):
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the account for the name {shown} ({want_pda}) is read-only in "
            "this transaction, so the claim cannot be what it writes. Nothing was signed."
        )
    want_config = config_pda(program)
    if accounts[IX_CONFIG] != want_config:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the claim instruction's config slot holds "
            f"{accounts[IX_CONFIG]}, not the registry's config account {want_config}. "
            "Nothing was signed."
        )
    if treasury is not None and accounts[IX_TREASURY] != treasury:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the claim would pay {accounts[IX_TREASURY]}, not the xete "
            f"treasury {treasury}. The price is moved by a program call to whatever sits in this "
            "slot, so this is where a hostile permit server points the money at itself. Set "
            f"{ENV_TREASURY} only if the registry's treasury has genuinely moved. "
            "Nothing was signed."
        )
    if accounts[IX_SYSTEM] != SYSTEM_PROGRAM:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the claim instruction's System-program slot holds "
            f"{accounts[IX_SYSTEM]}. Nothing was signed."
        )
    return want_pda


def inspect_alias_claim(tx_b64: str, *, expect_fee_payer: Pubkey, expect_name: str,
                        quoted_lamports: int, program: Pubkey | None = None,
                        tolerance: int | None = None,
                        blockhash_is_live: bool | None = None,
                        expect_record_key: bytes | None = None,
                        treasury: Pubkey | None | object = TREASURY_FROM_ENV,
                        ) -> tuple[Transaction, ClaimInspection]:
    """Decode and allow-list a permit-server alias-claim transaction.

    Returns (parsed transaction, inspection) if and only if every check passes. Raises
    TransactionRejected otherwise — at which point nothing has been signed.

    Every expectation is supplied by the CALLER from values it knew before it talked to
    the server: our own wallet, the name the user typed, the price we were quoted, the
    agent_id we own, the treasury the registry's config names.

    This function does NO network I/O, so the treasury has to be handed in. Callers that
    can reach an RPC pass `treasury=treasury_pubkey(program, rpc_url=...)`; leaving it at
    the default resolves `XETE_ALIAS_TREASURY` alone and reports `treasury_pinned:false`
    when that is unset, rather than pretending a stale constant is the answer.
    """
    program = program or alias_program_id()
    if treasury is TREASURY_FROM_ENV:
        treasury = treasury_pubkey(program)
    # ONE canonical byte string, settled before a single byte of the server's answer is
    # looked at. From here on `expect_name` is that string: registrable by definition,
    # so safe to interpolate into a message, and the only spelling a claim may register.
    want_name = _registrable_name_bytes(expect_name)
    expect_name = want_name.decode("ascii")
    ceiling = int(quoted_lamports) + (tolerance_lamports() if tolerance is None else int(tolerance))

    if not isinstance(tx_b64, str) or not tx_b64:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the permit server returned no transaction "
            f"(got {type(tx_b64).__name__}). Nothing was signed."
        )
    try:
        raw = base64.b64decode(tx_b64, validate=True)
    except Exception as e:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the transaction field is not valid base64 ({e}). "
            "Nothing was signed."
        ) from None

    _reject_versioned(raw)

    try:
        tx = Transaction.from_bytes(raw)
    except Exception as e:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the bytes do not deserialize as a Solana transaction "
            f"({str(e)[:200]}). Nothing was signed."
        ) from None

    msg = tx.message
    header = msg.header
    keys = list(msg.account_keys)
    nsig = header.num_required_signatures

    if len(keys) > MAX_ACCOUNT_KEYS:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: {len(keys)} accounts, over the {MAX_ACCOUNT_KEYS} an alias "
            "claim can need. Nothing was signed."
        )
    if not msg.instructions:
        raise TransactionRejected(
            "TRANSACTION REJECTED: the transaction contains no instructions. Nothing was signed."
        )
    if len(msg.instructions) > MAX_INSTRUCTIONS:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: {len(msg.instructions)} instructions, over the "
            f"{MAX_INSTRUCTIONS} an alias claim can need. Nothing was signed."
        )

    # ── who signs ────────────────────────────────────────────────────────────────────
    if not keys or keys[0] != expect_fee_payer:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the fee payer is {keys[0] if keys else '<none>'}, not this "
            f"agent's wallet {expect_fee_payer}. We only pay for our own claim. Nothing was signed."
        )
    if keys.count(expect_fee_payer) != 1:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: this agent's wallet {expect_fee_payer} appears "
            f"{keys.count(expect_fee_payer)} times in the account list. Nothing was signed."
        )
    if not 1 <= nsig <= 2:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the transaction requires {nsig} signatures. An alias claim "
            "needs this agent alone, or this agent plus the permit co-signer. Nothing was signed."
        )
    if len(tx.signatures) < nsig:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: {nsig} signatures are required but only {len(tx.signatures)} "
            "slots exist. Nothing was signed."
        )
    empty = Signature.default()
    if tx.signatures[0] != empty:
        raise TransactionRejected(
            "TRANSACTION REJECTED: our own signature slot already carries a signature we did not "
            "make. Nothing was signed."
        )
    for i in range(1, nsig):
        if tx.signatures[i] == empty:
            raise TransactionRejected(
                f"TRANSACTION REJECTED: required signer {keys[i]} has not signed. The permit "
                "server co-signs before handing the transaction over; an unsigned second slot "
                "means this is not that transaction, and our signature would be the only one on "
                "it. Nothing was signed."
            )

    # ── what runs ────────────────────────────────────────────────────────────────────
    expected_names = {want_name}
    described: list[dict] = []
    transfers: list[dict] = []
    debit = 0
    alias_ix_count = 0
    matched_pda = None
    claim_name = ""
    claim_price = 0
    record_key = ""
    declared_cu_limit: int | None = None
    cu_price_micro = 0
    non_budget_ix = 0
    seen_cb_tags: set[int] = set()

    for position, cix in enumerate(msg.instructions):
        if cix.program_id_index >= len(keys):
            raise TransactionRejected(
                f"TRANSACTION REJECTED: instruction {position} names program index "
                f"{cix.program_id_index}, past the end of the account list. Nothing was signed."
            )
        prog = keys[cix.program_id_index]
        data = bytes(cix.data)
        if len(data) > MAX_IX_DATA_BYTES:
            raise TransactionRejected(
                f"TRANSACTION REJECTED: instruction {position} carries {len(data)} bytes of data, "
                f"over the {MAX_IX_DATA_BYTES}-byte limit. Nothing was signed."
            )
        for idx in cix.accounts:
            if idx >= len(keys):
                raise TransactionRejected(
                    f"TRANSACTION REJECTED: instruction {position} names account index {idx}, past "
                    "the end of the account list. Nothing was signed."
                )
        accounts = [keys[i] for i in cix.accounts]

        if prog == program:
            non_budget_ix += 1
            alias_ix_count += 1
            if alias_ix_count > 1:
                raise TransactionRejected(
                    "TRANSACTION REJECTED: more than one alias-registry instruction. A claim is "
                    "one registry call; a second one is a second name being written with our "
                    "signature. Nothing was signed."
                )
            name_bytes, claim_price, key32 = _decode_claim_data(
                data, position=position, expected_names=expected_names,
                expect_name=expect_name, quoted_lamports=int(quoted_lamports),
                expect_record_key=expect_record_key)
            record_key = str(Pubkey.from_bytes(key32))
            pda = _check_claim_accounts(
                cix.accounts, accounts, header=header, n_keys=len(keys), position=position,
                expect_fee_payer=expect_fee_payer, program=program, treasury=treasury,
                claim_name=name_bytes, nsig=nsig)
            claim_name = name_bytes.decode("utf-8", "replace")
            # The price is moved by a CPI System transfer payer -> treasury, so it never
            # appears as a top-level instruction. Counting it here is what makes
            # static_debit_lamports describe a real claim instead of just its fee.
            debit += claim_price
            matched_pda = str(pda)
            described.append({"position": position, "program": "alias-registry",
                              "op": "Claim", "discriminator": CLAIM_DISCRIMINATOR,
                              "name": claim_name, "price_lamports": claim_price,
                              "pda": matched_pda, "treasury": str(accounts[IX_TREASURY]),
                              "data_len": len(data)})
            transfers.append({"position": position, "via": "cpi",
                              "from": str(expect_fee_payer),
                              "to": str(accounts[IX_TREASURY]), "lamports": claim_price})

        elif prog == COMPUTE_BUDGET:
            if accounts:
                raise TransactionRejected(
                    f"TRANSACTION REJECTED: compute-budget instruction {position} names "
                    f"{len(accounts)} account(s); it must name none. Nothing was signed."
                )
            if not data:
                raise TransactionRejected(
                    f"TRANSACTION REJECTED: empty compute-budget instruction at {position}. "
                    "Nothing was signed."
                )
            tag = data[0]
            # Solana itself rejects a duplicated compute-budget op, but "the runtime
            # would have caught it" is not a reason for the guard to have to guess WHICH
            # of two SetComputeUnitPrice values it is bounding.
            if tag in seen_cb_tags:
                raise TransactionRejected(
                    f"TRANSACTION REJECTED: compute-budget operation {tag} appears twice "
                    f"(instruction {position}). Nothing was signed."
                )
            seen_cb_tags.add(tag)
            if tag == _CB_SET_UNIT_LIMIT and len(data) == 5:
                declared_cu_limit = struct.unpack("<I", data[1:5])[0]
                described.append({"position": position, "program": "compute-budget",
                                  "op": "SetComputeUnitLimit", "units": declared_cu_limit})
            elif tag == _CB_SET_UNIT_PRICE and len(data) == 9:
                cu_price_micro = struct.unpack("<Q", data[1:9])[0]
                described.append({"position": position, "program": "compute-budget",
                                  "op": "SetComputeUnitPrice", "micro_lamports_per_cu": cu_price_micro})
            elif tag in (_CB_REQUEST_HEAP, _CB_SET_DATA_SIZE) and len(data) == 5:
                described.append({"position": position, "program": "compute-budget",
                                  "op": "RequestHeapFrame" if tag == _CB_REQUEST_HEAP
                                        else "SetLoadedAccountsDataSizeLimit",
                                  "value": struct.unpack("<I", data[1:5])[0]})
            else:
                raise TransactionRejected(
                    f"TRANSACTION REJECTED: compute-budget instruction {position} is not one this "
                    f"client recognises (tag {tag}, {len(data)} bytes). Nothing was signed."
                )

        elif prog == SYSTEM_PROGRAM:
            non_budget_ix += 1
            if len(data) < 4:
                raise TransactionRejected(
                    f"TRANSACTION REJECTED: SystemProgram instruction {position} is {len(data)} "
                    "bytes, too short to name an operation. Nothing was signed."
                )
            tag = struct.unpack("<I", data[:4])[0]
            name = _SYS_NAMES.get(tag, f"unknown({tag})")

            if tag == _SYS_ADVANCE_NONCE:
                raise TransactionRejected(
                    "TRANSACTION REJECTED: the transaction advances a durable nonce. A durable "
                    "nonce transaction does not expire with the blockhash — a signature given for "
                    "it can be held and submitted at any future moment, at whatever balance the "
                    "wallet holds then. The alias claim has no need of one. Nothing was signed."
                )

            # EVERY top-level System instruction is refused. A genuine claim contains
            # none — the price and the PDA rent both move by CPI from inside the alias
            # program — so allowing one buys no compatibility whatsoever, while allowing
            # it cost an unrestricted transfer to an address of the server's choosing
            # for anything that fitted inside the price tolerance. The decoding below
            # exists only to say precisely what was refused.
            detail = ""
            if tag == _SYS_TRANSFER and len(data) == 12 and len(accounts) == 2:
                lamports = struct.unpack("<Q", data[4:12])[0]
                detail = (f" It moves {lamports} lamports from {accounts[0]} to {accounts[1]}, a "
                          "destination nothing in the quote names.")
            elif tag == _SYS_CREATE_ACCOUNT and len(data) == 52 and len(accounts) == 2:
                lamports = struct.unpack("<Q", data[4:12])[0]
                detail = (f" It funds a new account {accounts[1]} with {lamports} lamports, owned "
                          f"by {Pubkey.from_bytes(data[20:52])}.")
            elif tag in (1, 10):
                detail = (" Assign hands an account to another program without moving a single "
                          "lamport, so an amount-based check never sees it.")
            elif tag == 11:
                detail = (" TransferWithSeed moves lamports out of a derived account, which a "
                          "top-level balance check does not cover.")
            raise TransactionRejected(
                f"TRANSACTION REJECTED: SystemProgram {name} at instruction {position}. An alias "
                "claim contains NO top-level System instruction at all — the price and the "
                "account rent are both moved by the registry program itself — so this instruction "
                f"is not part of the claim you asked for.{detail} Nothing was signed."
            )

        else:
            raise TransactionRejected(
                f"TRANSACTION REJECTED: instruction {position} invokes {prog}, which is not the "
                f"alias registry ({program}), the System program or the compute budget. A claim "
                "transaction runs nothing else, and anything this client cannot positively "
                "identify is refused rather than signed. Nothing was signed."
            )

    if alias_ix_count != 1:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the transaction contains no instruction for the alias registry "
            f"{program}, so whatever it is, it is not the claim of %{expect_name}. This is exactly "
            "the shape a bare drain transaction takes. Nothing was signed."
        )

    # ── worst-case fee, including the priority fee a compute-budget price authorises ──
    cu_limit = declared_cu_limit if declared_cu_limit is not None else min(
        _DEFAULT_CU_PER_IX * max(non_budget_ix, 1), _MAX_CU_LIMIT)
    priority_fee = math.ceil(cu_limit * cu_price_micro / 1_000_000)
    fee = _LAMPORTS_PER_SIGNATURE * nsig + priority_fee
    debit += fee

    # The priority fee is bounded ON ITS OWN, not merely folded into the price
    # tolerance. Two reasons the tolerance is the wrong instrument for it: the tolerance
    # exists to cover ~0.00163 SOL of PDA rent, and simulation — the backstop that makes
    # everything else in this module survivable — CANNOT see a fee at all, because
    # simulateTransaction does not charge one. Left inside the tolerance, a hostile
    # server burns the entire allowance on a free claim and every check still passes.
    fee_cap = max_priority_fee_lamports()
    if priority_fee > fee_cap:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: this transaction authorises a priority fee of up to "
            f"{priority_fee} lamports ({cu_price_micro} micro-lamports per compute unit over "
            f"{cu_limit} units), above the {fee_cap} this client will sign for. A priority fee is "
            "burned whether or not the claim succeeds, and simulation cannot see it — "
            "simulateTransaction charges no fees — so it is bounded here or nowhere. Every claim "
            "in the registry's history paid a flat 10,000-lamport fee and carried no "
            f"compute-budget instruction at all. Raise {ENV_MAX_PRIORITY_FEE} only if you know "
            "why this one needs to be different. Nothing was signed."
        )

    if debit > ceiling:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: this transaction visibly debits {debit} lamports from "
            f"{expect_fee_payer} (the {claim_price}-lamport price the claim instruction itself "
            f"declares plus a worst-case fee of {fee}, of which "
            f"{priority_fee} is priority fee at {cu_price_micro} micro-lamports per compute unit "
            f"over {cu_limit} units), but the quoted price was {quoted_lamports} lamports and the "
            f"most this client will sign for is {ceiling}. Raise {ENV_TOLERANCE} only if you know "
            "why the difference is legitimate. Nothing was signed."
        )

    if blockhash_is_live is False:
        raise TransactionRejected(
            "TRANSACTION REJECTED: the transaction's blockhash is not a live recent blockhash. "
            "Either it has already expired, or it is a durable nonce value that never will. "
            "Nothing was signed."
        )

    return tx, ClaimInspection(
        fee_payer=str(expect_fee_payer),
        required_signers=[str(k) for k in keys[:nsig]],
        alias_program=str(program),
        alias_pda=matched_pda or "",
        claim_name=claim_name,
        claim_price_lamports=claim_price,
        record_key=record_key,
        record_key_pinned=expect_record_key is not None,
        treasury=str(treasury) if treasury is not None else "",
        treasury_pinned=treasury is not None,
        message_sha256=hashlib.sha256(bytes(msg)).hexdigest(),
        instructions=described,
        transfers=transfers,
        priority_fee_lamports=priority_fee,
        worst_case_fee_lamports=fee,
        static_debit_lamports=debit,
        ceiling_lamports=ceiling,
    )


# ── what the transaction ACTUALLY moves (the part static decoding cannot see) ────────

def check_debit_within(pre_lamports: int, post_lamports: int, ceiling: int, *,
                       who: str = "this wallet") -> int:
    """Bound a measured balance change. Returns the debit; raises if it exceeds `ceiling`."""
    debit = int(pre_lamports) - int(post_lamports)
    if debit > ceiling:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: simulating this transaction takes {debit} lamports from "
            f"{who}, above the {ceiling} lamports the quoted price and tolerance allow. Static "
            "decoding did not show this, which means the movement happens inside a program call. "
            "Nothing was signed."
        )
    return debit


def simulated_debit(rpc_url: str, tx_b64: str, account: Pubkey, *, timeout: int = 20) -> int:
    """Ask an RPC node what this transaction does to `account`'s balance, in lamports.

    This is the only check that sees lamports moved by a cross-program invocation. It
    runs BEFORE our signature exists (`sigVerify: false`).

    Raises TransactionRejected if the node reports the transaction would fail — a
    transaction that fails simulation should not be signed and submitted, it would only
    burn a fee. Raises RuntimeError if the node could not be reached or answered in a
    shape we do not understand; the caller decides what to do with that, because a
    flaky RPC is not evidence of an attack.
    """
    def call(method: str, params: list):
        return _rpc_call(rpc_url, method, params, timeout=timeout)

    pre = call("getBalance", [str(account), {"commitment": "confirmed"}])["value"]
    sim = call("simulateTransaction", [tx_b64, {
        "sigVerify": False,
        "replaceRecentBlockhash": True,
        "commitment": "confirmed",
        "encoding": "base64",
        "accounts": {"encoding": "base64", "addresses": [str(account)]},
    }])["value"]

    if sim.get("err") is not None:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the network says this transaction fails "
            f"({_safe_text(str(sim['err']), limit=200, alphabet=_SAFE_ARG_CHARS)}). "
            "Nothing was signed."
        )
    accounts = sim.get("accounts") or []
    if not accounts or accounts[0] is None or "lamports" not in accounts[0]:
        raise RuntimeError("simulateTransaction did not return the post-balance we asked for")
    return int(pre) - int(accounts[0]["lamports"])


def bounded_simulated_debit(rpc_url: str, tx_b64: str, account: Pubkey,
                            inspection: ClaimInspection, *, who: str = "",
                            simulate=None) -> tuple[int | None, str | None]:
    """Simulate, bound the result, and FAIL CLOSED when simulation could not run.

    Returns (simulated_debit, note). `simulated_debit` is None only when the operator
    has explicitly set XETE_ALIAS_REQUIRE_SIMULATION=0; in that case `note` says so and
    `spend_charge()` charges the full ceiling instead.

    Raises TransactionRejected when the network says the transaction fails, when the
    measured debit exceeds the ceiling, or when simulation is required and did not run.
    Nothing has been signed at the point this raises.
    """
    run = simulate or simulated_debit
    who = who or str(account)
    try:
        measured = run(rpc_url, tx_b64, account)
    except TransactionRejected:
        raise
    except Exception as e:
        reason = str(e)[:200]
        if simulation_required():
            raise TransactionRejected(
                f"TRANSACTION REJECTED: this claim could not be simulated ({reason}), and "
                "simulation is the only check that sees the lamports the registry moves by "
                "program call — the instruction list shows a fee and nothing else. An RPC that "
                "will not answer is not evidence that a transaction is safe. Point XETE_RPC_URL "
                f"at a working node and retry, or set {ENV_REQUIRE_SIMULATION}=0 to accept the "
                "weaker static bound, in which case the full ceiling is charged against your "
                "spend limits. Nothing was signed."
            ) from None
        return None, (f"SIMULATION DID NOT RUN ({reason}). {ENV_REQUIRE_SIMULATION}=0 allowed the "
                      "claim to proceed on the static bound alone; the spend limits were charged "
                      f"the full ceiling of {inspection.ceiling_lamports} lamports instead of the "
                      "amount the instructions declare.")
    check_debit_within(measured, 0, inspection.ceiling_lamports, who=who)
    return measured, None


def spend_charge(quoted_lamports: int, inspection: ClaimInspection,
                 simulated: int | None) -> int:
    """What to charge the spend limits: the largest figure anyone can justify.

    When simulation did not run, that figure is the CEILING, not the static debit.
    Charging the static debit there was the bug: on a genuine claim the static debit is
    the fee alone, so an unsimulated claim looked ~200x cheaper than a simulated one and
    slipped under a cap that would have stopped it.
    """
    charge = max(int(quoted_lamports), inspection.static_debit_lamports, int(simulated or 0))
    if simulated is None:
        charge = max(charge, inspection.ceiling_lamports)
    return charge


def approve_and_sign(tx: Transaction, inspection: ClaimInspection, keypair) -> Transaction:
    """Sign ONLY the exact message `inspect_alias_claim` approved.

    `xete_alias_claim` signs with a raw `Keypair.from_seed(ident.ed_seed)`, which the
    signguard wrapper cannot cover — a serialized Solana message is binary and that
    guard's whole job is refusing binary. This is the binding that replaces it: the
    message bytes are re-hashed here and compared with the digest recorded during
    inspection, so a transaction that was swapped, mutated, or never inspected at all
    cannot reach the key.
    """
    digest = hashlib.sha256(bytes(tx.message)).hexdigest()
    if not inspection.message_sha256 or not hmac.compare_digest(digest, inspection.message_sha256):
        raise TransactionRejected(
            "TRANSACTION REJECTED: the transaction handed to the signer is not the one that was "
            f"inspected (message sha256 {digest}, approved {inspection.message_sha256 or '<none>'}"
            "). Nothing was signed."
        )
    if str(keypair.pubkey()) != inspection.fee_payer:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the signing key {keypair.pubkey()} is not the fee payer the "
            f"inspection approved ({inspection.fee_payer}). Nothing was signed."
        )
    tx.partial_sign([keypair], tx.message.recent_blockhash)
    return tx
