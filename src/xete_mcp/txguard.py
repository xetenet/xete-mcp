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
    nothing else, it names the name we asked for IN ITS DATA, its trailing price u64
    equals the price we were quoted, and its six accounts are in the positions a claim
    puts them in — including the treasury the money lands in;
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
    without a single "transfer" appearing anywhere;
  * the total this transaction can debit from us — the claim price the data itself
    declares, plus the worst-case fee — is bounded by the quoted price plus a
    tolerance.

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
  XETE_ALIAS_TREASURY                 the account a claim's price is allowed to land
                                      in. Defaults to the live mainnet treasury when
                                      the program is the live registry.
  XETE_ALIAS_TX_TOLERANCE_LAMPORTS    how much ABOVE the quoted price the claim
                                      transaction may debit, covering the account rent
                                      and network fees a quote excludes.
                                      default 5000000 (0.005 SOL)
  XETE_ALIAS_REQUIRE_SIMULATION       0 to allow a claim to proceed when the RPC could
                                      not simulate it. Default 1 (fail closed).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import math
import os
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
# The account every one of the registry's claims has paid into (11/11 in the program's
# whole history). Pinned so a hostile permit server cannot point the price at itself:
# the price moves by CPI to whatever sits in account position 4, and the config account
# does not carry a treasury field, so the client is the only thing that can bound it.
MAINNET_ALIAS_TREASURY = "CmraiWB8rTfR4td7iC7TmvrjMGbJv1nqkvJsbz2MJaDq"

ENV_ALIAS_PROGRAM = "XETE_ALIAS_PROGRAM"
ENV_TREASURY = "XETE_ALIAS_TREASURY"
ENV_TOLERANCE = "XETE_ALIAS_TX_TOLERANCE_LAMPORTS"
ENV_REQUIRE_SIMULATION = "XETE_ALIAS_REQUIRE_SIMULATION"
DEFAULT_TOLERANCE_LAMPORTS = 5_000_000   # 0.005 SOL — alias PDA rent is ~0.00163 SOL

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


def treasury_pubkey(program: Pubkey) -> Pubkey | None:
    """Where a claim's price is allowed to land, or None if it cannot be known.

    None happens only when XETE_ALIAS_PROGRAM points somewhere other than the live
    registry (local-validator testing) and no treasury was configured — there is no
    honest default to pin in that case. The inspection reports which happened.
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
    if str(program) == MAINNET_ALIAS_PROGRAM:
        return Pubkey.from_string(MAINNET_ALIAS_TREASURY)
    return None


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


def _name_candidates(name: str) -> list[str]:
    """The names a permit server may legitimately have normalised `name` to.

    The USER chose the name, so this set is not attacker-controlled; it exists only so
    a server that lowercases or strips a leading % is not mistaken for a server that
    substituted a different name entirely.
    """
    seen, out = set(), []
    base = name.strip()
    for candidate in (name, base, base.lstrip("%"), base.lower(), base.lstrip("%").lower()):
        if candidate and candidate not in seen:
            seen.add(candidate)
            out.append(candidate)
    return out


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
    treasury: str = ""
    treasury_pinned: bool = False
    message_sha256: str = ""
    instructions: list[dict] = field(default_factory=list)
    transfers: list[dict] = field(default_factory=list)
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
            "treasury": self.treasury,
            "treasury_pinned": self.treasury_pinned,
            "message_sha256": self.message_sha256,
            "instructions": self.instructions,
            "transfers": self.transfers,
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
        shown = name_bytes.decode("utf-8", "replace")
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the claim instruction registers %{shown}, but you asked to "
            f"claim %{expect_name}. This is the check that catches a server swapping in a "
            "different name, and it reads the name out of the instruction DATA rather than "
            "inferring it from an account. Nothing was signed."
        )
    key32 = data[2 + name_len:2 + name_len + 32]
    if expect_record_key is not None and not hmac.compare_digest(key32, bytes(expect_record_key)):
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the claim would write record key "
            f"{Pubkey.from_bytes(key32)} into %{expect_name}, not "
            f"{Pubkey.from_bytes(bytes(expect_record_key))}. Nothing was signed."
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
    shown = claim_name.decode("utf-8", "replace")
    want_pda = alias_pda(program, claim_name)
    if accounts[IX_ALIAS_PDA] != want_pda:
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the claim instruction writes account "
            f"{accounts[IX_ALIAS_PDA]}, but the registry account for %{shown} is "
            f"{want_pda}. Nothing was signed."
        )
    if not _is_writable(indexes[IX_ALIAS_PDA], header, n_keys):
        raise TransactionRejected(
            f"TRANSACTION REJECTED: the account for %{shown} ({want_pda}) is read-only in "
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
                        ) -> tuple[Transaction, ClaimInspection]:
    """Decode and allow-list a permit-server alias-claim transaction.

    Returns (parsed transaction, inspection) if and only if every check passes. Raises
    TransactionRejected otherwise — at which point nothing has been signed.

    Every expectation is supplied by the CALLER from values it knew before it talked to
    the server: our own wallet, the name the user typed, the price we were quoted.
    Nothing is read out of the transaction and then used to validate the transaction.
    """
    program = program or alias_program_id()
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
            f"({e}). Nothing was signed."
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
    expected_names = {n.encode("utf-8") for n in _name_candidates(expect_name)}
    treasury = treasury_pubkey(program)
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
        treasury=str(treasury) if treasury is not None else "",
        treasury_pinned=treasury is not None,
        message_sha256=hashlib.sha256(bytes(msg)).hexdigest(),
        instructions=described,
        transfers=transfers,
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
    import time

    import requests

    def call(method: str, params: list):
        # The default endpoint rate-limits, and a 429 that turned simulation off would
        # be the cheapest attack on this whole module. Retry before giving up, and when
        # we do give up the caller fails closed.
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
                    if "error" in body:                  # a real answer: do not retry it
                        raise RuntimeError(f"{method} rpc error: {str(body['error'])[:200]}")
                    return body["result"]
            except RuntimeError:
                raise
            except Exception as e:                       # transport-level, retryable
                last = e
            if attempt < attempts - 1:
                time.sleep(0.4 * (attempt + 1))
        raise RuntimeError(f"{method}: {last}")

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
            f"({str(sim['err'])[:200]}). Nothing was signed."
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
