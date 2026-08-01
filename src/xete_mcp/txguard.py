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

WHAT IS CHECKED
  * legacy transaction only — a v0 message with address lookup tables hides which
    accounts an instruction really touches, so it is refused outright;
  * the fee payer is us, appears exactly once, and our signature slot is still empty;
  * every other required signer has ALREADY signed (the permit server co-signature),
    so we are not the missing piece of some other party's transaction;
  * exactly one alias-registry instruction, and it references the PDA of the name we
    asked for — derived on this side from the name the USER passed, not read out of
    the transaction;
  * every SystemProgram instruction decodes to Transfer or CreateAccount, bounded;
    Assign, AssignWithSeed, TransferWithSeed, the nonce family and everything else are
    refused, because each is a way to take an account away from its owner or move
    lamports we did not agree to;
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
  * the total this transaction can VISIBLY debit from us — transfers + account funding
    + worst-case fee — is bounded by the quoted price plus a tolerance.

WHAT STATIC DECODING CANNOT SEE
Lamports moved by a cross-program invocation from inside the alias program are not
visible in the instruction list; the real claim funds its PDA rent exactly that way.
`simulated_debit()` closes that gap by asking an RPC node what the transaction
actually does to our balance, and the caller bounds THAT figure too. Where simulation
is unavailable, the static bound still holds and the caller is told the difference.

The alias program itself is trusted by policy: it is the product's own on-chain
registry. This module bounds what a malicious PERMIT SERVER can do; it cannot bound a
malicious alias program, which is why the program id is pinned here rather than taken
from the server.

CONFIGURATION (environment)
  XETE_ALIAS_PROGRAM                  alias registry program id. Exists for
                                      local-validator testing. Never point it at an
                                      untrusted program with a funded key.
  XETE_ALIAS_TX_TOLERANCE_LAMPORTS    how much ABOVE the quoted price the claim
                                      transaction may debit, covering the account rent
                                      and network fees a quote excludes.
                                      default 5000000 (0.005 SOL)
"""
from __future__ import annotations

import base64
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

ENV_ALIAS_PROGRAM = "XETE_ALIAS_PROGRAM"
ENV_TOLERANCE = "XETE_ALIAS_TX_TOLERANCE_LAMPORTS"
DEFAULT_TOLERANCE_LAMPORTS = 5_000_000   # 0.005 SOL — alias PDA rent is ~0.00163 SOL

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


def alias_pda(program: Pubkey, name: str) -> Pubkey:
    """PDA of a %name in the registry — same derivation the relay resolves with."""
    return Pubkey.find_program_address([b"alias", name.encode("utf-8")], program)[0]


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
            "instructions": self.instructions,
            "transfers": self.transfers,
            "worst_case_fee_lamports": self.worst_case_fee_lamports,
            "static_debit_lamports": self.static_debit_lamports,
            "ceiling_lamports": self.ceiling_lamports,
        }


def inspect_alias_claim(tx_b64: str, *, expect_fee_payer: Pubkey, expect_name: str,
                        quoted_lamports: int, program: Pubkey | None = None,
                        tolerance: int | None = None,
                        blockhash_is_live: bool | None = None,
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
    expected_pda_by_name = {str(alias_pda(program, n)): n for n in _name_candidates(expect_name)}
    described: list[dict] = []
    transfers: list[dict] = []
    debit = 0
    alias_ix_count = 0
    matched_pda = None
    declared_cu_limit: int | None = None
    cu_price_micro = 0
    non_budget_ix = 0

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
            if not data:
                raise TransactionRejected(
                    f"TRANSACTION REJECTED: the alias-registry instruction at {position} has no "
                    "data, so it is not a claim. Nothing was signed."
                )
            hit = [(i, a) for i, a in zip(cix.accounts, accounts)
                   if str(a) in expected_pda_by_name]
            if not hit:
                raise TransactionRejected(
                    f"TRANSACTION REJECTED: the alias-registry instruction does not touch the "
                    f"account for %{expect_name}. Expected one of "
                    f"{sorted(expected_pda_by_name)}, got {[str(a) for a in accounts]}. This is "
                    "the check that catches a server swapping in a different name. "
                    "Nothing was signed."
                )
            # A registry call may legitimately READ another alias account; what matters is
            # that the name WE asked for is the one being written.
            writable = [(i, a) for i, a in hit if _is_writable(i, header, len(keys))]
            if not writable:
                raise TransactionRejected(
                    f"TRANSACTION REJECTED: the account for %{expect_name} ({hit[0][1]}) is "
                    "read-only in this transaction, so the claim cannot be what it writes. "
                    "Nothing was signed."
                )
            pda_index, pda = writable[0]
            if expect_fee_payer not in accounts:
                raise TransactionRejected(
                    f"TRANSACTION REJECTED: the alias-registry instruction does not include this "
                    f"agent's wallet {expect_fee_payer}, so the name would not be claimed for us. "
                    "Nothing was signed."
                )
            matched_pda = str(pda)
            described.append({"position": position, "program": "alias-registry",
                              "pda": matched_pda, "data_len": len(data)})

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

            if tag == _SYS_TRANSFER:
                if len(data) != 12 or len(accounts) != 2:
                    raise TransactionRejected(
                        f"TRANSACTION REJECTED: malformed SystemProgram Transfer at {position} "
                        f"({len(data)} bytes, {len(accounts)} accounts). Nothing was signed."
                    )
                lamports = struct.unpack("<Q", data[4:12])[0]
                src, dst = accounts
                transfers.append({"position": position, "from": str(src), "to": str(dst),
                                  "lamports": lamports})
                described.append({"position": position, "program": "system", "op": "Transfer",
                                  "lamports": lamports, "to": str(dst)})
                if src == expect_fee_payer:
                    debit += lamports

            elif tag == _SYS_CREATE_ACCOUNT:
                if len(data) != 52 or len(accounts) != 2:
                    raise TransactionRejected(
                        f"TRANSACTION REJECTED: malformed SystemProgram CreateAccount at "
                        f"{position} ({len(data)} bytes, {len(accounts)} accounts). "
                        "Nothing was signed."
                    )
                lamports = struct.unpack("<Q", data[4:12])[0]
                owner = Pubkey.from_bytes(data[20:52])
                if owner != program:
                    raise TransactionRejected(
                        f"TRANSACTION REJECTED: the transaction funds a new account owned by "
                        f"{owner}, not by the alias registry {program}. An account handed to "
                        "another program is money handed to another program. Nothing was signed."
                    )
                src, new = accounts
                described.append({"position": position, "program": "system", "op": "CreateAccount",
                                  "lamports": lamports, "new_account": str(new), "owner": str(owner)})
                if src == expect_fee_payer:
                    debit += lamports

            else:
                raise TransactionRejected(
                    f"TRANSACTION REJECTED: SystemProgram {name} at instruction {position}. This "
                    "client signs only Transfer and CreateAccount from the System program; "
                    f"{name} can reassign, reallocate or drain an account in ways a price quote "
                    "does not describe. Nothing was signed."
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
            f"{expect_fee_payer} (transfers/funding plus a worst-case fee of {fee}, of which "
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
    import requests

    def call(method: str, params: list):
        r = requests.post(rpc_url, json={"jsonrpc": "2.0", "id": 1, "method": method,
                                         "params": params}, timeout=timeout)
        r.raise_for_status()
        body = r.json()
        if "error" in body:
            raise RuntimeError(f"{method} rpc error: {str(body['error'])[:200]}")
        return body["result"]

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
