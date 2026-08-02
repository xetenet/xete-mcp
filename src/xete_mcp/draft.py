"""Unsigned settlement drafts — the custody-T1 path.

`settlement.deposit()` signs and submits with a local key. That is the right shape for a fleet
agent the operator owns, and the wrong shape for handing xete to a general-purpose agent runtime
(ZeroClaw, Claude Desktop, anything speaking MCP): it means "connect xete" implies "give the agent
your money".

This module builds the SAME deposit instruction and stops one step short — it serializes an
UNSIGNED transaction for a human to review and sign in their own wallet. Nothing here constructs a
Keypair, reads a seed, or touches the network except to read a blockhash/nonce.

Two properties make the human review real rather than decorative:

  1. The beneficiary is hidden on-chain as sha256(recipient || salt), so a human staring at the raw
     transaction sees 32 opaque bytes. `verify_draft` re-derives that commitment from a recipient
     and salt supplied INDEPENDENTLY of the agent, so a tampered draft fails a check instead of
     passing on the strength of the agent's prose summary. If the agent is prompt-injected into
     drafting a payment to an attacker, the commitment will not match and verification fails.

  2. Durable nonce. An approval that sits in a queue outlives the ~90s blockhash window, and
     ZeroClaw's approval gate defaults to a 120s timeout — longer than the blockhash lives. With a
     nonce account configured the drafted transaction stays valid until it is used.
"""
from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass, field

from solders.hash import Hash
from solders.instruction import Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.system_program import AdvanceNonceAccountParams, advance_nonce_account
from solders.transaction import Transaction
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed

from . import settlement

# Nonce account layout: version(4) state(4) authority(32) durable_nonce(32) fee_calculator(8)
_NONCE_BLOCKHASH_OFFSET = 40
_NONCE_AUTHORITY_OFFSET = 8
_DEPOSIT_DATA_LEN = 1 + 32 + 8 + 32 + 8  # tag, escrow_id, amount, commitment, unlock


@dataclass(frozen=True)
class DraftedSettlement:
    unsigned_tx_b64: str
    escrow_id_hex: str
    salt_hex: str
    pda: str
    depositor: str
    recipient: str
    amount_lamports: int
    commitment_hex: str
    program: str
    nonce_account: str | None
    blockhash_kind: str  # "durable_nonce" | "recent_blockhash"
    expires_note: str


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checks: list[dict] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    movements: list[dict] = field(default_factory=list)
    total_lamports_out: int = 0
    fee_lamports: int = 0
    # The escrow the transaction actually funds. "" when verification stopped before the deposit
    # instruction was located — an empty string is not an escrow id, so a caller comparing it to
    # a ticket gets a mismatch rather than a silent pass.
    escrow_id_hex: str = ""


# ── what a transaction DOES, not merely which programs it touches ────────────────────────
# Checking the program id of every instruction is not verification. A plain system-program
# transfer is "only the system program"; a compute-budget price is "only compute budget". Both
# move real SOL out of the signer's wallet, and neither is visible unless the instruction DATA is
# decoded. Everything below decodes it, and fails closed on anything it cannot decode.

# 5000 lamports per signature; the deposit draft has exactly one signer.
LAMPORTS_PER_SIGNATURE = 5_000
# Runtime defaults for compute units when the transaction does not set a limit.
DEFAULT_CU_PER_IX = 200_000
MAX_CU_LIMIT = 1_400_000

# What an honest deposit draft costs: 60_000 CU at 1_000 micro-lamports/CU = 60 lamports of
# priority fee, plus 5_000 base = 5_060 lamports.
HONEST_TX_FEE_LAMPORTS = LAMPORTS_PER_SIGNATURE + 60
# The ceiling is a YIELD, not a bound on a hypothetical. Whatever slack sits between the honest
# cost and this number is extractable in full, silently, on every single draft a human signs —
# a priority fee moves real SOL out of the signer with nothing in the instruction list to show
# for it. The old 0.001 SOL cap was 198x the honest cost: 1_400_000 CU x 710_714
# micro-lamports/CU lands on exactly 1_000_000 lamports and verified "SAFE TO REVIEW AND SIGN".
# 50_000 still leaves ~10x headroom for a genuinely congested slot (200_000 CU at 50_000
# micro-lamports/CU = 15_000 lamports all-in) while cutting the per-signature take by 95%.
# Callers who really do need more must say so explicitly via max_fee_lamports and own it.
MAX_TX_FEE_LAMPORTS = 50_000

# Rent-exempt minimum for the 81-byte escrow account. Re-exported from settlement rather than
# recomputed here: it is the floor `deposit_ix` enforces and the floor this verifier checks, and
# two independently-derived copies of a constant on an IMMUTABLE program is how one of them ends
# up certifying what the other refuses.
#
# THIS IS NOT AN EXTRA DEBIT ON THE SIGNER, and this file used to tell them it was — finding
# [G12]. The program creates the escrow account with exactly the deposit `amount`, so the
# rent-exempt reserve comes OUT of the amount and the depositor pays `amount + fee`. See
# settlement.RENT_EXEMPT_LAMPORTS for the read-only mainnet balance deltas that establish it.
# The reserve is still real and still worth disclosing — it is what makes `amount` a floor
# rather than merely positive — it is just not money leaving the wallet on top of the amount.
ESCROW_RENT_LAMPORTS = settlement.RENT_EXEMPT_LAMPORTS              # 1_454_640

_SYS_CREATE_ACCOUNT = 0
_SYS_TRANSFER = 2
_SYS_CREATE_ACCOUNT_WITH_SEED = 3
_SYS_ADVANCE_NONCE = 4
_SYS_WITHDRAW_NONCE = 5
_SYS_TRANSFER_WITH_SEED = 11


def _message_version(raw: bytes) -> int | None:
    """None if `raw` is a LEGACY transaction, else the message's version number (0 for v0).

    This exists because `Transaction.from_bytes` does NOT reject a versioned transaction — that
    claim, made in an earlier review of this file, is wrong and was checked: a real MessageV0
    compiled with an AddressLookupTableAccount deserialises through the legacy parser without
    complaint. What actually happens is that the legacy parser reads v0's `0x80` version prefix
    as the message header's `num_required_signatures` and reports 128 of them, which trips the
    unrelated `single_signer` check further down.

    That is an accident, and it is load-bearing. A v0 transaction resolves instruction program
    ids through address lookup tables, whose contents are NOT in the transaction — so every
    program-id check in this module (`no_unexpected_programs`, the settlement/system/compute
    -budget dispatch in `_lamport_movements`) is reading an account list that does not contain
    the accounts the runtime will actually use. The moment `single_signer` is relaxed for any
    ordinary reason — a multisig depositor, a fee payer separate from the signer — an ALT bypass
    of the entire verifier reopens with nothing to catch it. So refuse non-legacy on its own
    terms, up front, before anything else reads the bytes.

    Layout: compact-u16 signature count || signatures || message. A legacy message begins with
    `num_required_signatures`, which is a plain count; a versioned one begins with `0x80 | ver`.
    The high bit is the discriminator, so it cannot collide with a legal legacy header.
    """
    n = shift = idx = 0
    while True:
        if idx >= len(raw):
            raise ValueError("truncated transaction: no signature-count prefix")
        b = raw[idx]
        idx += 1
        n |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
        if shift > 14:
            raise ValueError("malformed compact-u16 signature count")
    off = idx + n * 64
    if off >= len(raw):
        raise ValueError("truncated transaction: no message after the signature array")
    first = raw[off]
    return (first & 0x7F) if first & 0x80 else None


def _u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _u64(b: bytes, off: int) -> int:
    return struct.unpack_from("<Q", b, off)[0]


def _system_movement(data: bytes, accts: list) -> dict:
    """Decode one system-program instruction into a lamport movement.

    Fail-closed: anything not decoded in full comes back with decoded=False, which the caller
    treats as a failure. Only AdvanceNonceAccount is a legitimate part of a settlement draft —
    every other system instruction here either moves lamports or does something we did not ask
    for, and both deserve a refusal rather than a shrug.

    "Anything" means ANYTHING, so the guard is `except Exception`, not a tuple of the error
    types that happened to come to mind. This is hand-rolled binary parsing of bytes an attacker
    chose, and the tuple was already wrong: CreateAccountWithSeed's bincode String length is a
    u64 read straight out of the instruction and then used as an OFFSET, so a declared length of
    0xFFFFFFFFFFFFFFFF makes `struct.unpack_from` raise OverflowError — not struct.error, not
    IndexError, not ValueError. It unwound out of verify_draft and broke its documented contract
    of always returning a VerifyResult. The length is now bounded against the data before it is
    used as an offset as well, so the overflow is unreachable rather than merely caught.
    """
    def acct(i: int) -> str:
        return str(accts[i]) if len(accts) > i else "<missing>"

    if len(data) < 4:
        return {"program": "system", "kind": "system:truncated", "lamports": None,
                "from": None, "to": None, "decoded": False}
    tag = _u32(data, 0)
    try:
        if tag == _SYS_ADVANCE_NONCE:
            return {"program": "system", "kind": "system:advance_nonce_account", "lamports": 0,
                    "from": None, "to": acct(0), "decoded": True, "expected": True}
        if tag == _SYS_TRANSFER:
            return {"program": "system", "kind": "system:transfer", "lamports": _u64(data, 4),
                    "from": acct(0), "to": acct(1), "decoded": True}
        if tag == _SYS_CREATE_ACCOUNT:
            return {"program": "system", "kind": "system:create_account", "lamports": _u64(data, 4),
                    "from": acct(0), "to": acct(1), "decoded": True}
        if tag == _SYS_WITHDRAW_NONCE:
            return {"program": "system", "kind": "system:withdraw_nonce_account",
                    "lamports": _u64(data, 4), "from": acct(0), "to": acct(1), "decoded": True}
        if tag == _SYS_TRANSFER_WITH_SEED:
            return {"program": "system", "kind": "system:transfer_with_seed",
                    "lamports": _u64(data, 4), "from": acct(0), "to": acct(2), "decoded": True}
        if tag == _SYS_CREATE_ACCOUNT_WITH_SEED:
            seed_len = _u64(data, 36)                       # bincode String: u64 length + bytes
            # Bound it BEFORE it becomes an offset. An unbounded attacker-chosen u64 here is an
            # arbitrary offset into struct.unpack_from, which is how the OverflowError above got
            # out. `44 + seed_len + 8` is where the lamports field ends.
            if seed_len > len(data) or 44 + seed_len + 8 > len(data):
                raise ValueError(f"seed length {seed_len} does not fit in {len(data)} bytes")
            return {"program": "system", "kind": "system:create_account_with_seed",
                    "lamports": _u64(data, 44 + seed_len), "from": acct(0), "to": acct(1),
                    "decoded": True}
    except Exception:
        return {"program": "system", "kind": f"system:tag{tag}:truncated", "lamports": None,
                "from": None, "to": None, "decoded": False}
    return {"program": "system", "kind": f"system:tag{tag}:unrecognised", "lamports": None,
            "from": None, "to": None, "decoded": False}


def _transaction_fee(msg, keys) -> tuple[int, dict, list[str]]:
    """(total fee in lamports, itemisation, undecodable compute-budget instructions).

    The compute-budget program moves no lamports of its own, which is exactly why it gets waved
    through — but priority fee = compute_unit_limit x price_per_unit / 1e6, and both are attacker
    chosen u32/u64 values. 1_400_000 CU at 700_000_000 micro-lamports/CU is 0.98 SOL, debited
    from the signer with nothing in the instruction list that looks like a payment.
    """
    limit: int | None = None
    price = 0
    extra = 0
    unknown: list[str] = []
    n_ix = len(msg.instructions)
    for cix in msg.instructions:
        if cix.program_id_index >= len(keys) or keys[cix.program_id_index] != settlement.CB:
            continue
        d = bytes(cix.data)
        if not d:
            unknown.append("compute_budget:empty")
            continue
        tag = d[0]
        try:
            # max(), not last-wins: if a transaction somehow carries two of these, price the
            # worse one. Under-quoting the fee is the only direction that can hurt.
            if tag == 2 and len(d) >= 5:            # SetComputeUnitLimit(u32)
                limit = max(limit or 0, _u32(d, 1))
            elif tag == 3 and len(d) >= 9:          # SetComputeUnitPrice(u64 micro-lamports/CU)
                price = max(price, _u64(d, 1))
            elif tag == 0 and len(d) >= 9:          # deprecated RequestUnits(u32, additional_fee u32)
                limit = max(limit or 0, _u32(d, 1))
                extra += _u32(d, 5)                 # additional_fee is plain lamports
            elif tag in (1, 4) and len(d) >= 5:     # RequestHeapFrame / SetLoadedAccountsDataSize
                pass
            else:
                unknown.append(f"compute_budget:tag{tag}")
        except Exception:
            # Same reasoning as _system_movement: a named-exception tuple over attacker-chosen
            # bytes is a list of the failures someone thought of. An undecodable compute-budget
            # instruction is recorded as unknown, which fails the draft — never raised.
            unknown.append(f"compute_budget:tag{tag}:truncated")
    effective_cu = min(limit, MAX_CU_LIMIT) if limit is not None else min(DEFAULT_CU_PER_IX * n_ix,
                                                                          MAX_CU_LIMIT)
    priority = -(-(effective_cu * price) // 1_000_000)      # the runtime rounds up
    base = LAMPORTS_PER_SIGNATURE * msg.header.num_required_signatures
    detail = {"base_lamports": base, "priority_lamports": priority,
              "compute_unit_limit": effective_cu, "limit_was_explicit": limit is not None,
              "micro_lamports_per_cu": price, "additional_fee_lamports": extra}
    return base + priority + extra, detail, unknown


def _lamport_movements(msg, keys, program, expected_pda) -> tuple[list[dict], list[str]]:
    """Every lamport movement in the transaction, plus the instructions we could not decode."""
    movements: list[dict] = []
    undecodable: list[str] = []
    for n, cix in enumerate(msg.instructions):
        if cix.program_id_index >= len(keys):
            undecodable.append(f"ix{n}: program index {cix.program_id_index} out of range")
            continue
        prog_key = keys[cix.program_id_index]
        if any(i >= len(keys) for i in cix.accounts):
            # Do NOT filter these out and carry on: dropping an index SHIFTS every account after
            # it, so `from`/`to` would name the wrong wallets in a movement the human then reads
            # as authoritative. from_bytes does not sanitise account indices — that was checked.
            undecodable.append(f"ix{n}: account index {max(cix.accounts)} out of range "
                               f"({len(keys)} account keys) — malformed transaction")
            movements.append({"program": str(prog_key), "kind": "account_index_out_of_range",
                              "ix": n, "lamports": None, "from": None, "to": None,
                              "decoded": False})
            continue
        accts = [keys[i] for i in cix.accounts]
        data = bytes(cix.data)
        if prog_key == settlement.CB:
            continue                                     # priced separately, in _transaction_fee
        if prog_key == settlement.SYS:
            m = _system_movement(data, accts)
            m["ix"] = n
            movements.append(m)
            if not m["decoded"]:
                undecodable.append(f"ix{n}: {m['kind']}")
            continue
        if prog_key == program:
            tag = data[0] if data else None
            if tag == 0 and len(data) == _DEPOSIT_DATA_LEN:
                pda = settlement.escrow_pda(program, data[1:33])
                movements.append({"program": "settlement", "kind": "settlement:deposit", "ix": n,
                                  "lamports": struct.unpack("<Q", data[33:41])[0],
                                  "from": str(keys[0]) if keys else None, "to": str(pda),
                                  "decoded": True,
                                  "expected": str(pda) == str(expected_pda)})
            else:
                undecodable.append(f"ix{n}: settlement program instruction tag={tag} "
                                   f"len={len(data)} — not the deposit this draft claims to be")
                movements.append({"program": "settlement", "kind": f"settlement:tag{tag}", "ix": n,
                                  "lamports": None, "from": None, "to": None, "decoded": False})
            continue
        undecodable.append(f"ix{n}: unexpected program {prog_key}")
        movements.append({"program": str(prog_key), "kind": "unknown_program", "ix": n,
                          "lamports": None, "from": None, "to": None, "decoded": False})
    return movements, undecodable


# The complete instruction sequence an honest deposit can be, in order. `draft_deposit`
# emits exactly this and nothing else: an optional durable-nonce advance FIRST, then the two
# compute-budget instructions, then the deposit.
_SHAPE_WITHOUT_NONCE = ("cb_limit", "cb_price", "deposit")
_SHAPE_WITH_NONCE = ("advance_nonce",) + _SHAPE_WITHOUT_NONCE

_CB_SET_LIMIT = 2
_CB_SET_PRICE = 3


def _instruction_shape(msg, keys, program) -> tuple[list[str], list[str]]:
    """Classify every instruction by KIND, in order, plus the nonce accounts named.

    WHY A SHAPE CHECK EXISTS AT ALL, when this file already sums every lamport that leaves
    the signer: because `destinations` and `total_lamport_movement` are both VALUE-WEIGHTED,
    and an attacker does not have to move value to do damage. A zero-lamport instruction
    contributes 0 to the total and is filtered out of the destination list, so it is
    structurally invisible to every arithmetic check here. Four instructions were certified
    `ok=True, failures=none` on exactly that basis by an independent review:

      * a 0-lamport, 0-space system CreateAccount — decodes cleanly, moves nothing, and makes
        the RUNTIME reject the whole transaction because a 0-byte account is not rent-exempt.
        The human pays a fee for a deposit that never happens.
      * an AdvanceNonceAccount for an arbitrary nonce account — see `expect_nonce_account`.
      * an AdvanceNonceAccount anywhere but index 0, which `draft_deposit`'s own comment says
        the runtime rejects.
      * a 0-lamport transfer to an attacker-chosen address, which executes and writes an
        interaction between the signer's wallet and that address into the public record.

    Whitelisting the SHAPE kills all of those together, and kills the next zero-value system
    instruction nobody has thought of yet. Patching `destinations` to stop filtering on
    `lamports > 0` would fix two of the four and leave the ordering one alive.

    Unknown or undecodable instructions get a kind that cannot match the whitelist, so the
    default is refusal — this function never has to enumerate what is bad.
    """
    kinds: list[str] = []
    nonce_accounts: list[str] = []
    for n, cix in enumerate(msg.instructions):
        if cix.program_id_index >= len(keys):
            kinds.append(f"ix{n}:bad_program_index")
            continue
        prog_key = keys[cix.program_id_index]
        data = bytes(cix.data)
        if prog_key == settlement.CB:
            tag = data[0] if data else None
            kinds.append({_CB_SET_LIMIT: "cb_limit", _CB_SET_PRICE: "cb_price"}.get(
                tag, f"ix{n}:compute_budget_tag{tag}"))
        elif prog_key == settlement.SYS:
            tag = _u32(data, 0) if len(data) >= 4 else None
            if tag == _SYS_ADVANCE_NONCE:
                kinds.append("advance_nonce")
                # accounts[0] is the nonce account. Recorded rather than checked here so the
                # caller's expectation does the deciding.
                if cix.accounts and cix.accounts[0] < len(keys):
                    nonce_accounts.append(str(keys[cix.accounts[0]]))
                else:
                    nonce_accounts.append("<unresolvable>")
            else:
                kinds.append(f"ix{n}:system_tag{tag}")
        elif prog_key == program:
            tag = data[0] if data else None
            kinds.append("deposit" if tag == 0 and len(data) == _DEPOSIT_DATA_LEN
                         else f"ix{n}:settlement_tag{tag}")
        else:
            kinds.append(f"ix{n}:unknown_program")
    return kinds, nonce_accounts


def _read_nonce(client: Client, nonce_account: Pubkey) -> tuple[Hash, Pubkey]:
    """Read a durable nonce account -> (nonce value, on-chain authority). Raises if absent."""
    info = client.get_account_info(nonce_account, commitment=Confirmed).value
    if info is None:
        raise RuntimeError(f"nonce account {nonce_account} does not exist")
    data = bytes(info.data)
    if len(data) < _NONCE_BLOCKHASH_OFFSET + 32:
        raise RuntimeError(f"nonce account {nonce_account} is not a nonce account (len {len(data)})")
    nonce_value = Hash.from_bytes(data[_NONCE_BLOCKHASH_OFFSET:_NONCE_BLOCKHASH_OFFSET + 32])
    authority = Pubkey.from_bytes(data[_NONCE_AUTHORITY_OFFSET:_NONCE_AUTHORITY_OFFSET + 32])
    return nonce_value, authority


def draft_deposit(rpc_url: str, depositor: Pubkey, recipient: Pubkey, amount_lamports: int,
                  nonce_account: Pubkey | None = None,
                  nonce_authority: Pubkey | None = None) -> DraftedSettlement:
    """Build an UNSIGNED deposit transaction. `depositor` pays and signs — it must come from
    operator config, never from a tool argument or a counterparty's message."""
    if amount_lamports <= 0:
        raise ValueError("amount_lamports must be > 0")

    prog = settlement.program_id()
    # Random escrow id + salt, exactly as the signing path derives them. Never derived from the
    # recipient — that would leak the beneficiary the commitment is meant to hide.
    escrow_id = bytes(Keypair().pubkey())
    salt = bytes(Keypair().pubkey())[:16]
    commitment_bytes = settlement.commitment(recipient, salt)

    ixs: list[Instruction] = []
    client = Client(rpc_url)

    if nonce_account is not None:
        authority = nonce_authority or depositor
        nonce_value, onchain_authority = _read_nonce(client, nonce_account)
        if onchain_authority != authority:
            raise RuntimeError(
                f"nonce authority mismatch: account says {onchain_authority}, config says {authority}"
            )
        # MUST be the first instruction, or the runtime rejects the nonce.
        ixs.append(advance_nonce_account(
            AdvanceNonceAccountParams(nonce_pubkey=nonce_account, authorized_pubkey=authority)
        ))
        blockhash = nonce_value
        kind = "durable_nonce"
        note = (f"Does not expire on the ~90s blockhash clock; valid until the nonce at "
                f"{nonce_account} is advanced by another transaction.")
    else:
        blockhash = client.get_latest_blockhash().value.blockhash
        kind = "recent_blockhash"
        note = ("EXPIRES in ~90 seconds. Sign promptly, or configure XETE_NONCE_ACCOUNT so an "
                "approval that waits does not invalidate the transaction.")

    ixs.append(settlement._cb_limit(60_000))
    ixs.append(settlement._cb_price(1_000))
    ixs.append(settlement.deposit_ix(prog, depositor, escrow_id, amount_lamports, commitment_bytes))

    msg = Message.new_with_blockhash(ixs, depositor, blockhash)
    tx = Transaction.new_unsigned(msg)

    return DraftedSettlement(
        unsigned_tx_b64=base64.b64encode(bytes(tx)).decode(),
        escrow_id_hex=escrow_id.hex(),
        salt_hex=salt.hex(),
        pda=str(settlement.escrow_pda(prog, escrow_id)),
        depositor=str(depositor),
        recipient=str(recipient),
        amount_lamports=amount_lamports,
        commitment_hex=commitment_bytes.hex(),
        program=str(prog),
        nonce_account=str(nonce_account) if nonce_account else None,
        blockhash_kind=kind,
        expires_note=note,
    )


def _find_deposit_ix(tx: Transaction, program: Pubkey) -> tuple[bytes, list[Pubkey]]:
    """Locate the settlement deposit instruction and return (data, resolved account pubkeys).

    Raises ValueError on anything malformed, because ValueError is what `_verify_draft` catches
    at this call site to fail closed. (It used to claim ValueError was the ONLY thing that could
    escape this module's parsing. That was never a property anyone had established — an
    OverflowError out of `_system_movement` disproved the same claim next door — so the
    guarantee now lives in `verify_draft`'s outer guard, where it is structural rather than
    asserted.) `keys[i] for i in cix.accounts` was an unguarded
    IndexError path: `Transaction.from_bytes` does not bounds-check compiled account indices
    against the account-key array (verified), so an attacker-supplied transaction carrying an
    out-of-range index unwound an IndexError straight out of verify_draft and broke its
    documented contract of always returning a VerifyResult.
    """
    msg = tx.message
    keys = list(msg.account_keys)
    for cix in msg.instructions:
        if cix.program_id_index >= len(keys) or keys[cix.program_id_index] != program:
            continue
        data = bytes(cix.data)
        if data[:1] == b"\x00" and len(data) == _DEPOSIT_DATA_LEN:
            if any(i >= len(keys) for i in cix.accounts):
                raise ValueError(
                    f"the deposit instruction references account index {max(cix.accounts)} but "
                    f"the transaction carries only {len(keys)} account keys — malformed, "
                    "refusing to interpret it")
            return data, [keys[i] for i in cix.accounts]
    raise ValueError(f"no deposit (tag 0) instruction for program {program} found in transaction")


def verify_draft(unsigned_tx_b64: str, *, expect_recipient: Pubkey, expect_salt_hex: str,
                 expect_amount_lamports: int, expect_depositor: Pubkey,
                 expect_program: Pubkey | None = None,
                 expect_escrow_id_hex: str | None = None,
                 expect_nonce_account: Pubkey | str | None = None,
                 max_fee_lamports: int = MAX_TX_FEE_LAMPORTS) -> VerifyResult:
    """ALWAYS returns a VerifyResult — see `_verify_draft` for the actual verification.

    This wrapper is the structural guarantee behind that "always". Everything inside is
    hand-rolled binary parsing of bytes an attacker chose, and the contract had already been
    broken twice by exception types nobody had thought of (an unguarded IndexError on an
    out-of-range account index; an OverflowError from a u64 bincode length used as an offset).
    Patching each one as it is found leaves the contract resting on the completeness of a list.
    An escape is turned into a FAILED result, never a pass and never a raise, so the worst a
    novel parser bug can do to a human holding a key is refuse a legitimate draft.
    """
    try:
        return _verify_draft(
            unsigned_tx_b64, expect_recipient=expect_recipient, expect_salt_hex=expect_salt_hex,
            expect_amount_lamports=expect_amount_lamports, expect_depositor=expect_depositor,
            expect_program=expect_program, expect_escrow_id_hex=expect_escrow_id_hex,
            expect_nonce_account=expect_nonce_account,
            max_fee_lamports=max_fee_lamports)
    except Exception as e:                      # noqa: BLE001 — deliberate, see above
        return VerifyResult(
            ok=False,
            checks=[{"name": "verifier_internal_error", "ok": False,
                     "expected": "the verifier to decode this transaction in full",
                     "actual": f"{type(e).__name__}: {str(e)[:200]} — the verifier could not "
                               "finish. This is NOT a pass: nothing about this transaction has "
                               "been checked. DO NOT SIGN IT."}],
            failures=["verifier_internal_error"])


def _verify_draft(unsigned_tx_b64: str, *, expect_recipient: Pubkey, expect_salt_hex: str,
                  expect_amount_lamports: int, expect_depositor: Pubkey,
                  expect_program: Pubkey | None = None,
                  expect_escrow_id_hex: str | None = None,
                  expect_nonce_account: Pubkey | str | None = None,
                  max_fee_lamports: int = MAX_TX_FEE_LAMPORTS) -> VerifyResult:
    """Independently check that a drafted transaction does what its summary claims.

    Every expectation is supplied by the CALLER, not read out of the draft — that is the whole
    point. Re-deriving sha256(recipient || salt) is what catches a redirected beneficiary, since
    the recipient never appears in the transaction in the clear.

    The other half of the job is arithmetic, not identity: this decodes the DATA of every
    instruction, sums every lamport that leaves the signer, prices the compute-budget fee, and
    refuses unless the total and the destinations are exactly the deposit that was asked for. A
    green result from a whitelist of program ids means nothing — a system transfer and a
    compute-budget price both drain the signer while touching only "expected" programs.
    """
    checks: list[dict] = []
    failures: list[str] = []

    def record(name: str, ok: bool, expected, actual) -> None:
        checks.append({"name": name, "ok": bool(ok), "expected": str(expected), "actual": str(actual)})
        if not ok:
            failures.append(name)

    program = expect_program or settlement.program_id()
    try:
        raw = base64.b64decode(unsigned_tx_b64, validate=True)
        version = _message_version(raw)
        tx = Transaction.from_bytes(raw)
    except Exception as e:
        return VerifyResult(ok=False, checks=[{"name": "deserialize", "ok": False,
                                               "expected": "a valid Solana transaction",
                                               "actual": str(e)[:200]}],
                            failures=["deserialize"])

    # Explicit, and first, because everything after it reads program ids out of the account-key
    # array — which a versioned transaction is entitled to complete from address lookup tables
    # that are not in these bytes. See _message_version for why the old code only survived this
    # by accident.
    if version is not None:
        record("legacy_transaction", False, "a legacy (unversioned) transaction",
               f"a v{version} transaction. Its instructions can resolve program ids through "
               "address lookup tables whose contents are not in the transaction, so no check "
               "in this verifier can be trusted about it. This path only ever drafts legacy "
               "transactions; refusing.")
        return VerifyResult(ok=False, checks=checks, failures=failures)
    record("legacy_transaction", True, "a legacy (unversioned) transaction",
           "legacy — every program id is resolvable from the transaction itself")

    msg = tx.message
    keys = list(msg.account_keys)

    zero = Signature.default()
    unsigned = all(s == zero for s in tx.signatures)
    record("unsigned", unsigned, "all signature slots empty",
           "empty" if unsigned else "CONTAINS A SIGNATURE")

    record("single_signer", msg.header.num_required_signatures == 1,
           1, msg.header.num_required_signatures)

    record("fee_payer_is_depositor", bool(keys) and keys[0] == expect_depositor,
           expect_depositor, keys[0] if keys else "<none>")

    try:
        data, accounts = _find_deposit_ix(tx, program)
    except ValueError as e:
        record("deposit_instruction_present", False, f"tag-0 ix for {program}", str(e)[:200])
        return VerifyResult(ok=False, checks=checks, failures=failures)
    record("deposit_instruction_present", True, f"tag-0 ix for {program}", "found")

    # ── THE SHAPE, before any arithmetic ────────────────────────────────────────────────
    # An honest draft is a CLOSED SET of instructions in a fixed order. Everything below this
    # point is value-weighted, and a zero-lamport instruction is invisible to all of it — see
    # `_instruction_shape` for the four that were certified `ok=True, failures=none` on
    # exactly that basis.
    kinds, nonce_accounts = _instruction_shape(msg, keys, program)
    want = list(_SHAPE_WITH_NONCE if expect_nonce_account is not None
                else _SHAPE_WITHOUT_NONCE)
    record("instruction_shape", kinds == want, want, kinds)

    # Identity, which no shape check can supply: a nonce advance for an account the caller
    # never named is indistinguishable in shape from the intended one. It is the only finding
    # here with an effect OUTSIDE this transaction — advancing a durable nonce invalidates
    # every transaction already queued against it, so a signature given for a deposit
    # silently kills an unrelated pending transaction of the signer's, and nothing in the
    # itemisation shows it.
    #
    # Note the asymmetry this closes: `draft_deposit` reads the nonce account and refuses on
    # an authority mismatch, so the BUILDER was careful about nonce identity while the
    # VERIFIER — the half that exists to face a hostile builder — did not check it at all.
    if expect_nonce_account is not None:
        want_nonce = str(expect_nonce_account)
        record("nonce_account", nonce_accounts == [want_nonce], want_nonce,
               nonce_accounts or "<no nonce advance in this transaction>")

    escrow_id = data[1:33]
    escrow_id_hex = escrow_id.hex()
    amount = struct.unpack("<Q", data[33:41])[0]
    commitment_in_tx = data[41:73]
    unlock = struct.unpack("<q", data[73:81])[0]

    record("amount", amount == expect_amount_lamports, expect_amount_lamports, amount)

    # A DEPOSIT THAT CANNOT LAND IS NOT A SAFE DEPOSIT — finding [G12]. The program funds the
    # escrow account with exactly `amount`, so an amount below the rent-exempt minimum for
    # STATE_LEN bytes cannot create it: the runtime rejects the transaction for insufficient
    # funds for rent. `deposit_ix` used to validate only `amount > 0`, and this verifier said
    # nothing at all, so a draft that was never going to execute came back "SAFE TO REVIEW AND
    # SIGN". Nothing is stolen; the human spends a signature and a network fee on a transaction
    # that escrows nothing, against a tool whose entire promise is that it refuses anything that
    # is not the deposit that was asked for.
    #
    # Checked against the amount IN THE TRANSACTION, not the caller's expectation: the question
    # is what these bytes will do, and `amount` above already reports any disagreement.
    record("amount_covers_rent", amount >= ESCROW_RENT_LAMPORTS,
           f">= {ESCROW_RENT_LAMPORTS} lamports — the rent-exempt minimum for the "
           f"{settlement.STATE_LEN}-byte escrow account, which the program creates with exactly "
           f"the deposit amount",
           f"{amount} lamports" + ("" if amount >= ESCROW_RENT_LAMPORTS else
                                   f" — {ESCROW_RENT_LAMPORTS - amount} lamports short. This "
                                   "transaction CANNOT execute: the escrow account would not be "
                                   "rent-exempt, so the runtime rejects it after charging the "
                                   "fee. Do not sign it."))

    # The escrow id is the CLAIM TICKET's primary key, and until now it was never checked and
    # never even surfaced: a verified draft could fund escrow Y while the ticket handed to the
    # recipient named escrow X. Nothing is stolen — the commitment still pins the beneficiary —
    # but the recipient's claim finds nothing, and the depositor has to dig the real id out of
    # the confirmed transaction before they can reclaim. A stranded payment certified as safe is
    # exactly what this tool exists to prevent, so the id is always reported, and checked
    # whenever the caller can supply the one their ticket says.
    if expect_escrow_id_hex is None:
        record("escrow_id", True,
               "no expectation supplied — COMPARE THIS AGAINST THE ESCROW ID ON YOUR CLAIM "
               "TICKET; if they differ the recipient cannot claim what you are about to fund",
               escrow_id_hex)
    else:
        want = str(expect_escrow_id_hex).strip().lower()
        record("escrow_id", want == escrow_id_hex, want, escrow_id_hex)

    # The load-bearing check: does the hidden beneficiary actually resolve to who we were told?
    try:
        salt = bytes.fromhex(expect_salt_hex)
        expected_commitment = hashlib.sha256(bytes(expect_recipient) + salt).digest()
        ok = expected_commitment == commitment_in_tx
    except Exception:
        # A non-hex salt raises ValueError; a salt that is not a string at all raises TypeError.
        # Both mean "the commitment could not be re-derived", which is a FAILED check, not an
        # exception out of a function whose contract is to return a VerifyResult.
        expected_commitment, ok = b"", False
    record("recipient_commitment", ok,
           f"sha256({expect_recipient} || salt) = {expected_commitment.hex() or '<bad salt>'}",
           commitment_in_tx.hex())

    record("unlock_is_immediate", unlock == 0, 0, unlock)

    expected_pda = settlement.escrow_pda(program, escrow_id)
    record("escrow_pda", len(accounts) > 1 and accounts[1] == expected_pda,
           expected_pda, accounts[1] if len(accounts) > 1 else "<missing>")

    record("depositor_signs", bool(accounts) and accounts[0] == expect_depositor,
           expect_depositor, accounts[0] if accounts else "<missing>")

    # accounts[2] must be the system program — finding [G14]. The deposit's account list was
    # checked at [0] (depositor) and [1] (escrow PDA) and then stopped, so an attacker key in
    # slot 2 verified ok=True with zero failures. `no_unexpected_programs` below does NOT cover
    # it: the system program appears here as an ACCOUNT, and that check only looks at instruction
    # program ids.
    #
    # Not theft — the program's internal create_account CPI fails at execution — but it is not
    # the deposit that was asked for, it will never fund the escrow, and it costs the human a fee
    # plus a spent approval. The same reasoning as amount_covers_rent above: a transaction that
    # cannot do what the summary says must not be certified, whether the reason is arithmetic or
    # a wrong account.
    record("system_program_account", len(accounts) > 2 and accounts[2] == settlement.SYS,
           f"{settlement.SYS} (the system program, which the deposit's internal create_account "
           "CPI requires in this position)",
           accounts[2] if len(accounts) > 2 else
           f"<missing — the deposit carries only {len(accounts)} accounts>")

    # Anything else touching the program, or any extra instruction that moves value, is suspect.
    other = [keys[c.program_id_index] for c in msg.instructions
             if c.program_id_index < len(keys)
             and keys[c.program_id_index] not in (program, settlement.CB, settlement.SYS)]
    record("no_unexpected_programs", not other,
           "only settlement + compute-budget + system", other or "none")

    # ── the arithmetic: WHAT each instruction does ───────────────────────────────────────
    movements, undecodable = _lamport_movements(msg, keys, program, expected_pda)
    fee_lamports, fee_detail, fee_unknown = _transaction_fee(msg, keys)
    undecodable = undecodable + fee_unknown

    record("every_instruction_decoded", not undecodable,
           "every instruction decoded and understood", undecodable or "all decoded")

    deposits = [m for m in movements if m["kind"] == "settlement:deposit"]
    record("exactly_one_deposit", len(deposits) == 1, 1, len(deposits))

    # Surface every movement whether or not anything failed — a human signing this needs to see
    # the list, not just a verdict.
    record("lamport_movements", True, "itemised below",
           "; ".join(f"ix{m['ix']} {m['kind']} "
                     f"{'?' if m['lamports'] is None else m['lamports']} lamports -> {m['to']}"
                     for m in movements) or "none")

    total_out = sum(m["lamports"] or 0 for m in movements)
    record("total_lamport_movement", total_out == expect_amount_lamports and not undecodable,
           f"{expect_amount_lamports} lamports moved by the instructions in this transaction — "
           "the deposit and nothing else. This is NOT the whole debit: the network fee is also "
           "charged at execution, see additional_charges_at_execution below",
           f"{total_out} lamports" + (" + undecodable instructions" if undecodable else ""))

    # The line above is the one a human actually reads before signing, and on its own it read as
    # "this is what leaves my wallet". It is not: the network fee is charged by the runtime, not
    # by an instruction, so it can never appear in the itemisation. Saying so in the
    # residual-risk section of a review is not saying so to the person holding the key.
    #
    # It used to add the rent-exempt reserve on top as well, and that was WRONG — finding [G12].
    # The program funds the escrow with exactly `amount`, so the reserve comes out of the amount
    # and the debit is amount + fee. Overstating it by 1_454_640 lamports on every single draft
    # is not a harmlessly cautious rounding: this is the figure a person reconciles against their
    # wallet afterwards, and a disclosure that never matches is one they stop reading. The
    # reserve is still stated, because it is why `amount` has a floor and why the recipient
    # receives more than they were promised.
    record("additional_charges_at_execution", True,
           "charged by the runtime, not by an instruction — invisible in the itemisation above",
           f"{fee_lamports} lamports network fee. Approximate total debit: "
           f"~{total_out + fee_lamports} lamports (the deposit + the fee). The escrow account's "
           f"{ESCROW_RENT_LAMPORTS}-lamport rent-exempt reserve for its "
           f"{settlement.STATE_LEN} bytes is NOT charged on top of the deposit: the program "
           f"creates that account with exactly the deposit amount, so the reserve is taken out "
           f"of it and is returned with the funds when whoever claims or reclaims closes the "
           f"account.")

    dests = {m["to"] for m in movements if (m["lamports"] or 0) > 0}
    record("destinations", dests == {str(expected_pda)},
           f"only the escrow {expected_pda}", sorted(dests) or "none")

    how = (f"{fee_detail['compute_unit_limit']} CU x "
           f"{fee_detail['micro_lamports_per_cu']} micro-lamports/CU"
           + ("" if fee_detail["limit_was_explicit"] else " (limit unset — runtime default)")
           + f" = {fee_detail['priority_lamports']} priority"
           + f" + {fee_detail['base_lamports']} base"
           + (f" + {fee_detail['additional_fee_lamports']} additional"
              if fee_detail["additional_fee_lamports"] else ""))
    record("max_transaction_fee", fee_lamports <= max_fee_lamports,
           f"<= {max_fee_lamports} lamports (an honest draft of this shape costs "
           f"{HONEST_TX_FEE_LAMPORTS})",
           f"{fee_lamports} lamports [{how}]"
           + (f" — {fee_lamports / HONEST_TX_FEE_LAMPORTS:.0f}x the honest cost"
              if fee_lamports > HONEST_TX_FEE_LAMPORTS * 2 else ""))

    return VerifyResult(ok=not failures, checks=checks, failures=failures,
                        movements=movements, total_lamports_out=total_out,
                        fee_lamports=fee_lamports, escrow_id_hex=escrow_id_hex)
