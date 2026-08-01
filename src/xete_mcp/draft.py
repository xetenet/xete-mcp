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
# priority fee, plus 5_000 base. A cap of 0.001 SOL is ~16x that and still refuses a fee bomb by
# four orders of magnitude.
MAX_TX_FEE_LAMPORTS = 1_000_000

_SYS_CREATE_ACCOUNT = 0
_SYS_TRANSFER = 2
_SYS_CREATE_ACCOUNT_WITH_SEED = 3
_SYS_ADVANCE_NONCE = 4
_SYS_WITHDRAW_NONCE = 5
_SYS_TRANSFER_WITH_SEED = 11


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
            return {"program": "system", "kind": "system:create_account_with_seed",
                    "lamports": _u64(data, 44 + seed_len), "from": acct(0), "to": acct(1),
                    "decoded": True}
    except (struct.error, IndexError, ValueError):
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
        except struct.error:
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
        accts = [keys[i] for i in cix.accounts if i < len(keys)]
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
    """Locate the settlement deposit instruction and return (data, resolved account pubkeys)."""
    msg = tx.message
    keys = list(msg.account_keys)
    for cix in msg.instructions:
        if cix.program_id_index >= len(keys) or keys[cix.program_id_index] != program:
            continue
        data = bytes(cix.data)
        if data[:1] == b"\x00" and len(data) == _DEPOSIT_DATA_LEN:
            return data, [keys[i] for i in cix.accounts]
    raise ValueError(f"no deposit (tag 0) instruction for program {program} found in transaction")


def verify_draft(unsigned_tx_b64: str, *, expect_recipient: Pubkey, expect_salt_hex: str,
                 expect_amount_lamports: int, expect_depositor: Pubkey,
                 expect_program: Pubkey | None = None,
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
        tx = Transaction.from_bytes(raw)
    except Exception as e:
        return VerifyResult(ok=False, checks=[{"name": "deserialize", "ok": False,
                                               "expected": "a valid Solana transaction",
                                               "actual": str(e)[:200]}],
                            failures=["deserialize"])

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

    escrow_id = data[1:33]
    amount = struct.unpack("<Q", data[33:41])[0]
    commitment_in_tx = data[41:73]
    unlock = struct.unpack("<q", data[73:81])[0]

    record("amount", amount == expect_amount_lamports, expect_amount_lamports, amount)

    # The load-bearing check: does the hidden beneficiary actually resolve to who we were told?
    try:
        salt = bytes.fromhex(expect_salt_hex)
        expected_commitment = hashlib.sha256(bytes(expect_recipient) + salt).digest()
        ok = expected_commitment == commitment_in_tx
    except ValueError:
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
           f"{expect_amount_lamports} lamports (the deposit and nothing else)",
           f"{total_out} lamports" + (" + undecodable instructions" if undecodable else ""))

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
           f"<= {max_fee_lamports} lamports", f"{fee_lamports} lamports [{how}]")

    return VerifyResult(ok=not failures, checks=checks, failures=failures,
                        movements=movements, total_lamports_out=total_out,
                        fee_lamports=fee_lamports)
