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
        if keys[cix.program_id_index] != program:
            continue
        data = bytes(cix.data)
        if data[:1] == b"\x00" and len(data) == _DEPOSIT_DATA_LEN:
            return data, [keys[i] for i in cix.accounts]
    raise ValueError(f"no deposit (tag 0) instruction for program {program} found in transaction")


def verify_draft(unsigned_tx_b64: str, *, expect_recipient: Pubkey, expect_salt_hex: str,
                 expect_amount_lamports: int, expect_depositor: Pubkey,
                 expect_program: Pubkey | None = None) -> VerifyResult:
    """Independently check that a drafted transaction does what its summary claims.

    Every expectation is supplied by the CALLER, not read out of the draft — that is the whole
    point. Re-deriving sha256(recipient || salt) is what catches a redirected beneficiary, since
    the recipient never appears in the transaction in the clear.
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
             if keys[c.program_id_index] not in (program, settlement.CB, settlement.SYS)]
    record("no_unexpected_programs", not other,
           "only settlement + compute-budget + system", other or "none")

    return VerifyResult(ok=not failures, checks=checks, failures=failures)
