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
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts

SYS = Pubkey.from_string("11111111111111111111111111111111")
CB = Pubkey.from_string("ComputeBudget111111111111111111111111111111")
MAINNET_PROGRAM = "GPCsJ6kvrQ61wDG8bpP8315ge7AHfmsUHdxTD7LQ6CoJ"


def program_id() -> Pubkey:
    return Pubkey.from_string(os.environ.get("XETE_SETTLEMENT_PROGRAM", MAINNET_PROGRAM))


def escrow_pda(program: Pubkey, escrow_id: bytes) -> Pubkey:
    return Pubkey.find_program_address([b"escrow", escrow_id], program)[0]


def commitment(recipient: Pubkey, salt: bytes) -> bytes:
    return hashlib.sha256(bytes(recipient) + salt).digest()


def _cb_price(u: int) -> Instruction:
    return Instruction(program_id=CB, data=bytes([3]) + struct.pack("<Q", u), accounts=[])


def _cb_limit(u: int) -> Instruction:
    return Instruction(program_id=CB, data=bytes([2]) + struct.pack("<I", u), accounts=[])


def _send(client: Client, signers, ixs, payer: Keypair, label: str) -> str:
    bh = client.get_latest_blockhash().value.blockhash
    tx = Transaction(signers, Message.new_with_blockhash([_cb_limit(60_000), _cb_price(1_000)] + ixs, payer.pubkey(), bh), bh)
    sig = client.send_transaction(tx, opts=TxOpts(skip_preflight=False, preflight_commitment=Confirmed)).value
    for _ in range(60):
        time.sleep(0.3)
        st = client.get_signature_statuses([sig]).value[0]
        if st and st.confirmation_status:
            if st.err:
                raise RuntimeError(f"{label} failed on-chain: {st.err}")
            return str(sig)
    raise RuntimeError(f"{label} not confirmed")


def deposit(rpc_url: str, depositor: Keypair, recipient: Pubkey, amount_lamports: int):
    """Open a settlement: lock `amount_lamports` for `recipient` (hidden as a commitment). Returns
    (escrow_id_hex, salt_hex, pda_str, sig). The recipient needs escrow_id + salt to claim.

    SPEND GATE. The client-side limits are checked HERE, before the depositor key is used,
    so every caller is covered — not only the MCP tool. `amount_lamports` is the whole value
    being locked away, and once it is locked only the depositor (reclaim) or the hidden
    beneficiary (claim) can move it again."""
    from .spendguard import authorize

    authorize(int(amount_lamports), "xete_settle_create", detail=f"recipient={recipient}")

    client = Client(rpc_url)
    prog = program_id()
    eid = bytes(Keypair().pubkey())        # random 32-byte escrow id (never derived from the recipient)
    salt = bytes(Keypair().pubkey())[:16]  # random salt; shared with the recipient out-of-band
    pda = escrow_pda(prog, eid)
    data = bytes([0]) + eid + struct.pack("<Q", amount_lamports) + commitment(recipient, salt) + struct.pack("<q", 0)
    ix = Instruction(
        program_id=prog,
        data=data,
        accounts=[
            AccountMeta(depositor.pubkey(), True, True),
            AccountMeta(pda, False, True),
            AccountMeta(SYS, False, False),
        ],
    )
    sig = _send(client, [depositor], [ix], depositor, "deposit")
    return eid.hex(), salt.hex(), str(pda), sig


def claim(rpc_url: str, beneficiary: Keypair, escrow_id_hex: str, salt_hex: str):
    """Claim a settlement: prove you're the hidden beneficiary (signature + salt) and receive the
    funds + rent. Returns (sig, lamports_received)."""
    client = Client(rpc_url)
    prog = program_id()
    eid = bytes.fromhex(escrow_id_hex)
    salt = bytes.fromhex(salt_hex)
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
    client = Client(rpc_url)
    prog = program_id()
    eid = bytes.fromhex(escrow_id_hex)
    pda = escrow_pda(prog, eid)
    data = bytes([2]) + eid
    ix = Instruction(
        program_id=prog,
        data=data,
        accounts=[AccountMeta(depositor.pubkey(), True, True), AccountMeta(pda, False, True)],
    )
    return _send(client, [depositor], [ix], depositor, "reclaim")


def status(rpc_url: str, escrow_id_hex: str) -> dict:
    """Is a settlement still open (unclaimed/unreclaimed)? Reads the PDA. A closed account == settled
    (claimed or reclaimed). Returns the depositor + amount while it's open."""
    client = Client(rpc_url)
    prog = program_id()
    pda = escrow_pda(prog, bytes.fromhex(escrow_id_hex))
    info = client.get_account_info(pda, commitment=Confirmed).value
    if info is None:
        return {"escrow_id": escrow_id_hex, "pda": str(pda), "open": False, "note": "settled or never opened"}
    data = bytes(info.data)
    out = {"escrow_id": escrow_id_hex, "pda": str(pda), "open": True, "lamports": info.lamports}
    if len(data) >= 40:
        out["depositor"] = str(Pubkey.from_bytes(data[0:32]))
        out["amount_lamports"] = struct.unpack("<Q", data[32:40])[0]
    return out
