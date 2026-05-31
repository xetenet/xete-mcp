"""On-chain PayHerd payment for the MCP server.

Sending a message costs SOL (anti-spam). After /agent/send-multi returns an
invoice, the sender pays the xete payment contract on-chain, then calls
/agent/confirm-payment. This mirrors the proven concierge flow.

Money-critical constants are hardcoded here (not server-supplied): the program
id and treasury cannot be redirected by a malicious server.
"""
from __future__ import annotations

import hashlib
import struct

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.instruction import AccountMeta, Instruction
from solders.message import Message
from solders.system_program import ID as SYSTEM_PROGRAM_ID
from solders.transaction import Transaction
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts

PROGRAM_ID = Pubkey.from_string("GLdM82RspCLDFmAUqty2Ef8GBGursZVgMD9cqeNHDq2U")
TREASURY = Pubkey.from_string("XETEsj7sRmSQf1PHVU9FkmZW2n8z75UycWRrpJ8tRMv")
LAMPORTS_PER_BLOB = 1_000_000  # 0.001 SOL


def _derive_pda(nonce: str) -> tuple[Pubkey, int]:
    d = hashlib.sha256(nonce.encode()).digest()
    return Pubkey.find_program_address([b"payment", d[:16]], PROGRAM_ID)


def _encode_payherd(nonce: str, blob_count: int) -> bytes:
    nb = nonce.encode()
    return struct.pack("<I", len(nb)) + nb + struct.pack("<B", blob_count)


def pay_herd(rpc_url: str, payer: Keypair, payment_nonce: str, blob_count: int) -> str:
    """Build, sign, submit, and confirm the PayHerd tx. Returns the signature."""
    client = Client(rpc_url)
    pda, _ = _derive_pda(payment_nonce)
    ix = Instruction(
        program_id=PROGRAM_ID,
        accounts=[
            AccountMeta(payer.pubkey(), is_signer=True, is_writable=True),
            AccountMeta(pda, is_signer=False, is_writable=True),
            AccountMeta(TREASURY, is_signer=False, is_writable=True),
            AccountMeta(SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False),
        ],
        data=_encode_payherd(payment_nonce, blob_count),
    )
    bh = client.get_latest_blockhash().value.blockhash
    tx = Transaction([payer], Message.new_with_blockhash([ix], payer.pubkey(), bh), bh)
    sig = client.send_transaction(tx, opts=TxOpts(skip_preflight=False, preflight_commitment=Confirmed)).value
    # confirm
    import time
    for _ in range(30):
        time.sleep(0.5)
        st = client.get_signature_statuses([sig]).value[0]
        if st and st.confirmation_status:
            break
    return str(sig)


def sol_balance(rpc_url: str, pubkey: Pubkey) -> float:
    return Client(rpc_url).get_balance(pubkey, commitment=Confirmed).value / 1e9
