#!/usr/bin/env python3
"""Replay every real %alias claim on mainnet through txguard.inspect_alias_claim.

WHY THIS SCRIPT IS IN THE REPO
The previous round's compatibility evidence ("6 real mainnet AXTREG transactions
ACCEPTED") was not reproducible: the script was never committed, and it could only have
reached ACCEPT by reading `expect_fee_payer` out of the transaction it was validating —
the exact anti-pattern txguard's own docstring forbids. This script fixes both halves.

HOW IT AVOIDS THE CIRCULARITY
Every expectation is fetched from a source OTHER than the transaction under test:

  expect_fee_payer   the owner field of the on-chain alias RECORD (byte 0..32 of the
                     106-byte account), fetched with getAccountInfo;
  expect_name        the name field of that same record (bytes 32..32+name_len);
  quoted_lamports    the inner CPI System transfer actually observed in the
                     transaction's METADATA — the lamports that really moved, which the
                     instruction data is then required to agree with. Zero when the
                     claim moved nothing;
  treasury           the DESTINATION of that inner CPI transfer, read from the
                     transaction's metadata — i.e. where the money provably went, not
                     what the instruction's account list claims. txguard now reads the
                     treasury from config.names_wallet, and that field is ROTATABLE (it
                     was rotated on 2026-07-30), so replaying a historical claim against
                     today's value would fail for a reason that has nothing to do with
                     the guard. A free claim moves nothing, so it offers no independent
                     source at all and is replayed with the treasury unpinned, which the
                     output says.

Read-only. It makes getSignaturesForAddress / getTransaction / getAccountInfo calls and
signs nothing.

    python scripts/verify_mainnet_claims.py [--rpc URL] [--limit N]
"""
from __future__ import annotations

import argparse
import base64
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import base58                                                    # noqa: E402
import requests                                                  # noqa: E402
from solders.hash import Hash                                    # noqa: E402
from solders.instruction import AccountMeta, Instruction         # noqa: E402
from solders.message import Message                              # noqa: E402
from solders.pubkey import Pubkey                                # noqa: E402
from solders.signature import Signature                          # noqa: E402
from solders.transaction import Transaction                      # noqa: E402

from xete_mcp import txguard                                     # noqa: E402

SYSTEM = "11111111111111111111111111111111"
RECORD_NAME_OFFSET = 32
RECORD_NAME_LEN_OFFSET = 64


def rpc(url: str, method: str, params: list):
    for attempt in range(8):
        r = requests.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method,
                                     "params": params}, timeout=30)
        if r.status_code == 429:
            time.sleep(1.5 * (attempt + 1))
            continue
        r.raise_for_status()
        body = r.json()
        if "error" in body:
            raise RuntimeError(f"{method}: {body['error']}")
        return body["result"]
    raise RuntimeError(f"{method}: rate limited after 8 attempts")


def record_owner_and_name(url: str, pda: str) -> tuple[str, str] | None:
    """The independent source of truth: what the registry account itself says."""
    info = rpc(url, "getAccountInfo", [pda, {"encoding": "base64"}])["value"]
    if not info or not info.get("data"):
        return None
    data = base64.b64decode(info["data"][0])
    if len(data) < RECORD_NAME_LEN_OFFSET + 1:
        return None
    owner = base58.b58encode(data[:32]).decode()
    name_len = data[RECORD_NAME_LEN_OFFSET]
    name = data[RECORD_NAME_OFFSET:RECORD_NAME_OFFSET + name_len].decode()
    return owner, name


def rebuild(program: Pubkey, data: bytes, accounts: list[str], signers: set[str],
            writables: set[str], payer: Pubkey) -> str:
    """The transaction as the permit server hands it over: our slot empty, the
    co-signer's already filled. Instruction data and account order are byte-identical
    to what landed on chain."""
    metas = [AccountMeta(Pubkey.from_string(a), a in signers, a in writables)
             for a in accounts]
    msg = Message.new_with_blockhash(
        [Instruction(program_id=program, data=data, accounts=metas)], payer, Hash.default())
    nsig = msg.header.num_required_signatures
    sigs = [Signature.default()] + [Signature.from_bytes(bytes([7] * 64))] * (nsig - 1)
    return base64.b64encode(bytes(Transaction.populate(msg, sigs))).decode()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default="https://api.mainnet-beta.solana.com")
    ap.add_argument("--limit", type=int, default=200)
    args = ap.parse_args()

    program = Pubkey.from_string(txguard.MAINNET_ALIAS_PROGRAM)
    sigs, before = [], None
    while len(sigs) < args.limit:
        params = [str(program), {"limit": min(100, args.limit - len(sigs))}]
        if before:
            params[1]["before"] = before
        batch = rpc(args.rpc, "getSignaturesForAddress", params)
        if not batch:
            break
        sigs += batch
        before = batch[-1]["signature"]

    accepted = rejected = skipped = 0
    for entry in sigs:
        if entry.get("err"):
            continue
        tx = rpc(args.rpc, "getTransaction",
                 [entry["signature"], {"encoding": "json", "maxSupportedTransactionVersion": 0}])
        if tx is None:
            continue
        msg, meta = tx["transaction"]["message"], tx["meta"]
        keys, header = msg["accountKeys"], msg["header"]
        nsig = header["numRequiredSignatures"]
        signers = set(keys[:nsig])
        writables = {k for i, k in enumerate(keys)
                     if (i < nsig - header["numReadonlySignedAccounts"]) or
                        (nsig <= i < len(keys) - header["numReadonlyUnsignedAccounts"])}

        for ix in msg["instructions"]:
            if keys[ix["programIdIndex"]] != str(program):
                continue
            data = base58.b58decode(ix["data"])
            if not data or data[0] != txguard.CLAIM_DISCRIMINATOR:
                skipped += 1
                continue
            accounts = [keys[i] for i in ix["accounts"]]
            if len(accounts) < 3:
                skipped += 1
                continue

            # ── expectations, from anywhere but the transaction under test ──────────
            found = record_owner_and_name(args.rpc, accounts[txguard.IX_ALIAS_PDA])
            if found is None:
                skipped += 1
                print(f"SKIPPED   {entry['signature'][:16]}  the alias record no longer exists, "
                      "so there is no independent source for the expectations")
                continue
            owner, name = found
            if owner != keys[0]:
                # The record's owner is the only non-circular source for expect_fee_payer,
                # and a name that has been TRANSFERRED since it was claimed no longer names
                # its original claimant. Skipped rather than validated against the
                # transaction's own fee payer, which would be the circularity this script
                # exists to avoid.
                skipped += 1
                print(f"SKIPPED   {entry['signature'][:16]}  %{name} has changed owner since "
                      "this claim; the record can no longer supply the expected fee payer")
                continue
            # Where the money PROVABLY went, from the executed inner instructions —
            # not from the account list the guard is being asked to validate. A free
            # claim moves nothing and therefore names no treasury independently.
            treasury, moved = None, 0
            for inner in meta.get("innerInstructions") or []:
                for iix in inner["instructions"]:
                    if keys[iix["programIdIndex"]] != SYSTEM:
                        continue
                    d = base58.b58decode(iix["data"])
                    if len(d) == 12 and struct.unpack("<I", d[:4])[0] == 2:
                        src, dst = (keys[a] for a in iix["accounts"])
                        if src == owner:
                            treasury = dst
                            moved += struct.unpack("<Q", d[4:12])[0]

            rebuilt = rebuild(program, data, accounts, signers, writables,
                              Pubkey.from_string(owner))
            try:
                _, report = txguard.inspect_alias_claim(
                    rebuilt, expect_fee_payer=Pubkey.from_string(owner),
                    expect_name=name, quoted_lamports=moved,
                    treasury=Pubkey.from_string(treasury) if treasury else None)
            except txguard.TransactionRejected as e:
                rejected += 1
                print(f"REJECTED  {entry['signature'][:16]}  %{name}\n          {e}")
            else:
                accepted += 1
                print(f"ACCEPTED  {entry['signature'][:16]}  %{report.claim_name:<20} "
                      f"price={report.claim_price_lamports:<10} moved={moved:<10} "
                      f"static_debit={report.static_debit_lamports} "
                      f"treasury={report.treasury or '<unpinned: free claim moved nothing>'}")

    print(f"\n{accepted} real claims accepted, {rejected} rejected, "
          f"{skipped} non-claim registry operations skipped.")
    return 1 if rejected else 0


if __name__ == "__main__":
    raise SystemExit(main())
