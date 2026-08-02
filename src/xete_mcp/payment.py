"""On-chain PayHerd payment for the MCP server.

Sending a message costs SOL (anti-spam). After /agent/send-multi returns an
invoice, the sender pays the xete payment contract on-chain, then calls
/agent/confirm-payment. This mirrors the proven concierge flow.

Money-critical constants are hardcoded here (not server-supplied): the program
id and treasury cannot be redirected by a malicious server.
"""
from __future__ import annotations

import hashlib
import secrets
import struct
import time

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.instruction import AccountMeta, Instruction
from solders.message import Message
from solders.system_program import ID as SYSTEM_PROGRAM_ID
from solders.transaction import Transaction
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed
from solders.transaction_status import TransactionConfirmationStatus
from solana.rpc.core import RPCException
from solana.rpc.types import TxOpts

PROGRAM_ID = Pubkey.from_string("GLdM82RspCLDFmAUqty2Ef8GBGursZVgMD9cqeNHDq2U")
TREASURY = Pubkey.from_string("XETEsj7sRmSQf1PHVU9FkmZW2n8z75UycWRrpJ8tRMv")
LAMPORTS_PER_BLOB = 1_000_000  # 0.001 SOL


_DURABLE = (TransactionConfirmationStatus.Confirmed, TransactionConfirmationStatus.Finalized)


class PaymentNotSettled(RuntimeError):
    """Submitted, but this client cannot say it succeeded. ALWAYS carries the signature.

    Split from a bare RuntimeError because the caller's remedy differs completely from an
    ordinary failure: the transaction may be live, so the one thing it must not do is
    silently retry. The signature is the whole recovery path.
    """

    def __init__(self, message: str, *, signature: str):
        super().__init__(message)
        self.signature = signature


class PaymentUnconfirmed(PaymentNotSettled):
    """No durable status inside the window. It may still land."""


class PaymentFailedOnChain(PaymentNotSettled):
    """Confirmed, and the transaction errored. It definitively did not pay."""


def _derive_pda(nonce: str) -> tuple[Pubkey, int]:
    d = hashlib.sha256(nonce.encode()).digest()
    return Pubkey.find_program_address([b"payment", d[:16]], PROGRAM_ID)


def _encode_payherd(nonce: str, blob_count: int) -> bytes:
    nb = nonce.encode()
    return struct.pack("<I", len(nb)) + nb + struct.pack("<B", blob_count)


SEND_PATH_LABEL = "xete_send_message"


def _attempt_detail(payment_nonce: str, blob_count: int) -> str:
    """The ledger `detail` for one attempt, led by a token unique to THIS call.

    The token is what makes a release safe. Without it the detail is
    `blobs=<n> nonce=<server-supplied>`, which is not unique: the relay chooses
    `payment_nonce` and can repeat it, and two concurrent sends with the same nonce and
    blob count produce byte-identical entries. A release then deletes whichever matched
    — possibly the entry belonging to the OTHER call, the one that already reached
    `send_transaction` and must never be released.

    It leads the string because spendguard truncates `detail` to 200 characters and the
    server-chosen nonce is unbounded; a token at the tail could be truncated away.
    """
    return f"attempt={secrets.token_hex(8)} blobs={blob_count} nonce={payment_nonce}"


def _release_recorded_spend(detail: str, charged: int, path_label: str = SEND_PATH_LABEL) -> None:
    """Give back a spend that was recorded and then provably never happened.

    spendguard records at APPROVAL time and offers no release, deliberately: once a
    transaction has been submitted, "it failed" and "it landed and the receipt was
    lost" are the same observation from here, and over-counting is the safe direction
    for a ceiling. That reasoning is sound — and it does not reach a
    `get_latest_blockhash` that raised ConnectError. Nothing was built, nothing was
    signed, nothing was submitted, no lamport can possibly have moved. Charging those
    meant 25 attempts against an unreachable or 429ing RPC locked the agent out of its
    24-hour window having spent exactly zero.

    So this removes exactly the ONE entry just written for THIS attempt, identified by
    the unique token `_attempt_detail` put at the front of the detail string — not by
    anything the relay chose. Two concurrent sends can no longer match each other's
    entries, which is what made an earlier version able to release an entry belonging to
    a call that HAD reached `send_transaction`. It runs under spendguard's own exclusive
    lock and atomic replace, because a rollback that raced a concurrent write would be a
    worse bug than the over-count it fixes. Nothing else in the ledger is touched, so a
    rollback can only ever return budget this same call consumed — it cannot lift the
    ceiling (test_rolling_the_ledger_back_does_not_grant_more_than_the_window).

    `path_label` defaults to this module's own send path, which is what every existing
    caller wants. It is a PARAMETER because the identical pre-submission window exists on
    the %alias claim path, and hardcoding the label there meant the release matched nothing
    and silently did not fire -- the entry stayed, the window still drained, and every test
    that only checked "the code calls release" would have passed.

    Every failure is swallowed. If the entry cannot be given back the spend simply stays
    counted, which is the conservative direction and exactly the old behaviour.
    """
    try:
        from .spendguard import (LEDGER_VERSION, _ExclusiveLock, _read_ledger,
                                 _write_ledger, ledger_path)

        path = ledger_path()
        if not path.exists():
            return
        stored = str(detail)[:200]      # spendguard truncates `detail` on the way in
        with _ExclusiveLock(path.with_name(f"{path.name}.lock")):
            data = _read_ledger(path)
            entries = list(data["entries"])
            for i in range(len(entries) - 1, -1, -1):
                e = entries[i]
                if (e.get("path") == path_label and e.get("detail") == stored
                        and e.get("lamports") == charged):
                    del entries[i]
                    break
            else:
                return          # not ours to give back; leave the ledger alone
            _write_ledger(path, {"version": LEDGER_VERSION,
                                 "last_ts": data["last_ts"],
                                 "entries": entries})
    except Exception:
        pass


def pay_herd(rpc_url: str, payer: Keypair, payment_nonce: str, blob_count: int,
             declared_lamports: int | None = None) -> str:
    """Build, sign, submit, and confirm the PayHerd tx. Returns the signature.

    SPEND GATE. The client-side limits are checked HERE, before anything is built or
    signed — before the RPC client is even constructed — so every caller of this
    function is covered, not only the MCP tool.

    `declared_lamports` is the amount the server quoted for this send. It is only ever
    used to RAISE the figure the limits see. The baseline is derived on this side from
    `blob_count`, which is what actually goes into the instruction being signed, so a
    server that understates its own price cannot shrink the number that gets checked.

    WHAT HAPPENS WHEN THE ATTEMPT DIES BEFORE SUBMISSION. Approval is recorded up front,
    so an attempt that then fails has already consumed window budget. That is right for
    anything at or past `send_transaction` and wrong for everything before it: a dead
    RPC is not an ambiguous outcome, it is proof that no transaction exists. So the
    pre-submission span — connecting, fetching the blockhash, building and signing
    locally — releases the recorded spend on failure and re-raises. From
    `send_transaction` onward nothing is released: the transaction may be on the
    cluster whatever the client saw.
    """
    from .spendguard import authorize

    derived = max(int(blob_count), 0) * LAMPORTS_PER_BLOB
    detail = _attempt_detail(payment_nonce, blob_count)
    approval = authorize(max(int(declared_lamports or 0), derived), SEND_PATH_LABEL,
                         detail=detail)

    # ── pre-submission: refundable, because nothing can have left ──────────────────
    try:
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
    except BaseException:
        _release_recorded_spend(detail, int(approval["charged_lamports"]))
        raise

    # ── FROM HERE THE TRANSACTION MAY BE LIVE. Nothing below is ever released. ──────
    #
    # The signature is taken from the transaction we built, not from the endpoint's reply,
    # so a submit that raises after the write still leaves us able to name what may be live.
    sig_local = tx.signatures[0]

    # THE SPLIT IS TWO-BRANCH, NOT A BLANKET WRAP, and that is deliberate.
    # `DDR-settlement-submit-receipt-20260801` D2 records a reviewer's blanket
    # `except Exception` here as an over-correction: it turned every deterministic
    # rejection into "MAY BE LIVE", which tells an agent not to retry the very thing it
    # should fix. An endpoint that ANSWERED with a refusal and an endpoint that never
    # answered are different facts and get different reports.
    #
    # NOTE ON MESSAGE ORDER, both branches: OUR signature leads. The tools truncate
    # `str(e)` at 300-400 characters and the endpoint chooses its own text, so a message
    # that ends with "check signature X" can lose X while attacker-supplied
    # signature-shaped text survives at the front.
    try:
        returned = client.send_transaction(
            tx, opts=TxOpts(skip_preflight=False, preflight_commitment=Confirmed)).value
    except RPCException as e:
        # The node simulated it (skip_preflight=False) and declined to forward it. Nothing
        # moved. Reported as the failure it is — but WITH the signature, because an
        # endpoint lying about not having forwarded it looks exactly like this from here.
        raise PaymentNotSettled(
            f"the payment was REJECTED at submit: signature {sig_local}. The endpoint "
            f"simulated it and refused to forward it, so it did not execute and nothing "
            f"was paid. Fix the cause and retry. (If you have reason to doubt that "
            f"endpoint, check the signature on chain first — a node that refused a "
            f"transaction it had already forwarded would look identical.) Endpoint said: "
            f"{type(e).__name__}: {str(e)[:160]}", signature=str(sig_local)) from e
    except Exception as e:                      # noqa: BLE001 — deliberate, see above
        # NO ANSWER. An endpoint that forwarded the transaction and then dropped the
        # socket on the reply is indistinguishable, from this client, from one that never
        # forwarded it. The signature was computed locally two lines above for exactly
        # this moment, and it used to die here — leaving the caller with a bare exception,
        # no signature, and every incentive to retry. `send_multi` mints a fresh nonce per
        # call, so that retry is NOT idempotent: it pays a second time.
        raise PaymentUnconfirmed(
            f"the payment MAY ALREADY BE LIVE: check signature {sig_local} on chain "
            f"BEFORE retrying or discarding anything. The transaction is SIGNED and the "
            f"submit call failed without an answer from the endpoint. This is NOT a "
            f"confirmed failure, and a blind retry pays twice. Submit error was: "
            f"{type(e).__name__}: {str(e)[:160]}", signature=str(sig_local)) from e

    # THE ENDPOINT DOES NOT GET TO NAME OUR TRANSACTION. `settlement.py` refuses this and
    # explains why; this module was the second instance, not the counter-example. If the
    # returned string were adopted, the entire recovery story — "check signature X on
    # chain" — would confirm a STRANGER'S transaction as ours, and the poll below would
    # ask a possibly-hostile endpoint about a transaction it chose. Free check, so make
    # it, and poll the local value regardless of what came back.
    if str(returned) != str(sig_local):
        raise PaymentUnconfirmed(
            f"SIGNATURE MISMATCH: this client signed {sig_local}, and that is the only "
            f"transaction to look for. The endpoint answered with a different signature, "
            f"so nothing it says about either transaction can be trusted. The payment MAY "
            f"BE LIVE — check ours against a different endpoint before retrying or "
            f"discarding anything. It returned: {str(returned)[:96]}",
            signature=str(sig_local))
    sig = sig_local

    # This loop used to `break` on ANY confirmation_status and then `return str(sig)` when
    # it simply ran out — so a payment that never confirmed, or that CONFIRMED WITH AN
    # ERROR, was reported to the caller as sent. Three separate ways to certify a payment
    # that did not happen:
    #
    #   1. falling out of the loop after 15s returned success with no status at all;
    #   2. `Processed` was accepted, and settlement.py in this same package refuses it in
    #      as many words -- "one validator's opinion, and it can still be forked away";
    #   3. `st.err` was never read, so a transaction that landed and FAILED read as success.
    #
    # Now nothing but a durable, error-free status returns normally.
    last_status = None
    for _ in range(30):
        time.sleep(0.5)
        try:
            st = client.get_signature_statuses([sig]).value[0]
        except Exception:
            # A polling failure is not evidence about the transaction. Keep waiting; the
            # signature is already known locally, so nothing is lost by an unreadable poll.
            continue
        if st is None:
            continue
        last_status = st
        if st.err is not None:
            raise PaymentFailedOnChain(
                f"the payment transaction {sig_local} was confirmed on chain and FAILED. "
                "Nothing was delivered and the network fee was still spent.", signature=str(sig_local))
        if st.confirmation_status in _DURABLE:
            return str(sig)

    raise PaymentUnconfirmed(
        f"the payment transaction {sig_local} was submitted but did not reach a durable "
        f"commitment within 15s (last status: {last_status.confirmation_status if last_status else 'none'}). "
        "IT MAY STILL LAND. Do not retry blindly -- check this signature on chain first, "
        "or the same payment can be made twice.", signature=str(sig_local))


def sol_balance(rpc_url: str, pubkey: Pubkey) -> float:
    return Client(rpc_url).get_balance(pubkey, commitment=Confirmed).value / 1e9
