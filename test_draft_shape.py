"""`verify_draft` must refuse any transaction that is not the exact shape of an honest deposit.

FOUR PROBES FROM AN INDEPENDENT REVIEW OF draft.py, all of which came back `ok=True,
failures=none` -- i.e. SAFE TO REVIEW AND SIGN -- against a verifier whose entire promise is
that it refuses anything that is not the deposit that was asked for.

The root cause of three of them is that `destinations` and `total_lamport_movement` are both
VALUE-WEIGHTED: a zero-lamport instruction contributes 0 to the total and is filtered out of
the destination list, so it is structurally invisible to every arithmetic check in the file.
An attacker does not need to move value to do damage.

  A1  A zero-lamport, zero-space system CreateAccount. Decodes cleanly, contributes nothing,
      passes everything -- and the RUNTIME rejects the whole transaction, because a 0-byte
      account is not rent-exempt. The human spends a signature and a fee, the escrow is never
      funded, and the tool said it was safe. Identical harm class to the [G12] rent finding
      this file already has a comment about.

  A2  An AdvanceNonceAccount naming an ARBITRARY nonce account. `_system_movement` marks
      tag 4 `expected: True` unconditionally and nothing compares the account to anything the
      caller supplied. THE ONLY ONE WITH AN EFFECT OUTSIDE THIS TRANSACTION: advancing a
      durable nonce invalidates every transaction already queued against it, so the signature
      a human gives for a deposit silently kills an unrelated pending transaction of theirs.
      Note the asymmetry it exposes -- `draft_deposit` checks the nonce authority on chain
      before building, so the BUILDER is careful about nonce identity and the VERIFIER, which
      is the half that faces a hostile builder, did not check it at all.

  A3  An AdvanceNonceAccount anywhere other than index 0. `draft_deposit`'s own comment says
      "MUST be the first instruction, or the runtime rejects the nonce"; the verifier never
      checked the position. Same harm as A1: a wasted fee on a transaction that cannot land.

  A4  A zero-lamport transfer to an attacker-chosen address. Executes fine, so no wasted fee
      -- it writes an interaction between the signer's wallet and an address the attacker
      picked into the permanent public record, on a signature given for a deposit.

THE FIX IS A SHAPE WHITELIST, NOT MORE ARITHMETIC. The honest draft is a closed set: at most
one advance_nonce AT INDEX 0, exactly one compute-unit limit, exactly one compute-unit price,
exactly one settlement tag-0 deposit, and nothing else. Checking the decoded instruction KINDS
against that sequence kills A1, A3 and A4 together -- including any future zero-value system
instruction nobody has thought of yet -- which patching `destinations` to stop filtering on
`lamports > 0` would not: that fixes A1 and A4 and leaves A3 alive.

A2 needs its own answer, because no shape check can tell an intended nonce account from an
attacker-chosen one. It gets `expect_nonce_account`.

CONTROL FIRST. Every probe below is built from the honest draft and uses only instructions
the verifier decodes WITHOUT error, so `every_instruction_decoded` stays green and nothing is
refused on a technicality. The control test asserts the honest draft still verifies -- a
verifier that refuses everything passes every probe here and is worthless.
"""
from __future__ import annotations

import base64
import struct
import sys
from pathlib import Path

import pytest
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "src"))

from xete_mcp import draft, settlement  # noqa: E402

SYS = settlement.SYS
DEPOSITOR = Keypair()
RECIPIENT = Keypair()
NONCE_ACCT = Keypair().pubkey()
ATTACKER = Keypair().pubkey()
AMOUNT = settlement.RENT_EXEMPT_LAMPORTS + 5_000_000
SALT = bytes(range(16))


def _advance_nonce(nonce_pubkey: Pubkey, authority: Pubkey) -> Instruction:
    return Instruction(
        program_id=SYS, data=struct.pack("<I", 4),
        accounts=[AccountMeta(nonce_pubkey, False, True),
                  AccountMeta(Pubkey.from_string("SysvarRecentB1ockHashes11111111111111111111"),
                              False, False),
                  AccountMeta(authority, True, False)])


def _create_account(new_account: Pubkey, lamports: int = 0, space: int = 0) -> Instruction:
    """The A1 probe. New account NOT marked a signer, or `single_signer` refuses it for the
    wrong reason and the guard under test never runs."""
    data = struct.pack("<I", 0) + struct.pack("<Q", lamports) + struct.pack("<Q", space) + bytes(SYS)
    return Instruction(program_id=SYS, data=data,
                       accounts=[AccountMeta(DEPOSITOR.pubkey(), True, True),
                                 AccountMeta(new_account, False, True)])


def _transfer(to: Pubkey, lamports: int = 0) -> Instruction:
    data = struct.pack("<I", 2) + struct.pack("<Q", lamports)
    return Instruction(program_id=SYS, data=data,
                       accounts=[AccountMeta(DEPOSITOR.pubkey(), True, True),
                                 AccountMeta(to, False, True)])


def _build(extra: list[Instruction], *, nonce_first: Instruction | None = None):
    """An honest deposit, with `extra` spliced in. Returns (b64, escrow_id_hex)."""
    prog = settlement.program_id()
    escrow_id = bytes(Keypair().pubkey())
    commitment = settlement.commitment(RECIPIENT.pubkey(), SALT)
    ixs: list[Instruction] = []
    if nonce_first is not None:
        ixs.append(nonce_first)
    ixs += [settlement._cb_limit(60_000), settlement._cb_price(1_000)]
    ixs += extra
    ixs.append(settlement.deposit_ix(prog, DEPOSITOR.pubkey(), escrow_id, AMOUNT, commitment))
    from solders.hash import Hash

    msg = Message.new_with_blockhash(ixs, DEPOSITOR.pubkey(), Hash.default())
    tx = Transaction.new_unsigned(msg)
    return base64.b64encode(bytes(tx)).decode(), escrow_id.hex()


def _verify(b64, escrow_hex, **kw):
    return draft.verify_draft(
        b64, expect_recipient=RECIPIENT.pubkey(), expect_salt_hex=SALT.hex(),
        expect_amount_lamports=AMOUNT, expect_depositor=DEPOSITOR.pubkey(),
        expect_escrow_id_hex=escrow_hex, **kw)


def _assert_reached_the_shape_check(r):
    """A refusal by `single_signer`, `deserialize` or `legacy_transaction` means the probe was
    malformed and the guard under test never ran.

    This is the discipline from BM-a-red-that-came-from-the-wrong-cause, and it is not
    theoretical here: the independent reviewer's first probe came back REFUSED and was nearly
    written up as "the verifier catches this" -- it had marked the attacker account as a
    signer, which bumped `num_required_signatures` to 2 and tripped `single_signer` instead.
    """
    for wrong in ("single_signer", "deserialize", "legacy_transaction", "unsigned",
                  "fee_payer_is_depositor", "deposit_instruction_present"):
        assert wrong not in r.failures, (
            f"probe is malformed: refused by {wrong!r}, so the shape check never ran. "
            f"failures={r.failures}")


# ── control ────────────────────────────────────────────────────────────────────────────


def test_an_honest_draft_still_verifies():
    """THE CONTROL. Without this every probe below is satisfied by a verifier that refuses
    everything, which would be a worse tool than the one with the holes."""
    b64, eid = _build([])
    r = _verify(b64, eid)
    assert r.ok, f"an honest deposit was refused: {r.failures}"
    assert not r.failures


def test_an_honest_draft_with_a_durable_nonce_still_verifies():
    b64, eid = _build([], nonce_first=_advance_nonce(NONCE_ACCT, DEPOSITOR.pubkey()))
    r = _verify(b64, eid, expect_nonce_account=NONCE_ACCT)
    assert r.ok, f"an honest durable-nonce deposit was refused: {r.failures}"


# ── the four probes ────────────────────────────────────────────────────────────────────


def test_a1_a_zero_lamport_create_account_is_refused():
    b64, eid = _build([_create_account(Keypair().pubkey())])
    r = _verify(b64, eid)
    _assert_reached_the_shape_check(r)
    assert not r.ok, (
        "a zero-lamport, zero-space CreateAccount was CERTIFIED. It contributes 0 to every "
        "value-weighted check and the runtime then rejects the whole transaction for rent, so "
        "the human pays a fee for a deposit that never happens")


def test_a2_an_unexpected_nonce_account_is_refused():
    """The only finding with an effect OUTSIDE this transaction."""
    b64, eid = _build([], nonce_first=_advance_nonce(ATTACKER, DEPOSITOR.pubkey()))
    r = _verify(b64, eid, expect_nonce_account=NONCE_ACCT)
    _assert_reached_the_shape_check(r)
    assert not r.ok, (
        "an AdvanceNonceAccount naming an account the caller never asked for was CERTIFIED. "
        "Advancing a durable nonce invalidates every transaction already queued against it, "
        "so this signature silently kills an unrelated pending transaction of the signer's")


def test_a2_a_nonce_advance_is_refused_when_the_caller_expected_none():
    """No `expect_nonce_account` means the caller is not doing durable-nonce deposits at all,
    so a nonce advance is an instruction they never asked for and cannot see the effect of."""
    b64, eid = _build([], nonce_first=_advance_nonce(ATTACKER, DEPOSITOR.pubkey()))
    r = _verify(b64, eid)
    _assert_reached_the_shape_check(r)
    assert not r.ok, "a nonce advance was certified for a caller who expects no nonce at all"


def test_a3_a_nonce_advance_outside_position_zero_is_refused():
    b64, eid = _build([_advance_nonce(NONCE_ACCT, DEPOSITOR.pubkey())])
    r = _verify(b64, eid, expect_nonce_account=NONCE_ACCT)
    _assert_reached_the_shape_check(r)
    assert not r.ok, (
        "an AdvanceNonceAccount outside index 0 was CERTIFIED. draft_deposit's own comment "
        "says it MUST be first or the runtime rejects the nonce -- another fee spent on a "
        "transaction that cannot land")


def test_a4_a_zero_lamport_transfer_to_a_stranger_is_refused():
    b64, eid = _build([_transfer(ATTACKER, 0)])
    r = _verify(b64, eid)
    _assert_reached_the_shape_check(r)
    assert not r.ok, (
        "a zero-lamport transfer to an attacker-chosen address was CERTIFIED. It executes, so "
        "no fee is wasted -- it writes an interaction between the signer's wallet and that "
        "address into the permanent public record, on a signature given for a deposit")


# ── the shape check must not be satisfiable by reordering or duplication ───────────────


def test_a_duplicated_compute_budget_instruction_is_refused():
    """The whitelist is a SEQUENCE, not a set membership test. Two price instructions decode
    cleanly and are individually 'expected'; the honest draft has exactly one."""
    b64, eid = _build([settlement._cb_price(1_000)])
    r = _verify(b64, eid)
    _assert_reached_the_shape_check(r)
    assert not r.ok, "a duplicated compute-budget instruction was certified"


def test_a_second_deposit_instruction_is_refused():
    """Two deposits double what leaves the wallet. The amount check reads ONE of them."""
    prog = settlement.program_id()
    extra_id = bytes(Keypair().pubkey())
    commitment = settlement.commitment(RECIPIENT.pubkey(), SALT)
    b64, eid = _build([settlement.deposit_ix(prog, DEPOSITOR.pubkey(), extra_id, AMOUNT,
                                             commitment)])
    r = _verify(b64, eid)
    _assert_reached_the_shape_check(r)
    assert not r.ok, "a transaction containing TWO deposits was certified"


# ── the tool must actually SUPPLY the expectation ──────────────────────────────────────


def test_the_verify_tool_passes_the_operators_configured_nonce_account(monkeypatch):
    """The wiring, pinned separately from the check.

    `expect_nonce_account` defaults to None, so a verifier with a perfect nonce check and a
    tool that never passes the argument is indistinguishable from no fix at all -- and that
    is exactly what the mutation run found: removing the server's argument left every other
    test in this file green. A guard is only as real as its caller.

    The value must come from the OPERATOR'S CONFIG. Taking it from the draft would be
    circular: the hostile drafter chooses the draft.
    """
    from xete_mcp import server

    seen = {}

    def _spy(*a, **kw):
        seen.update(kw)
        return draft.VerifyResult(ok=True, checks=[], failures=[])

    monkeypatch.setattr(server.draft, "verify_draft", _spy)
    monkeypatch.setattr(server, "NONCE_ACCOUNT", str(NONCE_ACCT))
    monkeypatch.setattr(server, "DEPOSITOR_WALLET", str(DEPOSITOR.pubkey()))
    monkeypatch.setattr(server, "_resolve_recipient_corroborated",
                        lambda r, purpose: (RECIPIENT.pubkey(), "test", None))

    fn = getattr(server.xete_verify_settlement_tx, "fn", server.xete_verify_settlement_tx)
    fn("dGVzdA==", str(RECIPIENT.pubkey()), SALT.hex(), 0.01)

    assert "expect_nonce_account" in seen, (
        "xete_verify_settlement_tx never passed expect_nonce_account, so the nonce identity "
        "check is dead on the only path that matters")
    assert str(seen["expect_nonce_account"]) == str(NONCE_ACCT), (
        f"the tool passed {seen['expect_nonce_account']!r}, not the operator's configured "
        f"XETE_NONCE_ACCOUNT")
