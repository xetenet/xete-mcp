"""Unit tests for the signing guards: what the identity key will and will not sign.

Three defects are covered:

  1. xete_alias_claim signed the permit server's transaction blind. `txguard` decodes
     it against an allow-list first. The tests below build real solders transactions —
     including the reviewer's full-balance drain — and assert each one is refused.
  2. login() signed whatever string the relay sent. `signguard` parses the challenge
     against the exact live template.
  3. The messaging-key derivation constant is refused by the signing path, while the
     derivation itself still produces the same cross-language key.

Run: python -m pytest test_signing_safety.py -q
"""
from __future__ import annotations

import base64
import hashlib
import struct
import time

import nacl.signing
import pytest
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import Transaction

from xete_mcp import txguard
from xete_mcp.signguard import (
    MESSAGING_KEY_DERIVATION_MESSAGE,
    GuardedSigningKey,
    RefusedToSign,
    assert_signable,
    validate_alias_claim_challenge,
    validate_relay_auth_challenge,
)
from xete_mcp.txguard import TransactionRejected

ALIAS_PROGRAM = Pubkey.from_string(txguard.MAINNET_ALIAS_PROGRAM)
# config.names_wallet as the live registry carries it today. There is no longer a
# treasury constant in txguard to import — the treasury is READ from the config account
# (it was rotated on 2026-07-30 and the constant that used to live here had gone stale
# into a total outage), so these offline unit tests pin it the supported offline way:
# the XETE_ALIAS_TREASURY override, set by the autouse fixture below.
TREASURY = Pubkey.from_string("9zHPVcHhBeZBCLcw8NMWvAQqLWmMNBrcuiYVwyUcwFds")
CONFIG = txguard.config_pda(ALIAS_PROGRAM)
SYSTEM = txguard.SYSTEM_PROGRAM
CB = txguard.COMPUTE_BUDGET
BLOCKHASH = Hash.default()
NAME = "mcptestname"
RECORD_KEY = bytes([5] * 32)   # the 32-byte record field; not the owner (see test below)


@pytest.fixture(autouse=True)
def _pin_treasury_offline(monkeypatch):
    """These are offline unit tests: no RPC, so no config account to read.

    Setting the documented override is how a caller pins a treasury without a network,
    and it keeps every "the money may only land HERE" assertion below testing the same
    property it always tested — only the source of the pinned value changed.
    """
    monkeypatch.setenv(txguard.ENV_TREASURY, str(TREASURY))


# ── builders that reproduce the real shapes seen on mainnet ──────────────────────────
# Verified against every claim in the registry's on-chain history:
#   data     02 | u8 name_len | name | 32-byte record key | u64 price (LE)
#   accounts [payer(signer,writable), authority(signer), alias pda(writable),
#             config, treasury, system]

def _claimer() -> Keypair:
    return Keypair.from_seed(bytes([3] * 32))


def _permit_cosigner() -> Keypair:
    return Keypair.from_seed(bytes([9] * 32))


def _claim_data(name: str = NAME, *, price: int = 0, disc: int = 2,
                record: bytes = RECORD_KEY) -> bytes:
    raw = name.encode()
    return bytes([disc, len(raw)]) + raw + record + struct.pack("<Q", price)


def _alias_ix(payer: Pubkey, name: str = NAME, *, pda: Pubkey | None = None,
              price: int = 0, data: bytes | None = None,
              authority: Pubkey | None = None, config: Pubkey | None = None,
              treasury: Pubkey | None = None, system: Pubkey | None = None,
              accounts: list | None = None) -> Instruction:
    """A genuine mainnet-shaped claim instruction, with every field overridable so a
    test can corrupt exactly one of them."""
    pda = pda if pda is not None else txguard.alias_pda(ALIAS_PROGRAM, name)
    if accounts is None:
        accounts = [
            AccountMeta(payer, True, True),
            AccountMeta(authority if authority is not None else payer, True, False),
            AccountMeta(pda, False, True),
            AccountMeta(config if config is not None else CONFIG, False, False),
            AccountMeta(treasury if treasury is not None else TREASURY, False, True),
            AccountMeta(system if system is not None else SYSTEM, False, False),
        ]
    return Instruction(
        program_id=ALIAS_PROGRAM,
        data=data if data is not None else _claim_data(name, price=price),
        accounts=accounts,
    )


def _cb_limit(units: int) -> Instruction:
    return Instruction(program_id=CB, data=bytes([2]) + struct.pack("<I", units), accounts=[])


def _cb_price(micro: int) -> Instruction:
    return Instruction(program_id=CB, data=bytes([3]) + struct.pack("<Q", micro), accounts=[])


def _sys_transfer(src: Pubkey, dst: Pubkey, lamports: int) -> Instruction:
    return Instruction(
        program_id=SYSTEM,
        data=struct.pack("<I", 2) + struct.pack("<Q", lamports),
        accounts=[AccountMeta(src, True, True), AccountMeta(dst, False, True)],
    )


def _sys_raw(tag: int, payload: bytes, accounts: list[AccountMeta]) -> Instruction:
    return Instruction(program_id=SYSTEM, data=struct.pack("<I", tag) + payload, accounts=accounts)


def _encode(ixs, payer: Pubkey, *, cosign: Keypair | None = None) -> str:
    """Serialize like the permit server does: our slot empty, the co-signer's filled."""
    msg = Message.new_with_blockhash(ixs, payer, BLOCKHASH)
    tx = Transaction.new_unsigned(msg)
    if cosign is not None:
        tx.partial_sign([cosign], BLOCKHASH)
    return base64.b64encode(bytes(tx)).decode()


def _inspect(tx_b64: str, *, payer: Pubkey | None = None, name: str = NAME,
             quoted: int = 0, **kw):
    return txguard.inspect_alias_claim(
        tx_b64,
        expect_fee_payer=payer if payer is not None else _claimer().pubkey(),
        expect_name=name,
        quoted_lamports=quoted,
        **kw,
    )


# ── the happy paths must still work ──────────────────────────────────────────────────

def test_single_signer_claim_is_accepted():
    me = _claimer()
    tx_b64 = _encode([_cb_limit(60_000), _cb_price(1_000), _alias_ix(me.pubkey())], me.pubkey())
    _, report = _inspect(tx_b64, payer=me.pubkey())
    assert report.alias_pda == str(txguard.alias_pda(ALIAS_PROGRAM, NAME))
    assert report.static_debit_lamports == 5_000 + 60  # base fee + priority fee, price 0
    assert report.claim_name == NAME and report.claim_price_lamports == 0


def test_permit_cosigned_claim_is_accepted():
    me, permit = _claimer(), _permit_cosigner()
    msg = Message.new_with_blockhash([_alias_ix(me.pubkey(), authority=permit.pubkey())],
                                     me.pubkey(), BLOCKHASH)
    tx = Transaction.new_unsigned(msg)
    tx.partial_sign([permit], BLOCKHASH)
    _, report = _inspect(base64.b64encode(bytes(tx)).decode(), payer=me.pubkey())
    assert report.required_signers == [str(me.pubkey()), str(permit.pubkey())]


def test_priced_claim_within_tolerance_is_accepted():
    """The real shape of a paid claim: the price lives in the instruction data and is
    moved by CPI, so it must be counted as a debit even though no transfer appears."""
    me = _claimer()
    tx_b64 = _encode([_alias_ix(me.pubkey(), price=1_000_000)], me.pubkey())
    _, report = _inspect(tx_b64, payer=me.pubkey(), quoted=1_000_000)
    assert report.claim_price_lamports == 1_000_000
    assert report.static_debit_lamports == 1_000_000 + 5_000
    assert report.transfers[0] == {"position": 0, "via": "cpi", "from": str(me.pubkey()),
                                   "to": str(TREASURY), "lamports": 1_000_000}


def test_name_is_matched_case_insensitively():
    me = _claimer()
    tx_b64 = _encode([_alias_ix(me.pubkey(), "alice")], me.pubkey())
    _inspect(tx_b64, payer=me.pubkey(), name="%Alice")   # user typed %Alice, server normalised


# ── defect 1: the blind-signing attacks ──────────────────────────────────────────────

def test_full_balance_drain_is_rejected():
    """The reviewer's proof: a bare SystemProgram transfer served as the 'claim'."""
    me, attacker = _claimer(), Keypair().pubkey()
    tx_b64 = _encode([_sys_transfer(me.pubkey(), attacker, 4_000_000_000)], me.pubkey())
    # Refused at the System instruction now, one step earlier than "there is no registry
    # instruction here at all" — both are the same refusal, this one is more specific.
    with pytest.raises(TransactionRejected, match="NO top-level System instruction"):
        _inspect(tx_b64, payer=me.pubkey())


def test_a_transaction_with_no_registry_instruction_at_all_is_rejected():
    """The 'nothing but compute budget' shape, which reaches the end of the loop."""
    me = _claimer()
    tx_b64 = _encode([_cb_limit(1_000), _cb_price(1)], me.pubkey())
    with pytest.raises(TransactionRejected, match="no instruction for the alias registry"):
        _inspect(tx_b64, payer=me.pubkey())


def test_drain_smuggled_alongside_a_real_claim_is_rejected():
    """Harder version: a genuine claim instruction with a drain riding along. This is
    what a 'which programs are touched' check (draft.py verify_draft) lets through,
    because SystemProgram is an expected participant."""
    me, attacker = _claimer(), Keypair().pubkey()
    tx_b64 = _encode([_alias_ix(me.pubkey()), _sys_transfer(me.pubkey(), attacker, 4_000_000_000)],
                     me.pubkey())
    with pytest.raises(TransactionRejected, match="NO top-level System instruction"):
        _inspect(tx_b64, payer=me.pubkey())


def test_priority_fee_drain_is_rejected():
    """No transfer anywhere: the wallet is emptied through the prioritization fee."""
    me = _claimer()
    tx_b64 = _encode([_cb_limit(1_400_000), _cb_price(10_000_000), _alias_ix(me.pubkey())],
                     me.pubkey())
    with pytest.raises(TransactionRejected, match="priority fee"):
        _inspect(tx_b64, payer=me.pubkey())


def test_system_assign_of_our_wallet_is_rejected():
    """Assign hands the account to another program. It moves no lamports, so an
    amount-based check never sees it."""
    me, attacker_program = _claimer(), Keypair().pubkey()
    ix = _sys_raw(1, bytes(attacker_program), [AccountMeta(me.pubkey(), True, True)])
    tx_b64 = _encode([_alias_ix(me.pubkey()), ix], me.pubkey())
    with pytest.raises(TransactionRejected, match="SystemProgram Assign"):
        _inspect(tx_b64, payer=me.pubkey())


def test_no_top_level_system_instruction_is_allowed_at_any_amount():
    """Finding #11: the ceiling is chosen by the server it defends against, so a
    transfer to an arbitrary destination used to ride through inside the tolerance.
    Real claims carry no top-level System instruction at all, so the amount is now
    irrelevant — the shape is refused."""
    me, attacker = _claimer(), Keypair().pubkey()
    for amount, quoted in ((4_985_000, 0), (8_000_000, 8_000_000), (1, 0)):
        tx_b64 = _encode([_alias_ix(me.pubkey(), price=quoted),
                          _sys_transfer(me.pubkey(), attacker, amount)], me.pubkey())
        with pytest.raises(TransactionRejected, match="NO top-level System instruction"):
            _inspect(tx_b64, payer=me.pubkey(), quoted=quoted)


def test_transfer_with_seed_is_rejected():
    me = _claimer()
    ix = _sys_raw(11, struct.pack("<Q", 1) + b"\x00" * 40,
                  [AccountMeta(me.pubkey(), True, True), AccountMeta(Keypair().pubkey(), False, True)])
    tx_b64 = _encode([_alias_ix(me.pubkey()), ix], me.pubkey())
    with pytest.raises(TransactionRejected, match="TransferWithSeed"):
        _inspect(tx_b64, payer=me.pubkey())


def test_create_account_owned_by_a_foreign_program_is_rejected():
    """Funding a brand-new account owned by someone else's program is money handed over,
    and it never appears as a 'transfer'."""
    me, new_account, foreign = _claimer(), Keypair(), Keypair().pubkey()
    data = struct.pack("<Q", 1_000_000) + struct.pack("<Q", 165) + bytes(foreign)
    ix = _sys_raw(0, data, [AccountMeta(me.pubkey(), True, True),
                            AccountMeta(new_account.pubkey(), True, True)])
    tx_b64 = _encode([_alias_ix(me.pubkey(), authority=new_account.pubkey()), ix],
                     me.pubkey(), cosign=new_account)
    with pytest.raises(TransactionRejected, match="owned by"):
        _inspect(tx_b64, payer=me.pubkey())


def test_durable_nonce_is_rejected():
    """A durable-nonce transaction never expires — a signature for it can be pocketed
    and submitted whenever the balance is highest."""
    me = _claimer()
    nonce_account = Keypair().pubkey()
    recent_blockhashes = Pubkey.from_string("SysvarRecentB1ockHashes11111111111111111111")
    advance = _sys_raw(4, b"", [AccountMeta(nonce_account, False, True),
                                AccountMeta(recent_blockhashes, False, False),
                                AccountMeta(me.pubkey(), True, False)])
    tx_b64 = _encode([advance, _alias_ix(me.pubkey())], me.pubkey())
    with pytest.raises(TransactionRejected, match="durable nonce"):
        _inspect(tx_b64, payer=me.pubkey())


def test_unknown_program_is_rejected():
    me, other = _claimer(), Keypair().pubkey()
    ix = Instruction(program_id=other, data=b"\x00",
                     accounts=[AccountMeta(me.pubkey(), True, True)])
    tx_b64 = _encode([_alias_ix(me.pubkey()), ix], me.pubkey())
    with pytest.raises(TransactionRejected, match="not the alias registry"):
        _inspect(tx_b64, payer=me.pubkey())


def test_different_name_is_rejected():
    me = _claimer()
    tx_b64 = _encode([_alias_ix(me.pubkey(), "someoneelse")], me.pubkey())
    with pytest.raises(TransactionRejected, match='registers the name "someoneelse"'):
        _inspect(tx_b64, payer=me.pubkey(), name=NAME)


def test_right_name_in_the_data_but_a_different_pda_is_rejected():
    """Belt and braces: the data says the name we asked for, the account it writes is
    somebody else's record."""
    me = _claimer()
    other = txguard.alias_pda(ALIAS_PROGRAM, "someoneelse")
    tx_b64 = _encode([_alias_ix(me.pubkey(), pda=other)], me.pubkey())
    with pytest.raises(TransactionRejected, match="the registry account for the name"):
        _inspect(tx_b64, payer=me.pubkey(), name=NAME)


def test_second_registry_instruction_is_rejected():
    me = _claimer()
    tx_b64 = _encode([_alias_ix(me.pubkey()), _alias_ix(me.pubkey(), "bonusname")], me.pubkey())
    with pytest.raises(TransactionRejected, match="more than one alias-registry"):
        _inspect(tx_b64, payer=me.pubkey())


def test_foreign_fee_payer_is_rejected():
    me, someone = _claimer(), Keypair()
    tx_b64 = _encode([_alias_ix(someone.pubkey())], someone.pubkey())
    with pytest.raises(TransactionRejected, match="fee payer is"):
        _inspect(tx_b64, payer=me.pubkey())


def test_unsigned_cosigner_slot_is_rejected():
    """Two signers required but the permit server has not signed: we would be putting
    the only signature on a transaction someone else completes later."""
    me, permit = _claimer(), _permit_cosigner()
    msg = Message.new_with_blockhash([_alias_ix(me.pubkey(), authority=permit.pubkey())],
                                     me.pubkey(), BLOCKHASH)
    tx_b64 = base64.b64encode(bytes(Transaction.new_unsigned(msg))).decode()
    with pytest.raises(TransactionRejected, match="has not signed"):
        _inspect(tx_b64, payer=me.pubkey())


def test_versioned_transaction_is_rejected():
    """A v0 message resolves accounts through a lookup table the server also controls,
    so account_keys stops describing what is touched."""
    from solders.message import MessageV0
    from solders.transaction import VersionedTransaction

    me = _claimer()
    v0 = MessageV0.try_compile(me.pubkey(), [_alias_ix(me.pubkey())], [], BLOCKHASH)
    vtx = VersionedTransaction.populate(v0, [])
    with pytest.raises(TransactionRejected, match="versioned"):
        _inspect(base64.b64encode(bytes(vtx)).decode(), payer=me.pubkey())


def test_garbage_is_rejected():
    me = _claimer()
    with pytest.raises(TransactionRejected, match="not valid base64"):
        _inspect("!!!not base64!!!", payer=me.pubkey())
    with pytest.raises(TransactionRejected, match="do not deserialize|end before|length prefix"):
        _inspect(base64.b64encode(b"\x01\x02\x03").decode(), payer=me.pubkey())
    with pytest.raises(TransactionRejected, match="no transaction"):
        _inspect(None, payer=me.pubkey())


def test_already_expired_or_nonce_blockhash_is_rejected():
    me = _claimer()
    tx_b64 = _encode([_alias_ix(me.pubkey())], me.pubkey())
    with pytest.raises(TransactionRejected, match="live recent blockhash"):
        _inspect(tx_b64, payer=me.pubkey(), blockhash_is_live=False)


def test_simulated_debit_over_ceiling_is_rejected():
    """The CPI case: nothing in the instruction list moves money, but the program does."""
    txguard.check_debit_within(1_000_000_000, 999_000_000, 5_000_000)  # 1_000_000 debit, fine
    with pytest.raises(TransactionRejected, match="simulating this transaction"):
        txguard.check_debit_within(1_000_000_000, 0, 5_000_000)


# ── finding #9, second half: simulation is the only view of CPI money, so it is not
#    allowed to be "best effort" ──────────────────────────────────────────────────────

def _accepted_claim(price=0, quoted=None):
    me = _claimer()
    tx_b64 = _encode([_alias_ix(me.pubkey(), price=price)], me.pubkey())
    tx, report = _inspect(tx_b64, payer=me.pubkey(),
                          quoted=price if quoted is None else quoted)
    return me, tx_b64, tx, report


def test_an_rpc_that_will_not_answer_fails_closed():
    """A 429 from the public endpoint used to be swallowed into a `simulation_note` and
    the claim went through on a static bound that sees none of the money."""
    me, tx_b64, _, report = _accepted_claim()

    def boom(*_a, **_kw):
        raise RuntimeError("429 Client Error: Too Many Requests")

    with pytest.raises(TransactionRejected, match="could not be simulated"):
        txguard.bounded_simulated_debit("https://rpc.invalid", tx_b64, me.pubkey(), report,
                                        simulate=boom)


def test_turning_simulation_off_costs_the_full_ceiling_at_the_spend_gate(monkeypatch):
    """The escape hatch may not be the cheap path: an unsimulated claim is charged the
    ceiling, so it can never slip under a cap a simulated one would have hit."""
    monkeypatch.setenv(txguard.ENV_REQUIRE_SIMULATION, "0")
    me, tx_b64, _, report = _accepted_claim()

    def boom(*_a, **_kw):
        raise RuntimeError("no route to host")

    simulated, note = txguard.bounded_simulated_debit(
        "https://rpc.invalid", tx_b64, me.pubkey(), report, simulate=boom)
    assert simulated is None and "SIMULATION DID NOT RUN" in note
    assert txguard.spend_charge(0, report, simulated) == report.ceiling_lamports
    assert report.ceiling_lamports > report.static_debit_lamports


def test_a_bad_simulation_switch_fails_closed(monkeypatch):
    monkeypatch.setenv(txguard.ENV_REQUIRE_SIMULATION, "maybe")
    with pytest.raises(TransactionRejected, match="bad configuration"):
        txguard.simulation_required()


def test_simulation_that_runs_bounds_the_measured_debit():
    me, tx_b64, _, report = _accepted_claim(price=1_000_000)
    ok, note = txguard.bounded_simulated_debit(
        "https://rpc.invalid", tx_b64, me.pubkey(), report,
        simulate=lambda *_a, **_k: 2_628_640)
    assert ok == 2_628_640 and note is None
    with pytest.raises(TransactionRejected, match="simulating this transaction"):
        txguard.bounded_simulated_debit("https://rpc.invalid", tx_b64, me.pubkey(), report,
                                        simulate=lambda *_a, **_k: 4_000_000_000)


def test_spend_charge_never_reports_less_than_the_price_in_the_data():
    """`charged = max(quoted, static, simulated)` was fed a static figure of 10,000 on a
    genuine claim. The price is part of the static figure now."""
    _, _, _, report = _accepted_claim(price=3_000_000_000, quoted=3_000_000_000)
    assert txguard.spend_charge(0, report, None) >= 3_000_000_000
    assert txguard.spend_charge(0, report, 3_000_005_000) >= 3_000_000_000


# ── finding #14: the transaction signature is not covered by the signguard wrapper ───

def test_only_the_inspected_message_can_be_signed():
    me, _, tx, report = _accepted_claim()
    other = _encode([_alias_ix(me.pubkey(), "someoneelse")], me.pubkey())
    swapped = Transaction.from_bytes(base64.b64decode(other))
    with pytest.raises(TransactionRejected, match="not the one that was inspected"):
        txguard.approve_and_sign(swapped, report, me)
    assert swapped.signatures[0] == Signature.default()
    txguard.approve_and_sign(tx, report, me)          # the real one still signs
    assert tx.signatures[0] != Signature.default()


def test_a_key_that_is_not_the_inspected_fee_payer_cannot_sign():
    _, _, tx, report = _accepted_claim()
    with pytest.raises(TransactionRejected, match="not the fee payer"):
        txguard.approve_and_sign(tx, report, Keypair())
    assert tx.signatures[0] == Signature.default()


# ── finding #13: reproducible compatibility evidence, from committed mainnet bytes ────
# Instruction data and account lists copied verbatim from mainnet. `expect_fee_payer` is
# the owner recorded in the on-chain alias account, written down here as a constant —
# not read out of the transaction under test, which is the anti-pattern that made the
# previous "6 real transactions ACCEPTED" evidence meaningless.

BOLT_IX_DATA = bytes.fromhex(
    "0204626f6c748a8af2984bca02e02b61ac4463a7630a5770f00ec9a038375aa19236a3d662f1"
    "80f0fa0200000000")
BOLT_OWNER = Pubkey.from_string("2AasdG24GRkM1riiYLFAEvqRp2pGsXX3AgGyorCzc1qw")
BOLT_AUTHORITY = Pubkey.from_string("5Wr3C8yqsmr8BuNCRp7XgiLqiXpzVf4Py9LEVbo35qQE")
BOLT_PDA = Pubkey.from_string("9qrubRpMYdUuksTJkuHhxqkUpo6T2fwx1BTPM8xBH4qP")
BOLT_CONFIG = Pubkey.from_string("2WjYxKwHxEaD5Cp25YfymwxuG6XmyeTg3fs79RwELfms")
BOLT_TREASURY = Pubkey.from_string("CmraiWB8rTfR4td7iC7TmvrjMGbJv1nqkvJsbz2MJaDq")
BOLT_PRICE = 50_000_000

# ZxDXh9vv9ay8Hu… — the transaction the previous report cited as an "ACCEPTED real
# claim". It is discriminator 0x03, which moves a name to a new owner.
DEPLOY_TRANSFER_IX_DATA = bytes.fromhex(
    "03066465706c6f79858a219c2ac677d843477b2bfb12725e028b59368aa65820a32a8517d397c0d2")


def _mainnet_tx(data: bytes, accounts: list[AccountMeta], payer: Pubkey) -> str:
    """Rebuild a mainnet instruction as the permit server would hand it over: our slot
    empty, the co-signer's already filled."""
    msg = Message.new_with_blockhash(
        [Instruction(program_id=ALIAS_PROGRAM, data=data, accounts=accounts)], payer, BLOCKHASH)
    nsig = msg.header.num_required_signatures
    sigs = [Signature.default()] + [Signature.from_bytes(bytes([7] * 64))] * (nsig - 1)
    return base64.b64encode(bytes(Transaction.populate(msg, sigs))).decode()


def test_a_real_mainnet_claim_is_accepted(monkeypatch):
    # The treasury in force when this claim landed. config.names_wallet was rotated on
    # 2026-07-30; replaying a 2026-07 claim against today's value would be an anachronism,
    # so the historical treasury is pinned explicitly for this one replay.
    monkeypatch.setenv(txguard.ENV_TREASURY, str(BOLT_TREASURY))
    tx_b64 = _mainnet_tx(BOLT_IX_DATA, [
        AccountMeta(BOLT_OWNER, True, True),
        AccountMeta(BOLT_AUTHORITY, True, False),
        AccountMeta(BOLT_PDA, False, True),
        AccountMeta(BOLT_CONFIG, False, False),
        AccountMeta(BOLT_TREASURY, False, True),
        AccountMeta(SYSTEM, False, False),
    ], BOLT_OWNER)
    _, report = txguard.inspect_alias_claim(
        tx_b64, expect_fee_payer=BOLT_OWNER, expect_name="bolt",
        quoted_lamports=BOLT_PRICE)
    assert report.claim_name == "bolt"
    assert report.claim_price_lamports == BOLT_PRICE
    assert report.alias_pda == str(BOLT_PDA)
    assert report.treasury == str(BOLT_TREASURY) and report.treasury_pinned
    # 50,000,000 price + 10,000 fee for two signatures. The 1,628,640 of PDA rent is
    # funded by CPI and is covered by the tolerance, not by static decoding.
    assert report.static_debit_lamports == BOLT_PRICE + 10_000


def test_the_transaction_the_old_report_called_a_real_claim_is_not_one():
    tx_b64 = _mainnet_tx(DEPLOY_TRANSFER_IX_DATA, [
        AccountMeta(BOLT_TREASURY, True, True),
        AccountMeta(Pubkey.from_string("85L3tqLBJN517Uu4NtzUqmSkDbmU5uGRik1W3vSvmVC8"),
                    False, True),
        AccountMeta(Pubkey.from_string("9zHPVcHhBeZBCLcw8NMWvAQqLWmMNBrcuiYVwyUcwFds"),
                    True, False),
    ], BOLT_TREASURY)
    with pytest.raises(TransactionRejected, match="operation 0x03"):
        txguard.inspect_alias_claim(tx_b64, expect_fee_payer=BOLT_TREASURY,
                                    expect_name="deploy", quoted_lamports=0)


def test_the_committed_mainnet_bytes_really_are_the_documented_layout():
    """Guards the fixture itself: if someone edits the hex, this notices."""
    assert BOLT_IX_DATA[0] == txguard.CLAIM_DISCRIMINATOR
    assert BOLT_IX_DATA[1] == len("bolt")
    assert BOLT_IX_DATA[2:6] == b"bolt"
    assert struct.unpack("<Q", BOLT_IX_DATA[-8:])[0] == BOLT_PRICE
    assert len(BOLT_IX_DATA) == 42 + len("bolt")
    assert txguard.alias_pda(ALIAS_PROGRAM, "bolt") == BOLT_PDA
    assert txguard.config_pda(ALIAS_PROGRAM) == BOLT_CONFIG


# ── finding #9: the price the claim ACTUALLY moves lives in the instruction data ─────

def test_the_price_u64_in_the_data_must_equal_the_quote():
    """The demonstrated exploit: a correctly-shaped claim whose trailing u64 says three
    SOL, served with `price_lamports: 0`. Every top-level check passed before, because
    the price moves by CPI and no transfer appears anywhere in the instruction list."""
    me = _claimer()
    tx_b64 = _encode([_alias_ix(me.pubkey(), price=3_000_000_000)], me.pubkey())
    with pytest.raises(TransactionRejected, match="will move 3000000000 lamports"):
        _inspect(tx_b64, payer=me.pubkey(), quoted=0)


def test_the_price_is_counted_as_a_debit_even_though_no_transfer_appears():
    """Before the fix, static_debit_lamports was the fee alone (10,000) on every real
    claim, which is what let a 3 SOL claim look cheaper than the tolerance."""
    me = _claimer()
    tx_b64 = _encode([_alias_ix(me.pubkey(), price=3_000_000_000)], me.pubkey())
    with pytest.raises(TransactionRejected, match="visibly debits 3000005000"):
        _inspect(tx_b64, payer=me.pubkey(), quoted=3_000_000_000, tolerance=0)


def test_a_price_under_the_quote_is_also_refused():
    """Equality, not a ceiling: a claim that pays less than quoted is not the claim we
    were sold either, and a server that can vary this field can vary it upward."""
    me = _claimer()
    tx_b64 = _encode([_alias_ix(me.pubkey(), price=1)], me.pubkey())
    with pytest.raises(TransactionRejected, match="will move 1 lamports"):
        _inspect(tx_b64, payer=me.pubkey(), quoted=50_000_000)


# ── finding #10: which OPERATION, not merely which program ───────────────────────────

@pytest.mark.parametrize("disc", [0x00, 0x01, 0x03, 0x05, 0x06, 0x07, 0xFF])
def test_every_registry_operation_that_is_not_the_claim_is_rejected(disc):
    """The registry exposes at least seven operations on mainnet. 0x02 is the claim;
    0x03 transfers a name AWAY, and it is the op in the transaction the previous report
    cited as proof of compatibility."""
    me = _claimer()
    tx_b64 = _encode([_alias_ix(me.pubkey(), data=_claim_data(disc=disc))], me.pubkey())
    with pytest.raises(TransactionRejected, match=f"operation 0x{disc:02x}"):
        _inspect(tx_b64, payer=me.pubkey())


def test_a_long_opaque_registry_instruction_is_rejected():
    """399 random bytes under an unknown discriminator used to pass: data was checked
    only for 'non-empty and <= 512 bytes'."""
    me = _claimer()
    blob = bytes([0xFF]) + bytes(range(256)) * 2
    tx_b64 = _encode([_alias_ix(me.pubkey(), data=blob[:399])], me.pubkey())
    with pytest.raises(TransactionRejected, match="operation 0xff"):
        _inspect(tx_b64, payer=me.pubkey())


def test_trailing_bytes_after_the_price_are_rejected():
    me = _claimer()
    tx_b64 = _encode([_alias_ix(me.pubkey(), data=_claim_data() + b"\x00")], me.pubkey())
    with pytest.raises(TransactionRejected, match="is exactly"):
        _inspect(tx_b64, payer=me.pubkey())


def test_our_wallet_present_but_not_in_the_payer_slot_is_rejected():
    """`expect_fee_payer in accounts` proves presence, not role. Here we are the fee
    payer of the transaction and we appear in the instruction — as the treasury."""
    me, stranger = _claimer(), Keypair().pubkey()
    ix = _alias_ix(me.pubkey(), accounts=[
        AccountMeta(stranger, False, True),
        AccountMeta(me.pubkey(), True, True),
        AccountMeta(txguard.alias_pda(ALIAS_PROGRAM, NAME), False, True),
        AccountMeta(CONFIG, False, False),
        AccountMeta(me.pubkey(), True, True),
        AccountMeta(SYSTEM, False, False),
    ])
    tx_b64 = _encode([ix], me.pubkey())
    with pytest.raises(TransactionRejected, match="payer slot holds"):
        _inspect(tx_b64, payer=me.pubkey())


def test_a_claim_with_the_wrong_number_of_accounts_is_rejected():
    me = _claimer()
    short = _alias_ix(me.pubkey()).accounts[:5]
    tx_b64 = _encode([_alias_ix(me.pubkey(), accounts=list(short))], me.pubkey())
    with pytest.raises(TransactionRejected, match="names 5 accounts"):
        _inspect(tx_b64, payer=me.pubkey())


def test_an_unsigned_claim_authority_is_rejected():
    """Position 1 must be a required signer: without the permit co-signature nothing
    but us has approved this claim."""
    me, stranger = _claimer(), Keypair().pubkey()
    tx_b64 = _encode([_alias_ix(me.pubkey(), accounts=[
        AccountMeta(me.pubkey(), True, True),
        AccountMeta(stranger, False, False),          # authority, NOT a signer
        AccountMeta(txguard.alias_pda(ALIAS_PROGRAM, NAME), False, True),
        AccountMeta(CONFIG, False, False),
        AccountMeta(TREASURY, False, True),
        AccountMeta(SYSTEM, False, False),
    ])], me.pubkey())
    with pytest.raises(TransactionRejected, match="not a required signer"):
        _inspect(tx_b64, payer=me.pubkey())


def test_a_substituted_config_account_is_rejected():
    me = _claimer()
    tx_b64 = _encode([_alias_ix(me.pubkey(), config=Keypair().pubkey())], me.pubkey())
    with pytest.raises(TransactionRejected, match="config slot holds"):
        _inspect(tx_b64, payer=me.pubkey())


def test_a_read_only_alias_account_is_rejected():
    me = _claimer()
    pda = txguard.alias_pda(ALIAS_PROGRAM, NAME)
    tx_b64 = _encode([_alias_ix(me.pubkey(), accounts=[
        AccountMeta(me.pubkey(), True, True),
        AccountMeta(me.pubkey(), True, True),
        AccountMeta(pda, False, False),               # read-only: nothing gets written
        AccountMeta(CONFIG, False, False),
        AccountMeta(TREASURY, False, True),
        AccountMeta(SYSTEM, False, False),
    ])], me.pubkey())
    with pytest.raises(TransactionRejected, match="read-only"):
        _inspect(tx_b64, payer=me.pubkey())


# ── finding #11: where the money lands ───────────────────────────────────────────────

def test_the_price_may_only_be_paid_to_the_xete_treasury():
    """The price moves by CPI to whatever sits in account slot 4, so this slot is where
    a hostile permit server points the money at itself — at a price the quote 'agrees'
    with, so no amount check fires."""
    me, attacker = _claimer(), Keypair().pubkey()
    tx_b64 = _encode([_alias_ix(me.pubkey(), price=50_000_000, treasury=attacker)], me.pubkey())
    with pytest.raises(TransactionRejected, match="would pay"):
        _inspect(tx_b64, payer=me.pubkey(), quoted=50_000_000)


def test_the_treasury_can_be_repointed_by_configuration(monkeypatch):
    me, other = _claimer(), Keypair().pubkey()
    monkeypatch.setenv(txguard.ENV_TREASURY, str(other))
    tx_b64 = _encode([_alias_ix(me.pubkey(), treasury=other)], me.pubkey())
    _, report = _inspect(tx_b64, payer=me.pubkey())
    assert report.treasury == str(other) and report.treasury_pinned
    monkeypatch.setenv(txguard.ENV_TREASURY, "not-an-address")
    with pytest.raises(TransactionRejected, match="bad configuration"):
        _inspect(tx_b64, payer=me.pubkey())


def test_an_unpinnable_treasury_is_reported_rather_than_assumed(monkeypatch):
    """On a local validator there is no honest default; the inspection says so instead
    of silently accepting any destination while looking like it checked."""
    local = Keypair()
    monkeypatch.delenv(txguard.ENV_TREASURY, raising=False)
    monkeypatch.setenv(txguard.ENV_ALIAS_PROGRAM, str(local.pubkey()))
    me, anyone = _claimer(), Keypair().pubkey()
    ix = Instruction(program_id=local.pubkey(), data=_claim_data(),
                     accounts=[AccountMeta(me.pubkey(), True, True),
                               AccountMeta(me.pubkey(), True, True),
                               AccountMeta(txguard.alias_pda(local.pubkey(), NAME), False, True),
                               AccountMeta(txguard.config_pda(local.pubkey()), False, False),
                               AccountMeta(anyone, False, True),
                               AccountMeta(SYSTEM, False, False)])
    _, report = _inspect(_encode([ix], me.pubkey()), payer=me.pubkey())
    assert report.treasury_pinned is False and report.treasury == ""


# ── raised by the doubt pass on this change, not by the review ───────────────────────

def test_a_repeated_compute_budget_op_is_rejected():
    """Two SetComputeUnitPrice instructions leave 'the' priority fee ambiguous. The
    runtime rejects the duplicate too, but the guard must not have to guess which value
    it is bounding."""
    me = _claimer()
    tx_b64 = _encode([_cb_price(1), _cb_price(10_000_000), _alias_ix(me.pubkey())], me.pubkey())
    with pytest.raises(TransactionRejected, match="appears twice"):
        _inspect(tx_b64, payer=me.pubkey())


def test_the_record_key_is_reported_and_can_be_pinned():
    """The 32-byte field a claim writes into the record is the on-chain agent_id (permit
    cosign.rs ClaimParts.agent_id -> wire::data_claim). Nothing on chain validates it, so
    it is pinned here or nowhere; `record_key_pinned` says which happened rather than
    letting the report imply a check that did not run."""
    me = _claimer()
    tx_b64 = _encode([_alias_ix(me.pubkey())], me.pubkey())
    _, report = _inspect(tx_b64, payer=me.pubkey())
    assert report.record_key == str(Pubkey.from_bytes(RECORD_KEY))
    assert report.record_key_pinned is False
    _, pinned = _inspect(tx_b64, payer=me.pubkey(), expect_record_key=RECORD_KEY)
    assert pinned.record_key_pinned is True
    _inspect(tx_b64, payer=me.pubkey(), expect_record_key=RECORD_KEY)
    with pytest.raises(TransactionRejected, match="would bind %mcptestname to agent id"):
        _inspect(tx_b64, payer=me.pubkey(), expect_record_key=bytes(32))


def test_the_pda_is_derived_from_the_matched_name_bytes():
    """The PDA is derived from the BYTES that were matched — no decode/re-encode step
    sits between the check and the derivation.

    This used to be demonstrated with a non-ASCII name. It no longer can be, and that is
    the point: the only name a claim may carry is the canonical registrable form, which
    is ASCII by construction, so the round trip that this test guarded against cannot
    exist. The non-ASCII case is now refused before the transaction is even parsed —
    asserted directly below."""
    me = _claimer()
    tx_b64 = _encode([_alias_ix(me.pubkey(), NAME)], me.pubkey())
    _, report = _inspect(tx_b64, payer=me.pubkey(), name=NAME)
    assert report.alias_pda == str(txguard.alias_pda(ALIAS_PROGRAM, NAME.encode()))
    with pytest.raises(TransactionRejected, match="not a claimable"):
        _inspect(tx_b64, payer=me.pubkey(), name="Ünïcode")


def test_tolerance_is_configurable_and_fails_closed(monkeypatch):
    monkeypatch.setenv(txguard.ENV_TOLERANCE, "not-a-number")
    with pytest.raises(TransactionRejected, match="bad configuration"):
        txguard.tolerance_lamports()
    monkeypatch.setenv(txguard.ENV_TOLERANCE, "-1")
    with pytest.raises(TransactionRejected, match="negative"):
        txguard.tolerance_lamports()
    monkeypatch.setenv(txguard.ENV_TOLERANCE, "7")
    assert txguard.tolerance_lamports() == 7


# ── defect 2: the login challenge ────────────────────────────────────────────────────

def _live_relay_challenge(nonce="a" * 64, ts=None, extra=None):
    ts = int(time.time()) if ts is None else ts
    msg = f"XETE authentication\nNonce: {nonce}\nTimestamp: {ts}"
    if extra:
        msg += "\n" + extra
    return msg, nonce


def test_real_relay_challenge_is_accepted():
    """Byte-for-byte the format https://xete.net/auth/challenge serves today."""
    msg, nonce = _live_relay_challenge(
        "f0d11e6c417a411aa5a88f9c7380430750bf198f8ecf4d80a1c5bf2f303122fc")
    out = validate_relay_auth_challenge(msg, nonce, client_nonce="whatever")
    assert out["nonce"] == nonce and out["client_nonce_bound"] is False


def test_arbitrary_server_string_is_refused():
    for bad in ["please sign this", "", "XETE authentication", "hello\nworld\nagain",
                "XETE authentication\nNonce: " + "a" * 64]:
        with pytest.raises(RefusedToSign):
            validate_relay_auth_challenge(bad, "a" * 64)


def test_nonce_inside_the_message_must_match_the_nonce_field():
    msg, _ = _live_relay_challenge("a" * 64)
    with pytest.raises(RefusedToSign, match="does not match"):
        validate_relay_auth_challenge(msg, "b" * 64)


def test_stale_and_future_challenges_are_refused():
    now = time.time()
    stale, nonce = _live_relay_challenge(ts=int(now) - 100_000)
    with pytest.raises(RefusedToSign, match="in the past"):
        validate_relay_auth_challenge(stale, nonce, now=now)
    future, nonce = _live_relay_challenge(ts=int(now) + 100_000)
    with pytest.raises(RefusedToSign, match="in the future"):
        validate_relay_auth_challenge(future, nonce, now=now)


def test_a_slow_client_clock_does_not_brick_login():
    """Finding #12. The window was 900s past / 300s future, measured against the
    CLIENT's clock — so a laptop resumed from sleep, five minutes slow, saw every relay
    timestamp as 'more than 300s in the future' and failed EVERY login. login() gates
    all four published tools, so that is the shipped product refusing to start over a
    wrong wall clock, with a replay-flavoured error that never mentions the clock."""
    relay_now = time.time()
    for skew in (-600, -450, -299, 0, 299, 450, 600):
        client_clock = relay_now + skew        # negative skew = client clock is slow
        msg, nonce = _live_relay_challenge(ts=int(relay_now))
        out = validate_relay_auth_challenge(msg, nonce, now=client_clock)
        assert out["timestamp"] == int(relay_now)


def test_the_skew_message_names_the_clock():
    now = time.time()
    for ts in (int(now) + 100_000, int(now) - 100_000):
        msg, nonce = _live_relay_challenge(ts=ts)
        with pytest.raises(RefusedToSign, match="wrong local clock"):
            validate_relay_auth_challenge(msg, nonce, now=now)


def test_the_skew_window_is_symmetric():
    from xete_mcp import signguard

    assert signguard.MAX_CHALLENGE_FUTURE_SECONDS == signguard.MAX_CHALLENGE_AGE_SECONDS


def test_client_nonce_is_enforced_the_moment_the_relay_echoes_it():
    mine = "clientnonce123"
    msg, nonce = _live_relay_challenge(extra=f"Client-Nonce: {mine}")
    assert validate_relay_auth_challenge(msg, nonce, client_nonce=mine)["client_nonce_bound"]
    bad, nonce = _live_relay_challenge(extra="Client-Nonce: someone-elses")
    with pytest.raises(RefusedToSign, match="not this client's own nonce"):
        validate_relay_auth_challenge(bad, nonce, client_nonce=mine)


def test_alias_claim_challenge_template():
    """Byte-for-byte the format https://xete.net/alias/claim/challenge serves today."""
    pub = "11111111111111111111111111111111"
    nonce = "48aSgGfAhcHvDJwwFNG3jh"
    ts = int(time.time())
    good = f"xete alias claim\npubkey:{pub}\nnonce:{nonce}\nts:{ts}"
    assert validate_alias_claim_challenge(good, nonce, pub)["nonce"] == nonce
    other = f"xete alias claim\npubkey:{'2' * 32}\nnonce:{nonce}\nts:{ts}"
    with pytest.raises(RefusedToSign, match="addressed to"):
        validate_alias_claim_challenge(other, nonce, pub)
    with pytest.raises(RefusedToSign):
        validate_alias_claim_challenge("xete alias claim", nonce, pub)


# ── defect 3: the messaging-key derivation oracle ────────────────────────────────────

def test_the_derivation_constant_can_never_be_signed():
    with pytest.raises(RefusedToSign, match="reserved xete domain constant"):
        assert_signable(MESSAGING_KEY_DERIVATION_MESSAGE, context="test")
    with pytest.raises(RefusedToSign, match="reserved xete domain constant"):
        assert_signable(b"prefix " + MESSAGING_KEY_DERIVATION_MESSAGE + b" suffix", context="test")


def test_guarded_key_refuses_the_constant_but_signs_a_real_challenge():
    seed = bytes([7] * 32)
    guarded = GuardedSigningKey(nacl.signing.SigningKey(seed))
    with pytest.raises(RefusedToSign):
        guarded.sign(MESSAGING_KEY_DERIVATION_MESSAGE)
    msg, _ = _live_relay_challenge()
    assert len(guarded.sign(msg.encode()).signature) == 64
    assert bytes(guarded.verify_key) == bytes(nacl.signing.SigningKey(seed).verify_key)


def test_the_derivation_itself_still_works_and_still_matches_the_gold_vector():
    """The oracle is closed; the key derivation it exists for is untouched. These are
    the cross-language vectors from test_crypto_unification.py."""
    from xete_mcp.client import Identity, derive_x25519_secret

    seed = bytes([7] * 32)
    assert derive_x25519_secret(seed).hex() == (
        "34355869ba9f8e4356fe0d9bcaab1dbc2523c8477d12c2d28b64d2aa9cd8583d")
    assert Identity(ed_seed=seed).x_public.hex() == (
        "709bc66516f43417139932e423964700e91cea7718c75f90dd72b0bba662e670")
    sig = nacl.signing.SigningKey(seed).sign(MESSAGING_KEY_DERIVATION_MESSAGE).signature
    assert derive_x25519_secret(seed) == hashlib.sha256(sig).digest()


def test_identity_signing_key_is_guarded():
    from xete_mcp.client import Identity

    ident = Identity(ed_seed=bytes([11] * 32))
    with pytest.raises(RefusedToSign):
        ident.signing_key.sign(MESSAGING_KEY_DERIVATION_MESSAGE)
    # ...and still produces the same pubkey it always did
    import base58
    assert ident.pubkey_b58 == base58.b58encode(
        bytes(nacl.signing.SigningKey(bytes([11] * 32)).verify_key)).decode()


def test_binary_payloads_are_refused():
    """A serialized Solana message starts with a header byte below 0x20 and carries raw
    pubkeys, so the printable-ASCII rule stops the auth endpoint being used to sign one."""
    me = _claimer()
    raw_message = bytes(Message.new_with_blockhash([_alias_ix(me.pubkey())], me.pubkey(), BLOCKHASH))
    with pytest.raises(RefusedToSign, match="non-printable"):
        assert_signable(raw_message, context="test")
    with pytest.raises(RefusedToSign, match="over the"):
        assert_signable(b"x" * 5000, context="test")
