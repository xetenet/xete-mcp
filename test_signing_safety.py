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
SYSTEM = txguard.SYSTEM_PROGRAM
CB = txguard.COMPUTE_BUDGET
BLOCKHASH = Hash.default()
NAME = "mcptestname"


# ── builders that reproduce the real shapes seen on mainnet ──────────────────────────

def _claimer() -> Keypair:
    return Keypair.from_seed(bytes([3] * 32))


def _permit_cosigner() -> Keypair:
    return Keypair.from_seed(bytes([9] * 32))


def _alias_ix(payer: Pubkey, name: str = NAME, *, pda: Pubkey | None = None) -> Instruction:
    """The registry instruction, shaped like the real mainnet claim:
    accounts [payer(signer,writable), alias pda(writable), system, config]."""
    pda = pda if pda is not None else txguard.alias_pda(ALIAS_PROGRAM, name)
    return Instruction(
        program_id=ALIAS_PROGRAM,
        data=b"\x01" + len(name).to_bytes(4, "little") + name.encode(),
        accounts=[
            AccountMeta(payer, True, True),
            AccountMeta(pda, False, True),
            AccountMeta(SYSTEM, False, False),
        ],
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
    assert report.static_debit_lamports == 5_000 + 60  # base fee + priority fee
    assert report.transfers == []


def test_permit_cosigned_claim_is_accepted():
    me, permit = _claimer(), _permit_cosigner()
    ixs = [_alias_ix(me.pubkey())]
    msg = Message.new_with_blockhash(ixs, me.pubkey(), BLOCKHASH)
    # two required signers: fee payer (us) + the permit authority
    msg = Message.new_with_blockhash(
        [Instruction(program_id=ALIAS_PROGRAM,
                     data=b"\x01",
                     accounts=[AccountMeta(me.pubkey(), True, True),
                               AccountMeta(permit.pubkey(), True, False),
                               AccountMeta(txguard.alias_pda(ALIAS_PROGRAM, NAME), False, True)])],
        me.pubkey(), BLOCKHASH)
    tx = Transaction.new_unsigned(msg)
    tx.partial_sign([permit], BLOCKHASH)
    _, report = _inspect(base64.b64encode(bytes(tx)).decode(), payer=me.pubkey())
    assert report.required_signers == [str(me.pubkey()), str(permit.pubkey())]


def test_price_transfer_within_tolerance_is_accepted():
    me = _claimer()
    treasury = Pubkey.from_string("XETEsj7sRmSQf1PHVU9FkmZW2n8z75UycWRrpJ8tRMv")
    tx_b64 = _encode([_alias_ix(me.pubkey()), _sys_transfer(me.pubkey(), treasury, 1_000_000)],
                     me.pubkey())
    _, report = _inspect(tx_b64, payer=me.pubkey(), quoted=1_000_000)
    assert report.transfers[0]["lamports"] == 1_000_000


def test_name_is_matched_case_insensitively():
    me = _claimer()
    tx_b64 = _encode([_alias_ix(me.pubkey(), "alice")], me.pubkey())
    _inspect(tx_b64, payer=me.pubkey(), name="%Alice")   # user typed %Alice, server normalised


# ── defect 1: the blind-signing attacks ──────────────────────────────────────────────

def test_full_balance_drain_is_rejected():
    """The reviewer's proof: a bare SystemProgram transfer served as the 'claim'."""
    me, attacker = _claimer(), Keypair().pubkey()
    tx_b64 = _encode([_sys_transfer(me.pubkey(), attacker, 4_000_000_000)], me.pubkey())
    with pytest.raises(TransactionRejected, match="no instruction for the alias registry"):
        _inspect(tx_b64, payer=me.pubkey())


def test_drain_smuggled_alongside_a_real_claim_is_rejected():
    """Harder version: a genuine claim instruction with a drain riding along. This is
    what a 'which programs are touched' check (draft.py verify_draft) lets through,
    because SystemProgram is an expected participant."""
    me, attacker = _claimer(), Keypair().pubkey()
    tx_b64 = _encode([_alias_ix(me.pubkey()), _sys_transfer(me.pubkey(), attacker, 4_000_000_000)],
                     me.pubkey())
    with pytest.raises(TransactionRejected, match="visibly debits"):
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
    tx_b64 = _encode([_alias_ix(me.pubkey()), ix], me.pubkey(), cosign=new_account)
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
    with pytest.raises(TransactionRejected, match="does not touch the account"):
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
    msg = Message.new_with_blockhash(
        [Instruction(program_id=ALIAS_PROGRAM, data=b"\x01",
                     accounts=[AccountMeta(me.pubkey(), True, True),
                               AccountMeta(permit.pubkey(), True, False),
                               AccountMeta(txguard.alias_pda(ALIAS_PROGRAM, NAME), False, True)])],
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
