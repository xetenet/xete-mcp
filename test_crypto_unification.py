"""Unit test: xete-mcp messaging key is unified with House Elf AND the browser.

Proves the fix for the cross-interface [undecryptable] bug. Every xete interface
derives the x25519 messaging key the SAME way — from a WALLET SIGNATURE, the only
input a browser wallet (Phantom) can reproduce:
    sig          = ed25519_sign(ed_seed, MESSAGING_SIG_MESSAGE)
    x25519_secret = SHA256(sig)

The decisive check is the GOLD vector: these exact bytes were produced
independently by x25519-dalek/ed25519-dalek (House Elf) AND tweetnacl (the
browser inbox / Phantom). If xete-mcp's nacl derivation matches them, all three
interfaces are interoperable by construction.

Run: .venv/Scripts/python test_crypto_unification.py   (no server needed)
"""
import base64
import hashlib
import json
import os
import sys

import nacl.signing

from xete_mcp.client import (
    Identity,
    derive_x25519_secret,
    encrypt,
    decrypt,
    MESSAGING_SIG_MESSAGE,
)

# Gold vectors generated 2026-06-14 by THREE independent libraries (ed25519-dalek,
# pynacl, tweetnacl) for seed=[7]*32:
#   sig = ed25519_sign(seed, b"xete messaging key derivation v1"); x = SHA256(sig)
SEED7 = bytes([7] * 32)
GOLD_SECRET = "34355869ba9f8e4356fe0d9bcaab1dbc2523c8477d12c2d28b64d2aa9cd8583d"
GOLD_PUBLIC = "709bc66516f43417139932e423964700e91cea7718c75f90dd72b0bba662e670"

results = []
def chk(name, cond, detail=""):
    results.append(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' - ' + detail) if detail else ''}")


print("=== xete-mcp <-> House Elf <-> browser messaging-key unification ===")

# 1. derive_x25519_secret == SHA256(ed25519_sign(seed, CANON)), and deterministic.
sig = nacl.signing.SigningKey(SEED7).sign(MESSAGING_SIG_MESSAGE).signature
chk("derive == SHA256(ed25519_sign(seed, CANON))",
    derive_x25519_secret(SEED7) == hashlib.sha256(sig).digest())
chk("derive is deterministic", derive_x25519_secret(SEED7) == derive_x25519_secret(SEED7))
chk("canonical message is the agreed wire constant",
    MESSAGING_SIG_MESSAGE == b"xete messaging key derivation v1")

# 2. THE cross-language proof: xete-mcp output == HE/browser GOLD vectors.
chk("derived secret matches cross-language gold", derive_x25519_secret(SEED7).hex() == GOLD_SECRET,
    derive_x25519_secret(SEED7).hex())
ident7 = Identity(ed_seed=SEED7)
chk("x_public matches cross-language gold", ident7.x_public.hex() == GOLD_PUBLIC, ident7.x_public.hex())

# 3. The invariant holds for freshly generated identities.
g = Identity.generate()
chk("generate(): x_secret == derive(ed_seed)", g.x_secret == derive_x25519_secret(g.ed_seed))
chk("generate(): x_public is 32 bytes", len(g.x_public) == 32)

# 4. Legacy self-heal: a keystore that stored a RANDOM x_secret must be ignored;
#    from_json re-derives the correct key from ed_seed.
bogus = os.urandom(32)
legacy_json = json.dumps({
    "ed_seed": base64.b64encode(SEED7).decode(),
    "x_secret": base64.b64encode(bogus).decode(),   # the old random key — must be discarded
    "agent_id": "legacy-agent",
})
healed = Identity.from_json(legacy_json)
chk("legacy from_json ignores stored random x_secret", healed.x_secret != bogus)
chk("legacy from_json re-derives correct key", healed.x_secret == derive_x25519_secret(SEED7))
chk("legacy heal yields gold-matching public", healed.x_public.hex() == GOLD_PUBLIC)
chk("legacy from_json preserves agent_id", healed.agent_id == "legacy-agent")

# 5. to_json/from_json round-trips to the same (derived) identity.
rt = Identity.from_json(g.to_json())
chk("to_json/from_json round-trip", rt.ed_seed == g.ed_seed and rt.x_secret == g.x_secret)

# 6. Real E2E round-trip between two derived identities (the actual use case).
alice = Identity(ed_seed=bytes([44] * 32))
bob = Identity(ed_seed=bytes([55] * 32))
msg = "coordinate: execute trade A then ping me"
nonce_b64, ct_b64 = encrypt(alice.x_secret, bob.x_public, msg)
back = decrypt(bob.x_secret, alice.x_public, nonce_b64, ct_b64)
chk("A->B encrypt/decrypt round-trips", back == msg)
mallory = Identity(ed_seed=bytes([99] * 32))
try:
    decrypt(mallory.x_secret, alice.x_public, nonce_b64, ct_b64)
    chk("eavesdropper cannot decrypt", False, "decrypt unexpectedly succeeded")
except Exception:
    chk("eavesdropper cannot decrypt", True)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
