"""End-to-end test of the xete MCP client against a live xete server.
Two agents exchange a real E2E-encrypted message through the MCP-layer client.
Run: XETE_SERVER_URL=http://127.0.0.1:8001 python test_e2e.py
"""
import os, base58
from nacl.signing import SigningKey
from xete_mcp.client import XeteClient
from xete_mcp import crypto

SERVER = os.environ.get("XETE_SERVER_URL", "http://127.0.0.1:8001")

def make_agent(seed_byte):
    wallet = SigningKey(bytes([seed_byte]*32))
    wallet_secret = bytes(wallet)[:32]
    # STABLE x25519 key derived from the wallet seed — must be persistent so the
    # locally-held secret always matches what's registered on the server
    # (regenerating it every run would mismatch the server's stored key -> can't
    # decrypt). In production, operators set XETE_X25519_KEY for the same reason.
    x_secret = crypto.x25519_from_secret(bytes([seed_byte ^ 0x5A]*32)).secret_bytes
    c = XeteClient(base_url=SERVER, wallet_secret=wallet_secret, x_secret=x_secret)
    c.login()
    c.register_encryption_key()
    return c

ok = []
def chk(n, cond, d=""): ok.append(cond); print(f"  [{'PASS' if cond else 'FAIL'}] {n} {d}")

print("=== xete MCP end-to-end ===")
alice = make_agent(44)
bob = make_agent(55)
print(f"alice agent_id={alice.agent_id[:8]} pub={alice.pubkey_b58[:8]}")
print(f"bob   agent_id={bob.agent_id[:8]} pub={bob.pubkey_b58[:8]}")
chk("both agents authed", alice.agent_id and bob.agent_id)

# alice looks up bob's key (raw 32 bytes)
bob_key = alice.lookup_encryption_key(bob.agent_id)
chk("alice can look up bob's encryption key", bob_key is not None and len(bob_key) == 32)

# alice sends bob an encrypted message via the client (server stores ciphertext)
secret_msg = "coordinate: execute trade A then ping me — agent Alice"
res = alice.send(to=bob.agent_id, message=secret_msg, subject="task")
print("  send result:", res)
chk("send produced a payment invoice", res.get("status") == "invoice", f"(nonce={str(res.get('payment_nonce','-'))[:8]})")

# crypto-interop proof: bob decrypts what alice encrypted to him with the real
# registered keys (alice's pub fetched from server the same way bob would).
alice_pub = bob.lookup_encryption_key(alice.agent_id)
nonce_b64, ct_b64 = crypto.encrypt(alice.x_secret, bob_key, secret_msg)
back = crypto.decrypt(bob.x_secret, alice_pub, nonce_b64, ct_b64)
chk("bob decrypts a message alice encrypted to him", back == secret_msg, f"-> {back[:30]!r}")

print("\n=== RESULT ===")
passed = sum(1 for x in ok if x)
print(f"{'ALL PASS' if all(ok) else 'FAILURES'}: {passed}/{len(ok)}")
