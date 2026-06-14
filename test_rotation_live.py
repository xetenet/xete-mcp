"""Live integration test of relay key ROTATION + unified-key interop.

Runs against a locally-booted relay (xete-local-dev) with a throwaway DB. Proves:
  - first /keys/register stores the key
  - re-register with a DIFFERENT key ROTATES it (was 409 KEY_EXISTS before the fix)
  - re-register with the SAME key is idempotent (rotated:false), no row churn
  - exactly ONE active key remains after rotations
  - a second agent looks up the published key and gets the DERIVED key bytes
    (the end-to-end interop that was broken: HE<->xete-mcp now agree)

Run: XETE_SERVER_URL=http://127.0.0.1:8099 .venv/Scripts/python test_rotation_live.py
"""
import os
import sys

from xete_mcp.client import XeteClient, Identity

SERVER = os.environ.get("XETE_SERVER_URL", "http://127.0.0.1:8099")

results = []
def chk(name, cond, detail=""):
    results.append(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' — ' + detail) if detail else ''}")

def reg(client, key_hex):
    r = client._req("POST", "/keys/register", json={"x25519_public_key": key_hex})
    return r.status_code, (r.json() if r.headers.get("content-type","").startswith("application/json") else {})

def get_key(client, agent_id):
    r = client.session.get(f"{SERVER}/keys/{agent_id}", timeout=15)
    return (r.json().get("x25519_public_key") if r.status_code == 200 else None)

def active_count(client):
    r = client._req("GET", "/agent/keys/list")
    return len(r.json()) if r.status_code == 200 else -1

print(f"=== relay key rotation (live, {SERVER}) ===")

# Two agents with DERIVED messaging keys (fresh wallets for this test).
alice = XeteClient(base_url=SERVER, identity=Identity(ed_seed=bytes([171] * 32)))
bob = XeteClient(base_url=SERVER, identity=Identity(ed_seed=bytes([172] * 32)))
alice.login(force=True)
bob.login(force=True)
chk("both agents authed", bool(alice.identity.agent_id and bob.identity.agent_id))

alice_derived = alice.identity.x_public.hex()
other_key = bob.identity.x_public.hex()  # a valid-but-different 64-hex x25519 key

# 1. First register -> stored, rotated:false (no prior key).
code, body = reg(alice, alice_derived)
chk("first register accepted (200)", code == 200, f"code={code} {body}")
chk("first register: rotated=false", body.get("rotated") is False, str(body))
chk("GET returns the registered key", get_key(alice, alice.identity.agent_id) == alice_derived)
chk("exactly 1 active key", active_count(alice) == 1)

# 2. Re-register a DIFFERENT key -> ROTATES (the old behavior returned 409).
code, body = reg(alice, other_key)
chk("rotate to new key accepted (200, not 409)", code == 200, f"code={code} {body}")
chk("rotate: rotated=true", body.get("rotated") is True, str(body))
chk("GET now returns the NEW key", get_key(alice, alice.identity.agent_id) == other_key)
chk("still exactly 1 active key after rotation", active_count(alice) == 1)

# 3. Re-register the SAME key -> idempotent, rotated:false, no churn.
code, body = reg(alice, other_key)
chk("idempotent re-register (200)", code == 200, f"code={code} {body}")
chk("idempotent: rotated=false", body.get("rotated") is False, str(body))
chk("still 1 active key after idempotent re-register", active_count(alice) == 1)

# 4. Rotate back to the derived key (what HE would also publish for this wallet).
code, body = reg(alice, alice_derived)
chk("rotate back to derived key", code == 200 and body.get("rotated") is True, str(body))
chk("GET returns derived key again", get_key(alice, alice.identity.agent_id) == alice_derived)

# 5. INTEROP: bob registers, alice looks bob up and gets bob's DERIVED key bytes.
reg(bob, bob.identity.x_public.hex())
looked_up = alice.lookup_encryption_key(bob.identity.agent_id)
chk("cross-agent lookup returns bob's DERIVED key", looked_up == bob.identity.x_public,
    f"{looked_up.hex()[:16]}… vs {bob.identity.x_public.hex()[:16]}…")

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
