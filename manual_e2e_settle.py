"""Manual e2e for the settlement MCP tools — drives the REAL xete_settle_* tools against a local
deploy of the settlement program. Proves deposit -> claim (hidden beneficiary) and deposit -> reclaim
on-chain. Pairs with the WSL setup script.

To run (setup script is e2e/settle-mcp-setup.sh; run its copy under WSL home):
  1) (WSL)     bash ~/settle-mcp-setup.sh          # deploys settlement, funds wallets, prints values
  2) (Windows) export SETTLE_PROGRAM=... DEPOSITOR_SEED=... BENEFICIARY_SEED=... BENEFICIARY_PUB=...
               ./.venv/Scripts/python.exe manual_e2e_settle.py
"""
import os, base64, json, tempfile, sys
from pathlib import Path

os.environ["XETE_SETTLEMENT_PROGRAM"] = os.environ["SETTLE_PROGRAM"]
os.environ["XETE_RPC_URL"] = "http://127.0.0.1:8899"
os.environ["XETE_PERMIT_URL"] = "http://127.0.0.1:8787"  # unused here (recipient passed as a raw pubkey)


def identity_file(seed_b64: str, name: str) -> str:
    p = os.path.join(tempfile.gettempdir(), f"settle_{name}.json")
    json.dump({"ed_seed": seed_b64, "x_secret": base64.b64encode(os.urandom(32)).decode(),
               "agent_id": name}, open(p, "w"))
    return p

dep_id = identity_file(os.environ["DEPOSITOR_SEED"], "depositor")
ben_id = identity_file(os.environ["BENEFICIARY_SEED"], "beneficiary")
ben_pub = os.environ["BENEFICIARY_PUB"]

os.environ["XETE_IDENTITY"] = dep_id
sys.path.insert(0, "src")
import xete_mcp.server as s

def as_identity(path):  # the tools read the module global IDENTITY_PATH at call time
    s.IDENTITY_PATH = Path(path)

print("=== CLAIM PATH ===")
as_identity(dep_id)
created = json.loads(s.xete_settle_create(ben_pub, 0.05, notify=False))
print("CREATE:", json.dumps(created, indent=2))
eid = created["ticket"]["escrow_id"]; salt = created["ticket"]["salt"]
print("STATUS(open):", s.xete_settle_status(eid))
as_identity(ben_id)
print("CLAIM:", s.xete_settle_claim(eid, salt))
print("STATUS(after claim):", s.xete_settle_status(eid))

print("\n=== RECLAIM PATH ===")
as_identity(dep_id)
created2 = json.loads(s.xete_settle_create(ben_pub, 0.03, notify=False))
eid2 = created2["ticket"]["escrow_id"]
print("CREATE2 escrow:", eid2)
print("STATUS(open):", s.xete_settle_status(eid2))
print("RECLAIM:", s.xete_settle_reclaim(eid2))
print("STATUS(after reclaim):", s.xete_settle_status(eid2))
