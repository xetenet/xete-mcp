"""Manual e2e for the alias MCP tools — drives the REAL xete_alias_* tools against a local
validator + permit server. Proves the claim solders round-trip (parse permit-cosigned tx ->
partial_sign -> submit -> confirm on-chain), which the Rust e2e doesn't cover.

Pairs with the permit repo's setup script. To run:
  1) (WSL)     bash xete-permit-server/e2e/mcp-claim-setup.sh   # boots validator+agent+permit, prints TEST_*
  2) (Windows) export TEST_ED_SEED_B64=<value printed by step 1>
               ./.venv/Scripts/python.exe manual_e2e_claim.py
Expect CLAIM -> status:"claimed", settled:"confirmed", owner == the funded wallet. Reaches the WSL
permit (:8787) + validator RPC (:8899) over localhost forwarding. Not a pytest (needs live infra)."""
import os, base64, json, tempfile, sys
from pathlib import Path

os.environ["XETE_PERMIT_URL"] = "http://127.0.0.1:8787"
os.environ["XETE_RPC_URL"] = "http://127.0.0.1:8899"
os.environ["XETE_SERVER_URL"] = "http://127.0.0.1:8787"  # claim no longer uses this, but keep it off live
idf = os.path.join(tempfile.gettempdir(), "mcp_claim_identity.json")
json.dump({
    "ed_seed": os.environ["TEST_ED_SEED_B64"],
    "x_secret": base64.b64encode(os.urandom(32)).decode(),
    "agent_id": "mcp-test-agent",
}, open(idf, "w"))
os.environ["XETE_IDENTITY"] = idf

sys.path.insert(0, "src")
import xete_mcp.server as s
from xete_mcp.client import load_or_create_identity

ident = load_or_create_identity(Path(idf))
print("IDENT_PUB", ident.pubkey_b58)
print("RESOLVE_BEFORE", s.xete_alias_resolve("mcptestname"))
print("QUOTE", s.xete_alias_quote("mcptestname"))
print("CLAIM", s.xete_alias_claim("mcptestname"))
print("RESOLVE_AFTER", s.xete_alias_resolve("mcptestname"))
