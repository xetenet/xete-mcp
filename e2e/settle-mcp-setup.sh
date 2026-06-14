#!/usr/bin/env bash
# Settlement MCP e2e SETUP: deploy the lean settlement program (escrow-pin-rebuild, which reproduces
# the on-chain hash) to a fresh validator, fund a depositor + a beneficiary, print seeds for the
# Windows xete-mcp settlement test. Leaves validator UP. Teardown: pkill solana-test-validator.
set -uo pipefail
export PATH="$HOME/solana-release/bin:$HOME/.cargo/bin:$PATH"
source "$HOME/.cargo/env" 2>/dev/null || true
RPC="http://127.0.0.1:8899"
SO=/home/jshedrick/escrow-pin-rebuild/target/deploy/xete_escrow_pin.so
D=/tmp/xete-settle-test
mkdir -p "$D"
[ -f "$SO" ] || { echo "MISSING_SO $SO"; exit 1; }
solana-keygen new --no-bip39-passphrase --silent -o "$D/prog.json" --force
solana-keygen new --no-bip39-passphrase --silent -o "$D/depositor.json" --force
solana-keygen new --no-bip39-passphrase --silent -o "$D/beneficiary.json" --force
DEP=$(solana-keygen pubkey "$D/depositor.json"); BEN=$(solana-keygen pubkey "$D/beneficiary.json")

pkill -f solana-test-validator 2>/dev/null || true; sleep 2; rm -rf "$D/ledger"
nohup solana-test-validator --reset --quiet --ledger "$D/ledger" >/tmp/settle-validator.log 2>&1 &
for _ in $(seq 1 45); do solana -u "$RPC" cluster-version >/dev/null 2>&1 && break; sleep 1; done
solana -u "$RPC" airdrop 100 "$DEP" >/dev/null
solana -u "$RPC" airdrop 1 "$BEN" >/dev/null
solana -u "$RPC" -k "$D/depositor.json" program deploy --program-id "$D/prog.json" "$SO" 1>/dev/null
PROG=$(solana-keygen pubkey "$D/prog.json")

seed() { python3 - "$1" <<'PY'
import json, base64, sys
print(base64.b64encode(bytes(json.load(open(sys.argv[1]))[:32])).decode())
PY
}
echo "SETTLE_PROGRAM=$PROG"
echo "DEPOSITOR_SEED=$(seed "$D/depositor.json")"
echo "DEPOSITOR_PUB=$DEP"
echo "BENEFICIARY_SEED=$(seed "$D/beneficiary.json")"
echo "BENEFICIARY_PUB=$BEN"
echo "SETTLE_SETUP_OK"
