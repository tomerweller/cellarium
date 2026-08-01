#!/usr/bin/env bash
# Guided testnet demo: the full repo story (PLAN.md M6), narrated.
#
#   act I    two desks fund the venue (XLM cash / tUST collateral)
#   act II   a bilateral repo opens via intent -> countersign -> one proof
#   act III  the borrower repays early; interest lands to the stroop
#   act IV   a second repo is left to expire; the maturity watcher defaults it
#   act V    the oracle price crashes; the margin watcher liquidates
#
# Deploys fresh contracts + a fresh sequencer (like e2e_testnet.sh) so it
# works from a clean clone with only the toolchain installed. Everything is
# asserted — the demo fails loudly rather than narrating fiction.
set -euo pipefail
cd "$(dirname "$0")/.."

SCRATCH="${SCRATCH:-$(mktemp -d)}"
PORT=8093
URL="http://127.0.0.1:$PORT"
IDENTITY=cellarium-demo
SIM="cargo run -q -p sequencer --bin wallet-sim --"

say()  { printf '\n\033[1;33m%s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }
fail() { echo "DEMO ASSERT FAILED: $1" >&2; exit 1; }
jget() { grep -o "\"$1\":[^,}]*" | head -1 | cut -d: -f2- | tr -d '"'; }
acct() { curl -s "$URL/account/$1"; }
wait_for() { # wait_for <fn> <what>
  for i in $(seq 1 40); do "$1" && return 0; sleep 5; done
  fail "$2"
}

say "CELLARIUM - a private repo venue on Stellar, one proof per batch"
note "deploying fresh contracts to testnet (rollup + tUST + oracle)..."

stellar keys generate "$IDENTITY" --network testnet --fund 2>/dev/null || stellar keys fund "$IDENTITY" --network testnet 2>/dev/null || true
SEQ_ADDR=$(stellar keys address "$IDENTITY")
SEQ_SECRET=$(stellar keys show "$IDENTITY")
stellar contract asset deploy --asset native --source "$IDENTITY" --network testnet 2>/dev/null || true
TOKEN=$(stellar contract id asset --asset native --network testnet)
stellar contract build >/dev/null 2>&1
TUST=$(stellar contract deploy --wasm target/wasm32v1-none/release/tust.wasm \
  --source "$IDENTITY" --network testnet -- --admin "$SEQ_ADDR" 2>/dev/null)
stellar contract invoke --id "$TUST" --source "$IDENTITY" --network testnet -- \
  mint --to "$SEQ_ADDR" --amount 1000000000 >/dev/null 2>&1
ORACLE=$(stellar contract deploy --wasm target/wasm32v1-none/release/oracle.wasm \
  --source "$IDENTITY" --network testnet -- --admin "$SEQ_ADDR" 2>/dev/null)
stellar contract invoke --id "$ORACLE" --source "$IDENTITY" --network testnet -- \
  set_price --price 250000000 >/dev/null 2>&1
VK=$(xxd -p fixtures/batch_repo/vk.bin | tr -d '\n')
GENESIS=$(cargo run -q -p sequencer -- genesis-root); GENESIS=${GENESIS#0x}
ROLLUP=$(stellar contract deploy --wasm target/wasm32v1-none/release/rollup.wasm \
  --source "$IDENTITY" --network testnet -- --token_cash "$TOKEN" --token_coll "$TUST" \
  --oracle "$ORACLE" --vk "$VK" --genesis_root "$GENESIS" 2>/dev/null)
note "rollup   $ROLLUP"
note "tUST     $TUST"
note "oracle   $ORACLE  (1 tUST = 25 XLM)"

export CONTRACT_ID=$ROLLUP TOKEN_ID=$TOKEN TUST_ID=$TUST ORACLE_ID=$ORACLE \
  SEQUENCER_SECRET=$SEQ_SECRET SEQUENCER_ADDRESS=$SEQ_ADDR \
  RPC_URL=https://soroban-testnet.stellar.org \
  DB_PATH="$SCRATCH/demo.db" LISTEN_ADDR="127.0.0.1:$PORT" BATCH_MAX_WAIT_SECS=15 \
  CELLARIUM_URL="$URL" SEQ_KEY="$IDENTITY"
export NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
cargo run -q --release -p sequencer > "$SCRATCH/demo.log" 2>&1 &
SEQ_PID=$!
trap "kill $SEQ_PID 2>/dev/null || true" EXIT
for i in $(seq 1 30); do curl -sf "$URL/healthz" >/dev/null 2>&1 && break; sleep 2; done
curl -sf "$URL/healthz" >/dev/null || fail "sequencer did not become healthy"
note "sequencer up at $URL (log: $SCRATCH/demo.log)"

LENDER=$($SIM pk 101 | grep pk_x | cut -d= -f2)
BORROWER=$($SIM pk 202 | grep pk_x | cut -d= -f2)

say "ACT I - two desks fund the venue"
note "lender deposits 10 XLM cash; borrower deposits 1 XLM + 30 tUST collateral"
$SIM deposit "$LENDER" 0 100000000 >/dev/null
$SIM deposit "$BORROWER" 0 10000000 >/dev/null
$SIM deposit "$BORROWER" 1 300000000 >/dev/null
funded() {
  [ "$(acct "$LENDER" | jget cash)" = "100000000" ] &&
  [ "$(acct "$BORROWER" | jget cash)" = "10000000" ] &&
  [ "$(acct "$BORROWER" | jget coll)" = "300000000" ]
}
wait_for funded "deposits never credited"
note "credited on L2 - on L1 only the escrow totals moved"

say "ACT II - a bilateral repo opens (3 XLM vs 9 tUST, 4.30%, 2% haircut, 1h)"
note "borrower posts a half-signed intent; the venue shows it only to the lender"
INTENT=$($SIM intent 202 borrower 101 30000000 90000000 430 200 3600)
INTENT_ID=$(echo "$INTENT" | jget id)
note "lender countersigns intent #$INTENT_ID; the open rides the next proof"
$SIM accept 101 "$INTENT_ID" >/dev/null
opened() { curl -s "$URL/positions/$BORROWER" | grep -q '"cash":"30000000"'; }
wait_for opened "repo never opened"
SLOT=$(curl -s "$URL/positions/$BORROWER" | grep -o '"slot":[0-9]*' | head -1 | cut -d: -f2)
OPEN_TS=$(curl -s "$URL/positions/$BORROWER" | grep -o '"open_ts":[0-9]*' | head -1 | cut -d: -f2)
note "position live at slot $SLOT - invisible on L1, visible to both parties here:"
curl -s "$URL/positions/$BORROWER" | python3 -m json.tool | sed 's/^/      /'
ROOT_SEQ=$(curl -s "$URL/status" | jget root)
ROOT_CHAIN=0x$(stellar contract invoke --id "$ROLLUP" --source "$IDENTITY" --network testnet --send=no -- root 2>/dev/null | tr -d '"')
[ "$ROOT_SEQ" = "$ROOT_CHAIN" ] || fail "root mismatch"
note "combined state root on-chain == sequencer: $ROOT_CHAIN"

say "ACT III - the borrower repays early; interest is exact"
B_BEFORE=$(acct "$BORROWER" | jget cash)
L_BEFORE=$(acct "$LENDER" | jget cash)
$SIM close 202 "$SLOT" >/dev/null
closed() { ! curl -s "$URL/positions/$BORROWER" | grep -q "\"slot\":$SLOT"; }
wait_for closed "close never confirmed"
BN=$(curl -s "$URL/status" | jget batch_num)
CLOSE_TS=$(curl -s "$URL/da/$BN" | grep -o '"batch_ts":[0-9]*' | head -1 | cut -d: -f2)
ELAPSED=$((CLOSE_TS - OPEN_TS))
INTEREST=$(cargo run -q -p harness -- interest 30000000 430 "$ELAPSED")
[ "$(acct "$BORROWER" | jget cash)" = "$((B_BEFORE - 30000000 - INTEREST))" ] || fail "borrower repay mismatch"
[ "$(acct "$LENDER" | jget cash)" = "$((L_BEFORE + 30000000 + INTEREST))" ] || fail "lender receipt mismatch"
note "repaid 3 XLM + $INTEREST stroops interest for ${ELAPSED}s at 4.30% ACT/360"
note "the circuit enforced the exact floor division - the sequencer cannot fudge it"

say "ACT IV - a repo nobody repays (1 XLM vs 4 tUST, 45s maturity)"
L_COLL_BEFORE=$(acct "$LENDER" | jget coll)
INTENT2=$($SIM intent 202 borrower 101 10000000 40000000 500 300 45)
$SIM accept 101 "$(echo "$INTENT2" | jget id)" >/dev/null
opened2() { curl -s "$URL/positions/$BORROWER" | grep -q '"cash":"10000000"'; }
wait_for opened2 "short repo never opened"
note "tick... tick... (maturity watcher is scanning every batch tick)"
defaulted() { ! curl -s "$URL/positions/$BORROWER" | grep -q '"cash":"10000000"'; }
wait_for defaulted "expired repo never defaulted"
[ "$(acct "$LENDER" | jget coll)" = "$((L_COLL_BEFORE + 40000000))" ] || fail "default did not credit lender"
note "defaulted: lender took the 4 tUST collateral, borrower kept the 1 XLM"
note "(permissionless - no signature; valid only because batch_ts > maturity)"

say "ACT V - the collateral crashes; the margin watcher liquidates"
L_COLL_BEFORE2=$(acct "$LENDER" | jget coll)
INTENT3=$($SIM intent 202 borrower 101 20000000 9000000 300 200 3600)
$SIM accept 101 "$(echo "$INTENT3" | jget id)" >/dev/null
opened3() { curl -s "$URL/positions/$BORROWER" | grep -q '"cash":"20000000"'; }
wait_for opened3 "act V repo never opened"
note "healthy at 25 XLM/tUST (11x collateralized). Now the admin crashes the price to 2..."
stellar contract invoke --id "$ORACLE" --source "$IDENTITY" --network testnet -- \
  set_price --price 20000000 >/dev/null 2>&1
liquidated() { ! curl -s "$URL/positions/$BORROWER" | grep -q '"cash":"20000000"'; }
wait_for liquidated "under-margined repo never liquidated"
[ "$(acct "$LENDER" | jget coll)" = "$((L_COLL_BEFORE2 + 9000000))" ] || fail "liquidation did not credit lender"
note "liquidated at the oracle price the proof itself binds as a public input"

say "FIN"
note "every act settled as one UltraHonk proof on Stellar testnet"
note "L1 saw: escrow moves, state roots, commitments. Not who, how much, or at what rate."
note "sequencer still running at $URL - point the wallet at it to poke around"
note "  cd wallet && VITE_SEQUENCER_URL=$URL npm run dev"
wait $SEQ_PID
