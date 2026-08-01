#!/usr/bin/env bash
# Cellarium end-to-end acceptance test against public testnet, driving the
# NATIVE sequencer (the proving path bb needs is native arm64/amd64 here).
# Deploys fresh contracts (rollup + tUST + oracle), boots the sequencer, then:
#   M1: deposits XLM and tUST to two users, L2-transfers each asset,
#       withdraws each asset (wrong-asset negative included);
#   M2: repo open via the bilateral intent flow (post -> countersign ->
#       batch -> on-chain state-root advance; positions visible both sides);
#   M3: close before maturity with interest asserted to the stroop against
#       the harness computation; a short-maturity repo expires and the
#       maturity watcher auto-defaults it, crediting the lender's collateral;
#   M4: the margin watcher liquidates an under-margined repo after an admin
#       price crash; an under-collateralized open is evicted, never applied.
#
# The docker-compose path (`just bootstrap && just up`) exercises the same
# sequencer binary; this script uses the native process so it runs anywhere
# bb is installed, including CI on amd64.
set -euo pipefail
cd "$(dirname "$0")/.."

SCRATCH="${SCRATCH:-$(mktemp -d)}"
PORT=8091
URL="http://127.0.0.1:$PORT"
IDENTITY=cellarium-e2e
SIM="cargo run -q -p sequencer --bin wallet-sim --"

fail() { echo "ASSERT FAILED: $1" >&2; exit 1; }
jget() { grep -o "\"$1\":[^,}]*" | head -1 | cut -d: -f2- | tr -d '"'; }

echo "==> identity + tokens"
stellar keys generate "$IDENTITY" --network testnet --fund 2>/dev/null || stellar keys fund "$IDENTITY" --network testnet 2>/dev/null || true
SEQ_ADDR=$(stellar keys address "$IDENTITY")
SEQ_SECRET=$(stellar keys show "$IDENTITY")
stellar contract asset deploy --asset native --source "$IDENTITY" --network testnet 2>/dev/null || true
TOKEN=$(stellar contract id asset --asset native --network testnet)

echo "==> build wasm + deploy fresh tUST + rollup"
stellar contract build >/dev/null
TUST=$(stellar contract deploy --wasm target/wasm32v1-none/release/tust.wasm \
  --source "$IDENTITY" --network testnet -- --admin "$SEQ_ADDR")
echo "    tust=$TUST"
# The sequencer account doubles as tUST admin + depositor here: mint it a
# working balance for the collateral-leg deposits.
stellar contract invoke --id "$TUST" --source "$IDENTITY" --network testnet -- \
  mint --to "$SEQ_ADDR" --amount 1000000000 >/dev/null

ORACLE=$(stellar contract deploy --wasm target/wasm32v1-none/release/oracle.wasm \
  --source "$IDENTITY" --network testnet -- --admin "$SEQ_ADDR")
echo "    oracle=$ORACLE"
stellar contract invoke --id "$ORACLE" --source "$IDENTITY" --network testnet -- \
  set_price --price 250000000 >/dev/null

VK=$(xxd -p fixtures/batch_repo/vk.bin | tr -d '\n')
GENESIS=$(cargo run -q -p sequencer -- genesis-root); GENESIS=${GENESIS#0x}
ROLLUP=$(stellar contract deploy --wasm target/wasm32v1-none/release/rollup.wasm \
  --source "$IDENTITY" --network testnet -- --token_cash "$TOKEN" --token_coll "$TUST" \
  --oracle "$ORACLE" --operator "$SEQ_ADDR" --vk "$VK" --genesis_root "$GENESIS")
echo "    rollup=$ROLLUP"

echo "==> boot sequencer"
export CONTRACT_ID=$ROLLUP TOKEN_ID=$TOKEN TUST_ID=$TUST ORACLE_ID=$ORACLE SEQUENCER_SECRET=$SEQ_SECRET SEQUENCER_ADDRESS=$SEQ_ADDR
export ORACLE_ADMIN_SECRET=$SEQ_SECRET  # heartbeat: keep the mock price fresh
export RPC_URL=https://soroban-testnet.stellar.org
export NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
export DB_PATH="$SCRATCH/e2e.db" LISTEN_ADDR="127.0.0.1:$PORT" BATCH_MAX_WAIT_SECS=15
export CELLARIUM_URL="$URL" SEQ_KEY="$IDENTITY"
rm -f "$DB_PATH"
cargo run -q --release -p sequencer > "$SCRATCH/e2e.log" 2>&1 &
SEQ_PID=$!
trap "kill $SEQ_PID 2>/dev/null || true" EXIT
for i in $(seq 1 30); do curl -sf "$URL/healthz" >/dev/null 2>&1 && break; sleep 2; done
curl -sf "$URL/healthz" >/dev/null || fail "sequencer did not become healthy"

ALICE=$($SIM pk 101 | grep pk_x | cut -d= -f2)
BOB=$($SIM pk 202 | grep pk_x | cut -d= -f2)
# Withdrawal destination: a fixed contract-type address that starts with a
# zero balance in both tokens (C-addresses need no trustline), so L1 payout
# amounts can be asserted exactly.
WD_DEST=CADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQP5KR

echo "==> deposits (alice: XLM + tUST; bob: XLM + tUST)"
$SIM deposit "$ALICE" 0 100000000 >/dev/null
$SIM deposit "$ALICE" 1 300000000 >/dev/null
$SIM deposit "$BOB" 0 50000000 >/dev/null
$SIM deposit "$BOB" 1 200000000 >/dev/null

# The sequencer batches eagerly, so pending_deposits is transient — poll the
# CREDITED balances instead (deposits may settle across 1-2 batches).
echo "==> deposit credit (1-2 batches)"
deposits_landed() {
  [ "$(curl -s "$URL/account/$ALICE" | jget cash)" = "100000000" ] &&
  [ "$(curl -s "$URL/account/$ALICE" | jget coll)" = "300000000" ] &&
  [ "$(curl -s "$URL/account/$BOB" | jget cash)" = "50000000" ] &&
  [ "$(curl -s "$URL/account/$BOB" | jget coll)" = "200000000" ]
}
for i in $(seq 1 36); do deposits_landed && break; sleep 5; done
deposits_landed || fail "deposits never credited on L2"

echo "==> L2 transfers (one per asset) + withdrawals (one per asset)"
$SIM send 101 "$BOB" 0 20000000 0
$SIM send 202 "$ALICE" 1 40000000 0
$SIM withdraw 101 "$WD_DEST" 1 15000000 1
$SIM withdraw 202 "$WD_DEST" 0 10000000 1
# alice: cash 1000000-200000=800000, coll 3000000+400000-150000=3250000
# bob:   cash 500000+200000-100000=600000, coll 2000000-400000=1600000
txs_landed() {
  [ "$(curl -s "$URL/account/$ALICE" | jget cash)" = "80000000" ] &&
  [ "$(curl -s "$URL/account/$ALICE" | jget coll)" = "325000000" ] &&
  [ "$(curl -s "$URL/account/$BOB" | jget cash)" = "60000000" ] &&
  [ "$(curl -s "$URL/account/$BOB" | jget coll)" = "160000000" ]
}
for i in $(seq 1 36); do txs_landed && break; sleep 5; done
txs_landed || fail "tx batch never confirmed"

echo "==> assertions"
ALICE_CASH=$(curl -s "$URL/account/$ALICE" | jget cash)
ALICE_COLL=$(curl -s "$URL/account/$ALICE" | jget coll)
BOB_CASH=$(curl -s "$URL/account/$BOB" | jget cash)
BOB_COLL=$(curl -s "$URL/account/$BOB" | jget coll)
[ "$ALICE_CASH" = "80000000" ] || fail "alice cash $ALICE_CASH != 80000000"
[ "$ALICE_COLL" = "325000000" ] || fail "alice coll $ALICE_COLL != 325000000"
[ "$BOB_CASH" = "60000000" ] || fail "bob cash $BOB_CASH != 60000000"
[ "$BOB_COLL" = "160000000" ] || fail "bob coll $BOB_COLL != 160000000"
echo "    L2 balances correct across both assets"

# L1 payout: the tUST withdrawal must have paid 150000 tUST base units to
# WD_DEST from the coll custody pool (the sequencer's own account here).
TUST_OUT=$(stellar contract invoke --id "$TUST" --source "$IDENTITY" --network testnet --send=no -- \
  balance --id "$WD_DEST" 2>/dev/null | tr -d '"')
[ "$TUST_OUT" = "15000000" ] || fail "tUST withdrawal payout $TUST_OUT != 15000000"
echo "    tUST withdrawal paid out on L1 (15000000 base units)"

# Per-asset isolation: alice (nonce 2) signs a 1,000,000 CASH spend — more
# than her 800,000 cash but far less than her 3,250,000 coll. If balances
# were pooled or confused across assets this would be admitted.
OVER=$($SIM send 101 "$BOB" 0 100000000 2 2>&1 || true)
echo "$OVER" | grep -q "INSUFFICIENT_BALANCE" || fail "cross-asset overdraft admitted: $OVER"
echo "    per-asset balance isolation enforced"

SEQ_ROOT=$(curl -s "$URL/status" | jget root)
CHAIN_ROOT=0x$(stellar contract invoke --id "$ROLLUP" --source "$IDENTITY" --network testnet --send=no -- root 2>/dev/null | tr -d '"')
[ "$SEQ_ROOT" = "$CHAIN_ROOT" ] || fail "root mismatch: seq $SEQ_ROOT vs chain $CHAIN_ROOT"
echo "    sequencer root == on-chain root ($SEQ_ROOT)"

# DA blob availability: the latest confirmed batch must serve a proof.
BN=$(curl -s "$URL/status" | jget batch_num)
PROOF_LEN=$(curl -s "$URL/da/$BN" | grep -o '"proof":"[0-9a-f]*"' | head -1 | tr -d '"' | sed 's/proof://' | wc -c | tr -d ' ')
[ "$PROOF_LEN" -gt 20000 ] || fail "DA blob proof missing (len=$PROOF_LEN)"
echo "    DA blob for batch $BN served (proof present)"

echo "==> repo open: intent -> countersign -> batch"
# bob (borrower, sk=202) initiates against alice (lender, sk=101):
# 30000000 stroops cash vs 90000000 tUST coll, 4.30%, 2% haircut, 1h term.
# Nonces are fetched live by the sim (alice: 2 after send+withdraw; bob: 2).
INTENT=$($SIM intent 202 borrower 101 30000000 90000000 430 200 3600)
INTENT_ID=$(echo "$INTENT" | jget id)
[ -n "$INTENT_ID" ] || fail "intent not accepted: $INTENT"

# The intent must be visible to the counterparty (and carry the terms).
curl -s "$URL/intents/$ALICE" | grep -q '"cash":"30000000"' || fail "intent not listed for lender"

# Countersigning with the WRONG key must be rejected (single-signature guard).
BADSIG=$($SIM accept 303 "$INTENT_ID" 2>&1 || true)
echo "$BADSIG" | grep -qE "BAD_SIGNATURE|not found in incoming" || fail "wrong-key countersign accepted: $BADSIG"

$SIM accept 101 "$INTENT_ID" >/dev/null
repo_landed() {
  curl -s "$URL/positions/$BOB" | grep -q '"cash":"30000000"'
}
for i in $(seq 1 36); do repo_landed && break; sleep 5; done
repo_landed || fail "repo open never confirmed"

# Position visible from both sides with the agreed terms.
curl -s "$URL/positions/$ALICE" | grep -q '"rate_bps":430' || fail "lender position missing terms"
curl -s "$URL/positions/$BOB" | grep -q '"haircut_bps":200' || fail "borrower position missing terms"

# Balance effects: borrower cash += 30000000 (bob 60000000 -> 90000000), borrower
# coll -= 90000000 (160000000 -> 70000000), lender cash -= 30000000 (80000000 -> 50000000).
[ "$(curl -s "$URL/account/$BOB" | jget cash)" = "90000000" ] || fail "borrower cash after open"
[ "$(curl -s "$URL/account/$BOB" | jget coll)" = "70000000" ] || fail "borrower coll after open"
[ "$(curl -s "$URL/account/$ALICE" | jget cash)" = "50000000" ] || fail "lender cash after open"

# Sequencer state root (accounts+positions) == on-chain root after the open.
SEQ_ROOT2=$(curl -s "$URL/status" | jget root)
CHAIN_ROOT2=0x$(stellar contract invoke --id "$ROLLUP" --source "$IDENTITY" --network testnet --send=no -- root 2>/dev/null | tr -d '"')
[ "$SEQ_ROOT2" = "$CHAIN_ROOT2" ] || fail "post-open root mismatch: seq $SEQ_ROOT2 vs chain $CHAIN_ROOT2"
echo "    repo open confirmed; positions visible both sides; roots match"

echo "==> repo close: repay with interest before maturity"
# The M2 position sits at some slot with cash=30000000 @430bps. bob closes it.
SLOT=$(curl -s "$URL/positions/$BOB" | grep -o '"slot":[0-9]*' | head -1 | cut -d: -f2)
OPEN_TS=$(curl -s "$URL/positions/$BOB" | grep -o '"open_ts":[0-9]*' | head -1 | cut -d: -f2)
BOB_CASH_BEFORE=$(curl -s "$URL/account/$BOB" | jget cash)
ALICE_CASH_BEFORE=$(curl -s "$URL/account/$ALICE" | jget cash)
$SIM close 202 "$SLOT" >/dev/null
close_landed() { ! curl -s "$URL/positions/$BOB" | grep -q "\"slot\":$SLOT"; }
for i in $(seq 1 36); do close_landed && break; sleep 5; done
close_landed || fail "close never confirmed"

# Interest asserted to the stroop: elapsed = close batch_ts - open_ts, both
# from the sequencer's own records (DA blob binds batch_ts).
BN=$(curl -s "$URL/status" | jget batch_num)
CLOSE_TS=$(curl -s "$URL/da/$BN" | grep -o '"batch_ts":[0-9]*' | head -1 | cut -d: -f2)
ELAPSED=$((CLOSE_TS - OPEN_TS))
INTEREST=$(cargo run -q -p harness -- interest 30000000 430 "$ELAPSED")
EXPECT_BOB=$((BOB_CASH_BEFORE - 30000000 - INTEREST))
EXPECT_ALICE=$((ALICE_CASH_BEFORE + 30000000 + INTEREST))
BOB_CASH_AFTER=$(curl -s "$URL/account/$BOB" | jget cash)
ALICE_CASH_AFTER=$(curl -s "$URL/account/$ALICE" | jget cash)
[ "$BOB_CASH_AFTER" = "$EXPECT_BOB" ] || fail "borrower repay wrong: $BOB_CASH_AFTER != $EXPECT_BOB (interest $INTEREST over ${ELAPSED}s)"
[ "$ALICE_CASH_AFTER" = "$EXPECT_ALICE" ] || fail "lender receipt wrong: $ALICE_CASH_AFTER != $EXPECT_ALICE"
# Collateral returned to the borrower: 700000 + 900000 = 1600000.
[ "$INTEREST" -gt 0 ] || fail "interest unexpectedly zero (elapsed ${ELAPSED}s)"
[ "$(curl -s "$URL/account/$BOB" | jget coll)" = "160000000" ] || fail "borrower coll not returned"
echo "    close repaid 30000000 + $INTEREST interest (${ELAPSED}s elapsed), coll returned"

echo "==> repo default: maturity watcher"
# A 45s-maturity repo that nobody closes: the watcher must auto-default it
# and credit the LENDER's collateral account.
ALICE_COLL_BEFORE=$(curl -s "$URL/account/$ALICE" | jget coll)
INTENT2=$($SIM intent 202 borrower 101 10000000 40000000 500 300 45)
INTENT2_ID=$(echo "$INTENT2" | jget id)
$SIM accept 101 "$INTENT2_ID" >/dev/null
open2_landed() { curl -s "$URL/positions/$BOB" | grep -q '"cash":"10000000"'; }
for i in $(seq 1 36); do open2_landed && break; sleep 5; done
open2_landed || fail "short repo never opened"

default_landed() { ! curl -s "$URL/positions/$BOB" | grep -q '"cash":"10000000"'; }
for i in $(seq 1 36); do default_landed && break; sleep 5; done
default_landed || fail "expired repo never auto-defaulted"
ALICE_COLL_AFTER=$(curl -s "$URL/account/$ALICE" | jget coll)
[ "$ALICE_COLL_AFTER" = "$((ALICE_COLL_BEFORE + 40000000))" ] || fail "lender collateral not credited on default: $ALICE_COLL_AFTER"
# Borrower keeps the borrowed cash (no clawback).
echo "    auto-default credited lender 40000000 coll; borrower kept the cash"

echo "==> repo liquidation: margin watcher (M4)"
# Open a healthy repo at 25 XLM/tUST: 20000000 stroops cash vs 9000000 tUST
# (11x overcollateralized), then crash the oracle price to 2 XLM/tUST —
# breach: 9000000*price*2e4 < 20000000*(2e4+200)*1e7 for price < 22444444.
ALICE_COLL_BEFORE_LIQ=$(curl -s "$URL/account/$ALICE" | jget coll)
INTENT3=$($SIM intent 202 borrower 101 20000000 9000000 300 200 3600)
INTENT3_ID=$(echo "$INTENT3" | jget id)
$SIM accept 101 "$INTENT3_ID" >/dev/null
open3_landed() { curl -s "$URL/positions/$BOB" | grep -q '"cash":"20000000"'; }
for i in $(seq 1 36); do open3_landed && break; sleep 5; done
open3_landed || fail "M4 repo never opened"

stellar contract invoke --id "$ORACLE" --source "$IDENTITY" --network testnet -- \
  set_price --price 20000000 >/dev/null
echo "    oracle price dropped 25 -> 2 XLM/tUST"

liq_landed() { ! curl -s "$URL/positions/$BOB" | grep -q '"cash":"20000000"'; }
for i in $(seq 1 36); do liq_landed && break; sleep 5; done
liq_landed || fail "under-margined repo never liquidated"
ALICE_COLL_AFTER_LIQ=$(curl -s "$URL/account/$ALICE" | jget coll)
[ "$ALICE_COLL_AFTER_LIQ" = "$((ALICE_COLL_BEFORE_LIQ + 9000000))" ] || fail "lender collateral not credited on liquidation: $ALICE_COLL_AFTER_LIQ"
echo "    margin watcher liquidated the position; lender credited 9000000 coll"

echo "==> under-collateralized open rejected (M4)"
# At 2 XLM/tUST, 20000000 cash needs >= 10200000 tUST; offer only 3000000.
INTENT4=$($SIM intent 202 borrower 101 20000000 3000000 300 200 3600)
INTENT4_ID=$(echo "$INTENT4" | jget id)
$SIM accept 101 "$INTENT4_ID" >/dev/null
sleep 25
curl -s "$URL/positions/$BOB" | grep -q '"cash":"20000000"' && fail "under-collateralized open was applied"
echo "    under-collateralized open evicted (never becomes a position)"

# Anti-replay: resubmitting alice's consumed nonce 0 must NOT re-execute —
# the (sender,nonce) idempotency short-circuit returns the original included
# receipt.
REPLAY=$($SIM send 101 "$BOB" 0 20000000 0 2>&1 || true)
echo "$REPLAY" | grep -q '"status":"included"' || fail "replay of nonce 0 was re-executed: $REPLAY"
# A future/gap nonce must be rejected outright.
GAP=$($SIM send 101 "$BOB" 0 1 7 2>&1 || true)
echo "$GAP" | grep -q "NONCE_MISMATCH" || fail "gap nonce 7 was not rejected: $GAP"
echo "    replay idempotent + gap-nonce rejected"

echo "==> E2E PASSED"
