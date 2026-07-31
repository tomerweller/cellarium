#!/usr/bin/env bash
# Soribium end-to-end acceptance test against public testnet, driving the
# NATIVE sequencer (the proving path bb needs is native arm64/amd64 here).
# Deploys fresh contracts (rollup + tUST token), boots the sequencer, then
# (M1 acceptance, PLAN.md): deposits XLM and tUST to two users, L2-transfers
# each asset, withdraws each asset, asserting every invariant including the
# wrong-asset negative (exit 1 on any mismatch).
#
# The docker-compose path (`just bootstrap && just up`) exercises the same
# sequencer binary; this script uses the native process so it runs anywhere
# bb is installed, including CI on amd64.
set -euo pipefail
cd "$(dirname "$0")/.."

SCRATCH="${SCRATCH:-$(mktemp -d)}"
PORT=8091
URL="http://127.0.0.1:$PORT"
IDENTITY=soribium-e2e
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
  mint --to "$SEQ_ADDR" --amount 10000000 >/dev/null

VK=$(xxd -p fixtures/batch_n16/vk.bin | tr -d '\n')
GENESIS=$(cargo run -q -p sequencer -- genesis-root); GENESIS=${GENESIS#0x}
ROLLUP=$(stellar contract deploy --wasm target/wasm32v1-none/release/rollup.wasm \
  --source "$IDENTITY" --network testnet -- --token_cash "$TOKEN" --token_coll "$TUST" \
  --vk "$VK" --genesis_root "$GENESIS")
echo "    rollup=$ROLLUP"

echo "==> boot sequencer"
export CONTRACT_ID=$ROLLUP TOKEN_ID=$TOKEN TUST_ID=$TUST SEQUENCER_SECRET=$SEQ_SECRET SEQUENCER_ADDRESS=$SEQ_ADDR
export RPC_URL=https://soroban-testnet.stellar.org
export NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
export DB_PATH="$SCRATCH/e2e.db" LISTEN_ADDR="127.0.0.1:$PORT" BATCH_MAX_WAIT_SECS=15
export SORIBIUM_URL="$URL" SEQ_KEY="$IDENTITY"
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
$SIM deposit "$ALICE" 0 1000000 >/dev/null
$SIM deposit "$ALICE" 1 3000000 >/dev/null
$SIM deposit "$BOB" 0 500000 >/dev/null
$SIM deposit "$BOB" 1 2000000 >/dev/null

# The sequencer batches eagerly, so pending_deposits is transient — poll the
# CREDITED balances instead (deposits may settle across 1-2 batches).
echo "==> deposit credit (1-2 batches)"
deposits_landed() {
  [ "$(curl -s "$URL/account/$ALICE" | jget cash)" = "1000000" ] &&
  [ "$(curl -s "$URL/account/$ALICE" | jget coll)" = "3000000" ] &&
  [ "$(curl -s "$URL/account/$BOB" | jget cash)" = "500000" ] &&
  [ "$(curl -s "$URL/account/$BOB" | jget coll)" = "2000000" ]
}
for i in $(seq 1 36); do deposits_landed && break; sleep 5; done
deposits_landed || fail "deposits never credited on L2"

echo "==> L2 transfers (one per asset) + withdrawals (one per asset)"
$SIM send 101 "$BOB" 0 200000 0
$SIM send 202 "$ALICE" 1 400000 0
$SIM withdraw 101 "$WD_DEST" 1 150000 1
$SIM withdraw 202 "$WD_DEST" 0 100000 1
# alice: cash 1000000-200000=800000, coll 3000000+400000-150000=3250000
# bob:   cash 500000+200000-100000=600000, coll 2000000-400000=1600000
txs_landed() {
  [ "$(curl -s "$URL/account/$ALICE" | jget cash)" = "800000" ] &&
  [ "$(curl -s "$URL/account/$BOB" | jget coll)" = "1600000" ]
}
for i in $(seq 1 36); do txs_landed && break; sleep 5; done
txs_landed || fail "tx batch never confirmed"

echo "==> assertions"
ALICE_CASH=$(curl -s "$URL/account/$ALICE" | jget cash)
ALICE_COLL=$(curl -s "$URL/account/$ALICE" | jget coll)
BOB_CASH=$(curl -s "$URL/account/$BOB" | jget cash)
BOB_COLL=$(curl -s "$URL/account/$BOB" | jget coll)
[ "$ALICE_CASH" = "800000" ] || fail "alice cash $ALICE_CASH != 800000"
[ "$ALICE_COLL" = "3250000" ] || fail "alice coll $ALICE_COLL != 3250000"
[ "$BOB_CASH" = "600000" ] || fail "bob cash $BOB_CASH != 600000"
[ "$BOB_COLL" = "1600000" ] || fail "bob coll $BOB_COLL != 1600000"
echo "    L2 balances correct across both assets"

# L1 payout: the tUST withdrawal must have paid 150000 tUST base units to
# WD_DEST from the coll custody pool (the sequencer's own account here).
TUST_OUT=$(stellar contract invoke --id "$TUST" --source "$IDENTITY" --network testnet --send=no -- \
  balance --id "$WD_DEST" 2>/dev/null | tr -d '"')
[ "$TUST_OUT" = "150000" ] || fail "tUST withdrawal payout $TUST_OUT != 150000"
echo "    tUST withdrawal paid out on L1 (150000 base units)"

# Per-asset isolation: alice (nonce 2) signs a 1,000,000 CASH spend — more
# than her 800,000 cash but far less than her 3,250,000 coll. If balances
# were pooled or confused across assets this would be admitted.
OVER=$($SIM send 101 "$BOB" 0 1000000 2 2>&1 || true)
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

# Anti-replay: resubmitting alice's consumed nonce 0 must NOT re-execute —
# the (sender,nonce) idempotency short-circuit returns the original included
# receipt.
REPLAY=$($SIM send 101 "$BOB" 0 200000 0 2>&1 || true)
echo "$REPLAY" | grep -q '"status":"included"' || fail "replay of nonce 0 was re-executed: $REPLAY"
# A future/gap nonce must be rejected outright.
GAP=$($SIM send 101 "$BOB" 0 1 7 2>&1 || true)
echo "$GAP" | grep -q "NONCE_MISMATCH" || fail "gap nonce 7 was not rejected: $GAP"
echo "    replay idempotent + gap-nonce rejected"

echo "==> E2E PASSED"
