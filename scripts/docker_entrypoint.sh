#!/usr/bin/env bash
# Container entrypoint with opt-in self-bootstrap (AUTO_BOOTSTRAP=1).
#
# Problem this solves: the rollup contract's VK is immutable, so any circuit
# change makes the deployed instance permanently unusable by a newer
# sequencer (and a DB schema bump makes the on-volume SQLite unopenable by
# design). Before this entrypoint, every such commit required a manual
# re-bootstrap + config patch; a deploy without one left the machine
# crash-looping.
#
# Mechanism: the persistent volume carries `instance.env` — the deployed
# contract ids plus the compatibility FINGERPRINT they were bootstrapped
# under:
#
#   fingerprint = sha256(VK derived from the baked circuit) + "-v" + DB schema
#
# On boot:
#   - fingerprint matches  -> reuse the recorded instance, start normally.
#   - mismatch or missing  -> deploy a fresh tUST + oracle + rollup with the
#     current VK (operator = the sequencer account), archive the old DB, and
#     record the new instance. The wallet needs no redeploy: it reads
#     contract ids live from the sequencer's /params.
#
# The abandoned old instance keeps its escrow; depositors can reclaim queued
# entries via its permissionless refund_deposit after the 24h timeout
# (issue #1 M5). Testnet-prototype semantics — a production rollup would
# migrate state, not abandon it.
#
# Without AUTO_BOOTSTRAP=1 this execs the sequencer directly, leaving the
# docker-compose / host-bootstrap flow exactly as before.
set -euo pipefail

if [ "${AUTO_BOOTSTRAP:-0}" != "1" ]; then
  exec sequencer "$@"
fi

: "${SEQUENCER_SECRET:?AUTO_BOOTSTRAP=1 requires SEQUENCER_SECRET}"
RPC_URL="${RPC_URL:-https://soroban-testnet.stellar.org}"
NETWORK_PASSPHRASE="${NETWORK_PASSPHRASE:-Test SDF Network ; September 2015}"
FRIENDBOT_URL="${FRIENDBOT_URL:-https://friendbot.stellar.org}"
CIRCUIT_PKG="${CIRCUIT_PKG:-batch_repo}"
CIRCUITS_DIR="${CIRCUITS_DIR:-/app/circuits}"
WASM_DIR="${WASM_DIR:-/app/wasm}"
DATA_DIR="$(dirname "${DB_PATH:-/data/sequencer.db}")"
INSTANCE_FILE="${INSTANCE_FILE:-$DATA_DIR/instance.env}"
INITIAL_PRICE="${INITIAL_PRICE:-250000000}" # 25 XLM per tUST x 1e7

log() { echo "entrypoint: $*" >&2; }

# --- compatibility fingerprint: VK of the baked circuit + DB schema ---
VK_OUT=$(mktemp -d)
bb write_vk --scheme ultra_honk --oracle_hash keccak \
  --bytecode_path "$CIRCUITS_DIR/target/${CIRCUIT_PKG}.json" \
  --output_path "$VK_OUT" >&2
VK_BIN="$VK_OUT/vk"
[ "$(wc -c < "$VK_BIN" | tr -d ' ')" = "1760" ] || { log "unexpected VK length"; exit 1; }
SCHEMA=$(sequencer schema-version)
FINGERPRINT="$(sha256sum "$VK_BIN" | cut -d' ' -f1)-v${SCHEMA}"
log "compatibility fingerprint: $FINGERPRINT"

use_instance() {
  # shellcheck disable=SC1090
  set -a; . "$INSTANCE_FILE"; set +a
  # Oracle admin == operator under auto-bootstrap; keep the secret out of
  # the on-volume file and inject it here instead.
  export ORACLE_ADMIN_SECRET="$SEQUENCER_SECRET"
  rm -rf "$VK_OUT"
  log "starting sequencer against $CONTRACT_ID"
  exec sequencer "$@"
}

if [ -f "$INSTANCE_FILE" ]; then
  RECORDED=$(. "$INSTANCE_FILE"; echo "${INSTANCE_FINGERPRINT:-}")
  if [ "$RECORDED" = "$FINGERPRINT" ]; then
    log "recorded instance matches fingerprint; reusing"
    use_instance "$@"
  fi
  log "recorded instance fingerprint ($RECORDED) != current; re-bootstrapping"
else
  log "no recorded instance on volume; bootstrapping"
fi

# --- self-bootstrap a fresh instance ---
IDENTITY=cellarium-boot
export SOROBAN_SECRET_KEY="$SEQUENCER_SECRET" STELLAR_SECRET_KEY="$SEQUENCER_SECRET"
stellar keys add "$IDENTITY" --secret-key --overwrite >&2
unset SOROBAN_SECRET_KEY STELLAR_SECRET_KEY
SEQ_ADDR=$(stellar keys address "$IDENTITY")
log "sequencer/operator account: $SEQ_ADDR"
# Fund if the account is new; harmless if it already exists.
curl -fsS "${FRIENDBOT_URL}/?addr=${SEQ_ADDR}" >/dev/null 2>&1 || true

invoke_flags=(--rpc-url "$RPC_URL" --network-passphrase "$NETWORK_PASSPHRASE" --source-account "$IDENTITY")

log "native SAC (cash leg)"
stellar contract asset deploy --asset native "${invoke_flags[@]}" >/dev/null 2>&1 || true
TOKEN=$(stellar contract id asset --asset native --rpc-url "$RPC_URL" --network-passphrase "$NETWORK_PASSPHRASE")

log "tUST (collateral leg; admin = operator)"
TUST=$(stellar contract deploy --wasm "$WASM_DIR/tust.wasm" "${invoke_flags[@]}" -- --admin "$SEQ_ADDR")

log "oracle (admin = operator, so the heartbeat uses the sequencer secret)"
ORACLE=$(stellar contract deploy --wasm "$WASM_DIR/oracle.wasm" "${invoke_flags[@]}" -- --admin "$SEQ_ADDR")
stellar contract invoke --id "$ORACLE" "${invoke_flags[@]}" -- set_price --price "$INITIAL_PRICE" >/dev/null

GENESIS=$(sequencer genesis-root)
VK_HEX=$(od -A n -v -t x1 "$VK_BIN" | tr -d ' \n')
log "rollup (operator-pinned, genesis ${GENESIS})"
ROLLUP=$(stellar contract deploy --wasm "$WASM_DIR/rollup.wasm" "${invoke_flags[@]}" -- \
  --token_cash "$TOKEN" --token_coll "$TUST" --oracle "$ORACLE" \
  --operator "$SEQ_ADDR" --vk "$VK_HEX" --genesis_root "${GENESIS#0x}")
log "rollup deployed: $ROLLUP"

# Archive (never delete) the previous instance's DB: it belongs to the old
# contract and the new binary refuses to open it anyway.
DB_BASE="${DB_PATH:-/data/sequencer.db}"
if [ -e "$DB_BASE" ]; then
  ARCHIVE="$DATA_DIR/archive-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$ARCHIVE"
  mv "$DB_BASE" "$ARCHIVE/" 2>/dev/null || true
  mv "$DB_BASE-wal" "$DB_BASE-shm" "$ARCHIVE/" 2>/dev/null || true
  [ -f "$INSTANCE_FILE" ] && cp "$INSTANCE_FILE" "$ARCHIVE/instance.env.old" || true
  log "archived previous DB to $ARCHIVE"
fi

cat > "$INSTANCE_FILE" <<EOF
# Written by docker_entrypoint.sh — the instance this volume's DB belongs to.
INSTANCE_FINGERPRINT=$FINGERPRINT
CONTRACT_ID=$ROLLUP
TOKEN_ID=$TOKEN
TUST_ID=$TUST
TUST_ADMIN=$SEQ_ADDR
ORACLE_ID=$ORACLE
SEQUENCER_ADDRESS=$SEQ_ADDR
EOF
log "recorded new instance in $INSTANCE_FILE"

use_instance "$@"
