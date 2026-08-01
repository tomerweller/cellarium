#!/usr/bin/env bash
# Mint mock tUST (7-decimal base units) to any G.../C... address via the
# token admin identity that bootstrap controls. Pure Soroban token — no
# trustline needed on the destination.
#
# usage: scripts/mint_tust.sh <destination> <amount-base-units>
set -euo pipefail
cd "$(dirname "$0")/.."

DEST="${1:?usage: mint_tust.sh <dest address> <amount base units>}"
AMOUNT="${2:?usage: mint_tust.sh <dest address> <amount base units>}"

if [ -f .env ]; then
  set -a; source .env; set +a
fi
: "${TUST_ID:?TUST_ID not set (run just bootstrap)}"
NET="${NETWORK:-testnet}"

stellar contract invoke --id "$TUST_ID" --source cellarium-tust-admin --network "$NET" -- \
  mint --to "$DEST" --amount "$AMOUNT" >/dev/null
echo "minted $AMOUNT tUST base units to $DEST"
