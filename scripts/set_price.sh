#!/usr/bin/env bash
# Push a tUST/XLM price to the mock oracle (PLAN.md §1.6).
# Price convention: XLM per 1 whole tUST × 1e7 (PLAN.md §6.1.1), e.g.
# 250000000 = 25 XLM per tUST. Reads ORACLE_ID (+ optionally
# ORACLE_ADMIN_SECRET) from .env unless already exported.
#
# usage: scripts/set_price.sh <price>
set -euo pipefail
cd "$(dirname "$0")/.."

PRICE="${1:?usage: set_price.sh <price (XLM-per-tUST x 1e7)>}"

if [ -f .env ]; then
  set -a; source .env; set +a
fi
: "${ORACLE_ID:?ORACLE_ID not set (run just bootstrap)}"
NET="${NETWORK:-testnet}"

# Prefer the bootstrap identity; fall back to the secret from .env.
if stellar keys address cellarium-oracle-admin >/dev/null 2>&1; then
  SOURCE=cellarium-oracle-admin
else
  : "${ORACLE_ADMIN_SECRET:?no cellarium-oracle-admin identity and no ORACLE_ADMIN_SECRET}"
  SOURCE="$ORACLE_ADMIN_SECRET"
fi

stellar contract invoke --id "$ORACLE_ID" --source "$SOURCE" --network "$NET" -- \
  set_price --price "$PRICE" >/dev/null
echo "oracle $ORACLE_ID price set to $PRICE"
