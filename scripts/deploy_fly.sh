#!/usr/bin/env bash
# Deploy the sequencer to Fly.io. The container self-bootstraps
# (AUTO_BOOTSTRAP=1 in fly.toml): on a circuit/schema change it deploys
# fresh contracts and resets the DB by itself, so this script only needs to
# guarantee the SEQUENCER_SECRET exists and kick off a remote build
# (required: the image is amd64-only and Apple Silicon can't build it
# locally).
#
# The secret comes from, in order: $SEQUENCER_SECRET, the bootstrap .env,
# or the secret already set on the app.
set -euo pipefail
cd "$(dirname "$0")/.."

APP="${FLY_APP:-cellarium}"

if [ -z "${SEQUENCER_SECRET:-}" ] && [ -f .env ]; then
  SEQUENCER_SECRET=$(. ./.env; echo "${SEQUENCER_SECRET:-}")
fi

if [ -n "${SEQUENCER_SECRET:-}" ]; then
  echo "==> staging SEQUENCER_SECRET (applied with the deploy)"
  fly secrets set --app "$APP" --stage "SEQUENCER_SECRET=$SEQUENCER_SECRET" >/dev/null
elif fly secrets list --app "$APP" | grep -q SEQUENCER_SECRET; then
  echo "==> reusing the app's existing SEQUENCER_SECRET"
else
  echo "no SEQUENCER_SECRET in env/.env and none set on the app" >&2
  echo "generate one:  stellar keys generate cellarium-op && stellar keys show cellarium-op" >&2
  exit 1
fi

echo "==> remote deploy (entrypoint re-bootstraps the instance if needed)"
fly deploy --app "$APP" --remote-only

echo "==> status"
fly status --app "$APP" | head -12
curl -s "https://${APP}.fly.dev/status" && echo
