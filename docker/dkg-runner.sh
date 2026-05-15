#!/bin/sh
# Entry point for the one-shot dkg-coordinator service.
#   1. Waits for every keyper's /status to return 200.
#   2. Checks Election.isDKGFinalized() on chain; exits 0 if already done.
#   3. Runs dkg_coordinator.py, which fans the DKG protocol across keypers
#      and publishes the result on chain.
#
# Re-running is safe: step 2 short-circuits once the on-chain DKG has
# been finalized, so subsequent `docker compose up` invocations are no-ops.
set -eu

: "${KEYPER_URLS:?KEYPER_URLS not set}"
: "${RPC_URL:?RPC_URL not set}"
: "${ELECTION_ADDRESS:?ELECTION_ADDRESS not set}"
: "${ELECTION_ID:?ELECTION_ID not set}"
: "${NUM_KEYPERS:?NUM_KEYPERS not set}"
: "${DKG_THRESHOLD:?DKG_THRESHOLD not set}"

echo "[dkg-runner] waiting for keypers..."
for url in $(echo "$KEYPER_URLS" | tr ',' ' '); do
  until curl -fsS "$url/status" >/dev/null 2>&1; do
    sleep 2
  done
  echo "[dkg-runner]   $url ready"
done

echo "[dkg-runner] checking on-chain DKG state..."
if python - <<'PY'
import os, sys
from eth_client import EthChain, ElectionClient
chain = EthChain.connect(os.environ["RPC_URL"])
ec = ElectionClient(chain, os.environ["ELECTION_ADDRESS"])
sys.exit(0 if ec.is_dkg_finalized() else 1)
PY
then
  echo "[dkg-runner] DKG already finalized on chain — nothing to do"
  exit 0
fi

echo "[dkg-runner] orchestrating DKG (n=$NUM_KEYPERS, t=$DKG_THRESHOLD)"
exec python dkg_coordinator.py \
  --keyper-urls="$KEYPER_URLS" \
  --election-id="$ELECTION_ID" \
  --election-address="$ELECTION_ADDRESS" \
  --n="$NUM_KEYPERS" \
  --t="$DKG_THRESHOLD"
