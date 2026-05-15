# Docker Compose — keypers + DKG coordinator + tally aggregator

Spin up an arbitrary-sized keyper cluster, run DKG end-to-end, and
poll-and-tally the result against any chain. The compose stack is
intentionally scoped to a single election — bring your own RPC, your
own deployed `Election` contract, and your own WR oracle / vote proxy
(run those from `src/` on the host).

## Layout

```
docker/
├── Dockerfile             # builds the shared image (src/ + abis/ + dkg-runner)
├── dkg-runner.sh          # entry point for the one-shot dkg-coordinator
├── .env.example           # copy to .env and edit
├── generate-compose.py    # renders docker-compose.yml from .env
└── docker-compose.yml     # (generated — do not edit by hand)
```

## What the services do

- **`keyper-<i>`** — long-running Flask servers participating in DKG
  and partial decryption. Each one listens internally on port 5000 and
  is exposed on the host at `KEYPER_HOST_PORT_BASE + i`.
- **`dkg-coordinator`** — one-shot. Waits for every keyper's `/status`,
  checks `Election.isDKGFinalized()` on chain, and runs the full DKG
  protocol (round1 → distribute commitments → distribute shares →
  round2 → publish on chain) if not already done. Re-running
  `docker compose up` is safe: the on-chain check short-circuits it.
- **`tally-aggregator`** — long-running daemon. Waits for `votingEnd`,
  publishes the aggregate, waits for `thresholdT` decryption shares,
  then publishes the result and exits.

Casting votes and triggering keyper `decrypt/publish_on_chain` is still
done from the host — see step 6 below.

## Prerequisites

- Docker (with `docker compose` v2 — no separate `docker-compose` binary needed).
- Python 3 on the host (only used to run `generate-compose.py`; preinstalled on standard Ubuntu/Debian/DigitalOcean droplet images).
- A reachable chain RPC and a deployed `Election` contract on that chain.
- Per-keyper private keys whose addresses are already registered as
  members of the on-chain `KeyperSet` for this election.
- A private key holding `TALLY_AGGREGATOR_ROLE` on the `Election`.

## 1. Configure

```sh
cd docker
cp .env.example .env
```

All knobs live in `.env`:

| Variable | Meaning |
|---|---|
| `NUM_KEYPERS` | Committee size (e.g. `3`, `5`, `7`). |
| `KEYPER_HOST_PORT_BASE` | Host port for keyper 1 is `base + 1`; keyper 2 is `base + 2`; … |
| `RPC_URL` | Chain RPC URL. Use `http://host.docker.internal:8545` to reach a node on the docker host (works on Linux too via `extra_hosts`). |
| `ELECTION_ADDRESS` | Address of the deployed `Election` contract for this run. |
| `ELECTION_ID` | Opaque DKG scope string (any non-empty value, kept stable per election). |
| `DKG_THRESHOLD` | Polynomial degree `t` — `t+1` shares are required to decrypt. Typical: `floor((NUM_KEYPERS - 1) / 2)`. |
| `KEYPER_PRIVATE_KEY_<i>` | Per-keyper Ethereum key (also signs P2P DKG messages). Must match the i-th `KeyperSet` member address. |
| `TALLY_AGGREGATOR_PRIVATE_KEY` | Key holding `TALLY_AGGREGATOR_ROLE` on the `Election`. |
| `TALLY_POLL_SECONDS` | Tally daemon poll interval. |

If you raise `NUM_KEYPERS` past 3, add the extra `KEYPER_PRIVATE_KEY_<i>`
lines.

## 2. Render the compose file

```sh
python3 generate-compose.py
```

Writes `docker-compose.yml` with `keyper-1`..`keyper-N`, the one-shot
`dkg-coordinator`, and the long-running `tally-aggregator`. Re-run any
time you change `NUM_KEYPERS` or the port base in `.env`.

## 3. Bring the stack up

```sh
docker compose up --build
```

First boot builds the shared `threshold-elgamal-app` image; subsequent
boots reuse it. Drop `--build` to skip the rebuild step.

To run detached:

```sh
docker compose up -d --build
docker compose logs -f
```

## 4. Verify the services

Each keyper exposes a `/status` endpoint on `KEYPER_HOST_PORT_BASE + i`
(defaults to 5001, 5002, …):

```sh
curl -s http://127.0.0.1:5001/status | jq
curl -s http://127.0.0.1:5002/status | jq
curl -s http://127.0.0.1:5003/status | jq
```

The `address` field should match the keyper-set member at index `i-1`.

## 5. DKG runs automatically

The `dkg-coordinator` service comes up after the keypers, waits for
their `/status` endpoints, and runs the full DKG protocol. Watch its
logs:

```sh
docker compose logs -f dkg-coordinator
```

It exits with code 0 as soon as the DKG result is finalized on chain.
Re-running `docker compose up` is safe — the service checks
`Election.isDKGFinalized()` first and short-circuits.

To drive DKG manually instead (e.g. from the admin TUI on the host),
ignore the service and run the curl recipe from `RUNNING.md` §3b
against the host-exposed keyper ports.

## 6. Cast votes and trigger decryption

Vote casting is done from the host — see `RUNNING.md` §3b for the full
curl recipe. After voting ends, each keyper publishes its decryption
share:

```sh
for kid in 1 2 3; do
  curl -X POST http://127.0.0.1:500$kid/decrypt/publish_on_chain \
    -H "Content-Type: application/json" \
    -d "{\"election_address\":\"$ELECTION_ADDRESS\"}"
done
```

The `tally-aggregator` daemon picks up the aggregate publish and the
decryption shares automatically — watch its logs:

```sh
docker compose logs -f tally-aggregator
```

## 7. Tear down

```sh
docker compose down
```

Add `-v` if you ever introduce named volumes you want wiped.

## Common changes

| Change | Action |
|---|---|
| Add/remove keypers | Edit `NUM_KEYPERS` (and add `KEYPER_PRIVATE_KEY_<i>` entries) → re-run `generate-compose.py` → `docker compose up`. |
| Move to a new chain | Edit `RPC_URL` and `ELECTION_ADDRESS` → `docker compose up` (no regenerate needed — these are read at container start). |
| Change exposed ports | Edit `KEYPER_HOST_PORT_BASE` → re-run `generate-compose.py`. |
| Rotate keyper keys | Edit `KEYPER_PRIVATE_KEY_<i>` → `docker compose up` (the new key is read at container start). Make sure the new address is registered in the on-chain `KeyperSet`. |

## Troubleshooting

- **`error: .env not found`** — run `cp .env.example .env` first.
- **`error: KEYPER_PRIVATE_KEY_<i> missing`** — add the missing key for
  every `i` in `1..NUM_KEYPERS`.
- **`ConnectionError` to RPC** — if your chain runs on the docker host,
  use `http://host.docker.internal:8545` (works on Linux too because
  the compose file wires `host.docker.internal` to the host gateway).
- **Keyper signature errors during DKG** — the address derived from
  `KEYPER_PRIVATE_KEY_<i>` does not match the i-th `KeyperSet` member.
  Check `curl /status` on each keyper and compare against the on-chain
  set.
- **Tally daemon loops with "DKG not finalized"** — expected until
  enough keypers have called `/dkg/publish_on_chain` to cross the
  threshold.
