# Docker Compose — multi-operator deployment

Two independent stacks, matching the two real-world roles in a live
election:

- **`docker-compose.keyper.yml`** (project root) — one committee member.
  Run by each keyper operator, on their own machine, holding only their
  own private key.
- **`docker-compose.coordinator.yml`** (project root) — `dkg-coordinator` +
  `tally-aggregator`. Run once by the election administrator, who holds
  the chain RPC, the deployed `Election` contract, and the public URLs of
  every keyper operator.

This directory (`docker/`) only holds the shared image build (`Dockerfile`)
and the one-shot coordinator entry point (`dkg-runner.sh`) — the compose
files themselves live at the project root, since that's where each
operator actually runs `docker compose up` from.

For a single-machine demo with no real multi-operator auth, use
`admin_tui.py` instead (see `RUNNING.md` §3a) — it spins up all keypers
in-process and drives the whole election via a menu. These compose files
are for a *real* deployment: independently-operated keypers, each holding
only their own key, talking over the network.

## Layout

```
docker/
├── Dockerfile              # builds the shared image (src/ + abis/ + dkg-runner)
├── dkg-runner.sh            # entry point for the one-shot dkg-coordinator
└── README.md                # this file

(project root)
├── docker-compose.keyper.yml       # one keyper — run by each operator
├── .env.keyper.example
├── docker-compose.coordinator.yml  # dkg-coordinator + tally-aggregator — run once
└── .env.coordinator.example
```

## What the services do

- **`keyper`** (`docker-compose.keyper.yml`) — one Flask server
  participating in DKG and partial decryption. Persists its DKG secret,
  its bootstrap-installed bearer tokens, and its bootstrap X25519 keypair
  to a Fernet-encrypted volume (`./keyper-state`, key derived from
  `KEYPER_PRIVATE_KEY`), so a restart never needs a fresh DKG ceremony or
  a fresh bootstrap.
- **`dkg-coordinator`** (`docker-compose.coordinator.yml`) — one-shot.
  First bootstraps every keyper's bearer tokens (mints an `api_token` +
  `peer_token` pair per keyper, seals + signs them via each keyper's
  `/auth/bootstrap`, and writes `./coordinator-state/bootstrap_tokens.json`
  so `tally-aggregator` can use the same tokens later — see "Auth &
  bootstrap" below). Then checks `Election.isDKGFinalized()` and runs the
  DKG protocol (round1 → distribute commitments → distribute shares →
  round2 → publish on chain) if not already done. Re-running
  `docker compose up` is safe: both steps are idempotent.
- **`tally-aggregator`** (`docker-compose.coordinator.yml`) — long-running
  daemon. Waits for `votingEnd`, publishes the aggregate, then reads
  `./coordinator-state/bootstrap_tokens.json` and calls each keyper's
  `/decrypt/publish_on_chain` directly (no manual step needed — see
  "Auth & bootstrap"), waits for `thresholdT` decryption shares, publishes
  the result, and exits.

## Auth & bootstrap

Every keyper endpoint except `/status`, `/health`, and `/auth/bootstrap`
requires a bearer token once `COORDINATOR_ADDRESS` is set on that keyper
(empty = single-operator dev mode, no auth enforced — never use this for
a real multi-operator deployment). Two token tiers, mirroring sx-monorepo's
design:

- **`api_token`** — held by `dkg-coordinator` and reused as-is by
  `tally-aggregator` (deliberately the *same* token, not a third type —
  keeps operational surface small). Required on round1/round2/
  distribute_*/publish_on_chain/decrypt/publish_on_chain.
- **`peer_token`** — held by every keyper, used only for keyper-to-keyper
  P2P calls (`/dkg/receive_commitments`, `/dkg/receive_share`).

Tokens are minted once by `dkg-coordinator` (never rotated automatically)
and pushed to each keyper over an anonymous X25519 sealed box, EIP-191
signed by `COORDINATOR_SIGNING_KEY` so a keyper can verify the push really
came from its configured `COORDINATOR_ADDRESS` — an unauthenticated
`POST /auth/bootstrap` is unavoidable (it establishes the very
credentials every other route checks), so authenticity comes entirely
from that signature, not from the HTTP layer.

`dkg-coordinator` also delivers each keyper's `peers` map (every *other*
keyper's URL + P2P token) via this same bootstrap push. Keypers never
accept a caller-supplied address book from an authenticated request body
— `distribute_commitments`/`distribute_shares` always fan out to the
bootstrap-installed `peers` map once auth is on, so a leaked `api_token`
alone can't be used to redirect where a keyper's shares get sent.

`tally-aggregator` needs the same `api_token`s much later — after
`votingEnd`, to trigger decryption — but the two processes share no
database and don't overlap in any guaranteed way. The fix:
`dkg-coordinator` writes `./coordinator-state/bootstrap_tokens.json`
(a Docker volume mounted at the project root, `{keyper_url:
{api_token, peer_token}}`), and `tally-aggregator` reads it lazily —
right when it's about to trigger decryption, not at daemon startup —
retrying automatically on its own poll loop if the file isn't there yet.
This file is **plaintext**, not Fernet-encrypted like keyper-side state:
both processes are run by the same administering party that already
holds `TALLY_AGGREGATOR_PRIVATE_KEY` and `COORDINATOR_SIGNING_KEY` in the
same `.env`/filesystem trust boundary, so it adds no new secret exposure.

Because `tally-aggregator` now triggers decryption automatically,
`admin_tui.py`'s menu option **8 — "Keypers submit decryption shares
(on-chain)"** is not needed in this deployment path; it remains useful
only for the single-machine demo TUI, where nothing else triggers it.

## Prerequisites

- Docker (with `docker compose` v2).
- A reachable chain RPC and a deployed `Election` contract on that chain.
- Per-keyper private keys whose addresses are already registered as
  members of the on-chain `KeyperSet` for this election.
- A private key holding `TALLY_AGGREGATOR_ROLE` on the `Election`.
- (Multi-operator auth) A `COORDINATOR_SIGNING_KEY` generated by the
  election administrator; its address shared with every keyper operator
  as their `COORDINATOR_ADDRESS`.

## 1. Each keyper operator

```sh
cp .env.keyper.example .env
mkdir -p keyper-state
docker compose -f docker-compose.keyper.yml up -d --build
```

Fill in `.env`: `KEYPER_PRIVATE_KEY`, `RPC_URL`, `KEYPER_PORT`,
and (once the administrator has generated one) `COORDINATOR_ADDRESS`.
Share your public URL with the administrator during onboarding — no
token to generate or exchange yourself.

Verify:

```sh
curl -s http://127.0.0.1:${KEYPER_PORT:-5001}/status | jq
```

`address` should match your `KeyperSet` member entry; `bootstrapped`
flips to `true` once the administrator's `dkg-coordinator` reaches you.

## 2. Election administrator

```sh
cp .env.coordinator.example .env
mkdir -p coordinator-state
docker compose -f docker-compose.coordinator.yml up --build
```

Fill in `.env`: `KEYPER_URLS` (every keyper operator's public URL — any
order; `dkg-coordinator` resolves each one's real DKG index from the
on-chain `KeyperSet`, not from position in this list), `NUM_KEYPERS`,
`DKG_THRESHOLD`, `RPC_URL`, `ELECTION_ADDRESS`, `ELECTION_ID`,
`COORDINATOR_SIGNING_KEY`, `TALLY_AGGREGATOR_PRIVATE_KEY`, `TALLY_POLL_SECONDS`.

`dkg-coordinator` bootstraps tokens, runs DKG, and exits 0. Watch it:

```sh
docker compose -f docker-compose.coordinator.yml logs -f dkg-coordinator
```

`tally-aggregator` keeps running, watching for `votingEnd`:

```sh
docker compose -f docker-compose.coordinator.yml logs -f tally-aggregator
```

## 3. Cast votes

Still done from the host / voter tooling directly against the deployed
`Election` contract — see `RUNNING.md` §3b.

## 4. Tear down

```sh
docker compose -f docker-compose.keyper.yml down      # each keyper operator
docker compose -f docker-compose.coordinator.yml down  # the administrator
```

## Local multi-keyper testing on one machine

Run `docker-compose.keyper.yml` more than once with different project
names, ports, and state directories:

```sh
KEYPER_PORT=5001 KEYPER_STATE_DIR_HOST=./keyper-state-1 \
  docker compose -p keyper1 -f docker-compose.keyper.yml up -d
KEYPER_PORT=5002 KEYPER_STATE_DIR_HOST=./keyper-state-2 \
  docker compose -p keyper2 -f docker-compose.keyper.yml up -d
KEYPER_PORT=5003 KEYPER_STATE_DIR_HOST=./keyper-state-3 \
  docker compose -p keyper3 -f docker-compose.keyper.yml up -d
```

Then point `docker-compose.coordinator.yml`'s `KEYPER_URLS` at
`http://host.docker.internal:5001,...:5002,...:5003`.

## Troubleshooting

- **Keyper stuck `bootstrapped: false`** — check `dkg-coordinator`'s logs;
  it needs to reach that keyper's `/status` over the network. Confirm the
  keyper's public URL is correct in the administrator's `KEYPER_URLS`.
- **`Unauthorized` from a keyper endpoint** — either `COORDINATOR_ADDRESS`
  is set on the keyper but it was never successfully bootstrapped (check
  `/status.bootstrapped`), or `COORDINATOR_SIGNING_KEY` doesn't match the
  address the keyper expects.
- **`ConnectionError` to RPC** — if your chain runs on the docker host,
  use `http://host.docker.internal:8545` (both compose files wire the
  alias on Linux too).
- **Tally daemon loops with "DKG not finalized"** — expected until
  `dkg-coordinator` (or a manual run) crosses the on-chain threshold.
- **Tally daemon loops with "shares on chain 0/N"** — check
  `tally-aggregator`'s logs for `decrypt trigger failed at <url>`; a
  keyper may be unreachable or still missing its bootstrap token.
