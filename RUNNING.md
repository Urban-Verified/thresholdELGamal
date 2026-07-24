# Running and Testing

How to run the threshold-ElGamal voting system end-to-end, both the
on-chain pipeline (target topology) and the legacy off-chain prototype,
plus how to run the test suite.

For the architecture and migration history see [`PLAN.md`](PLAN.md);
deferred work lives in [`TODO.md`](TODO.md).

## 1. Prerequisites

- **Python 3.11+**.
- **Foundry** (`anvil`, `forge`) on `PATH`, or at `~/.foundry/bin/`. Install via
  [`foundryup`](https://book.getfoundry.sh/getting-started/installation).
- The production contracts repo
  [`Urban-Verified/bulletin-board`](https://github.com/Urban-Verified/bulletin-board)
  cloned as a sibling of this repo:
  ```sh
  cd ..
  git clone git@github.com:Urban-Verified/bulletin-board.git
  cd bulletin-board && forge build
  ```
  The repo's root **is** the Foundry project — it does not contain a
  nested `voting-contracts/` or similar subfolder; `src/`, `script/`,
  `out/`, and `foundry.toml` live directly at the repo root. Default
  lookup path is `../bulletin-board` (relative to this repo). Override
  with the `VOTING_CONTRACTS_DIR` env var if your clone lives elsewhere
  or you cloned it under a different directory name. The contracts are
  deployed via `forge create` against that working tree, so it must be
  `forge build`-able.
- The shutter-voting-sdk repo is **not** required at runtime — we
  vendored the small subset we need into `src/sdk_compat.py`.

## 2. One-time setup

```sh
cd path/to/thresholdELGamal

# Python venv + deps
python3 -m venv .venv
.venv/bin/pip install -r src/requirements.txt

# Verify the contract ABIs are present (they are vendored — see
# abis/README.md for the refresh recipe if the contracts move).
ls abis/
```

## 3. Running the on-chain pipeline

The on-chain pipeline involves five long-running processes plus two
short-lived CLIs:

| Process / CLI         | Role                                                              |
| --------------------- | ----------------------------------------------------------------- |
| `anvil`               | Local EVM node                                                    |
| `keyper.py × N`       | Threshold committee members; run DKG over signed P2P HTTP (commitments + shares); publish DKG result + decryption shares on chain. |
| `wr_oracle.py`        | Dev Wahlregister-Server stub; signs ballot attestations on G1     |
| `vote_proxy.py`       | Dev stub holding `VOTE_PROXY_ROLE`; forwards ballots              |
| `dkg_coordinator.py` (CLI / lib) | Orchestrates keyper DKG HTTP APIs and triggers on-chain DKG publication. |
| voter (CLI)           | Encrypts, signs, attests, and submits ballots through the proxy   |
| `tally_aggregator.py` (CLI / lib) | Holds `TALLY_AGGREGATOR_ROLE`; verifies ballots, publishes aggregate, finalises result. Library-only — no Flask. |

Note: the tally aggregator runs full SDK-shape ballot verification
(`sdk_compat.verify_ballot`) — range OR proofs, exact-budget DLEQ,
voter Schnorr signature, and WR attestation against the on-chain
`Election.pkWR`. Election creation must therefore set `pkWR` to the
WR oracle's public key (the `chain_setup.publish_election` helper
takes `pk_wr=` for this).


### 3a. Interactive — via the admin TUI (recommended for demos)

```sh
cd src
../.venv/bin/python admin_tui.py --num-keypers 3
```

From the menu:

1. Press **`1`** — Start chain (anvil + KeyperSet + Registry)
2. Press **`2`** — Create election on chain (publishElection)
3. Press **`3`** — Start services (keypers + vote proxy + WR oracle + tally aggregator)
4. Press **`4`** — Run DKG coordinator (incl. publish on-chain)
5. Press **`5`** — Cast votes (via vote proxy)
6. Press **`6`** — Fast-forward time to votingEnd
7. Press **`7`** — Show aggregate (on-chain)
8. Press **`8`** — Keypers submit decryption shares (on-chain)
9. Press **`9`** — Show result (on-chain)
10. Press **`0`** — Stop chain
11. Press **`q`** — Quit

in chain mode — for the full lifecycle, run them separately as in §3b
below, pointing them at the addresses the TUI logged.

### 3b. Manual — each process in its own shell

Pick the deterministic anvil dev-mnemonic keys; the convention this repo
uses (and the tests rely on) is:

| Index | Role                | Address                                      |
| ----- | ------------------- | -------------------------------------------- |
| 0     | admin / Vote Manager| `0xf39F…2266`                                |
| 1     | tally aggregator    | `0x7099…79C8`                                |
| 2     | vote proxy          | `0x3C44…93BC`                                |
| 3     | keyper 1            | `0x90F7…b906`                                |
| 4     | keyper 2            | `0x15d3…6A65`                                |
| 5     | keyper 3            | `0x9965…A4dc`                                |

The full private keys are in `src/chain_setup.py:ANVIL_KEYS` (public —
these are the same keys every anvil instance ships with).

```sh
# Shell 1 — anvil
anvil --port 8545

# Shells 2–4 — keypers (each with its own anvil key). The same private
# key signs both the on-chain transactions and the P2P DKG messages
# (commitments + shares + reveals). No COORDINATOR_ADDRESS is set here,
# so these run unauthenticated (single-operator dev mode) -- every
# endpoint below works without a bearer token. See §3c for the
# authenticated, multi-operator equivalent via Docker.
cd src
KEYPER_PRIVATE_KEY=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6 \
  ../.venv/bin/python keyper.py --id 1 --port 5001 --rpc-url http://127.0.0.1:8545
KEYPER_PRIVATE_KEY=0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a \
  ../.venv/bin/python keyper.py --id 2 --port 5002 --rpc-url http://127.0.0.1:8545
KEYPER_PRIVATE_KEY=0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba \
  ../.venv/bin/python keyper.py --id 3 --port 5003 --rpc-url http://127.0.0.1:8545

# Deploy KeyperSet + ElectionRegistry + an Election. Easiest: pop into
# admin_tui.py options c then e (§3a) and grab the printed addresses.
# Then export them for the remaining processes:
export ELECTION_ADDR=0x...    # from the TUI's "Election #1 published" panel

# Shell 5 — WR oracle (deterministic dev keypair). Capture the printed vk —
# you'll need it as pkWR when publishing the election.
cd src
WR_PRIVATE_KEY=0x577200000000000000000000000000000000000000000000000000000000000001 \
  ../.venv/bin/python wr_oracle.py --port 5300

# Shell 6 — vote proxy
cd src
VOTE_PROXY_PRIVATE_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a \
  ../.venv/bin/python vote_proxy.py \
    --rpc-url http://127.0.0.1:8545 \
    --election $ELECTION_ADDR \
    --port 5400

```

Now drive the lifecycle (any shell). DKG orchestration still uses the
keyper HTTP endpoints directly:

```sh
# Run DKG: round 1 → signed-P2P commitment fan-out → signed-P2P share
# distribution → round 2 (verify locally). Each keyper needs the full
# ``members`` list of expected dealer addresses — fetch them from /status.
EID=demo-election
ADDRS=$(for kid in 1 2 3; do
  curl -s http://127.0.0.1:500$kid/status | python3 -c "import sys,json;print(json.load(sys.stdin)['address'])"
done | python3 -c "import sys,json;print(json.dumps([l.strip() for l in sys.stdin]))")
URLS='{"1":"http://127.0.0.1:5001","2":"http://127.0.0.1:5002","3":"http://127.0.0.1:5003"}'

for kid in 1 2 3; do
  curl -X POST http://127.0.0.1:500$kid/dkg/round1 \
    -H "Content-Type: application/json" \
    -d "{\"n\":3,\"t\":1,\"keyper_id\":$kid,\"election_id\":\"$EID\",\"members\":$ADDRS}"
done
for kid in 1 2 3; do
  curl -X POST http://127.0.0.1:500$kid/dkg/distribute_commitments \
    -H "Content-Type: application/json" \
    -d "{\"keyper_urls\":$URLS}"
done
for kid in 1 2 3; do
  curl -X POST http://127.0.0.1:500$kid/dkg/distribute_shares \
    -H "Content-Type: application/json" \
    -d "{\"keyper_urls\":$URLS}"
done
for kid in 1 2 3; do
  curl -X POST http://127.0.0.1:500$kid/dkg/round2 \
    -H "Content-Type: application/json" \
    -d "{\"election_id\":\"$EID\"}"
done

# Each keyper publishes the DKG result on chain.
for kid in 1 2 3; do
  curl -X POST http://127.0.0.1:500$kid/dkg/publish_on_chain \
    -H "Content-Type: application/json" \
    -d "{\"election_address\":\"$ELECTION_ADDR\",\"n\":3}"
done

# Cast votes through the proxy. --wr is the WR oracle URL — without it
# the voter sends an empty WR attestation, which the contract rejects.
cd src
../.venv/bin/python voter.py \
  --proxy http://127.0.0.1:5400 \
  --rpc-url http://127.0.0.1:8545 \
  --election $ELECTION_ADDR \
  --wr http://127.0.0.1:5300 \
  vote --choice 0
../.venv/bin/python voter.py \
  --proxy http://127.0.0.1:5400 \
  --rpc-url http://127.0.0.1:8545 \
  --election $ELECTION_ADDR \
  --wr http://127.0.0.1:5300 \
  vote --choice 1

# Use ``daemon`` to combine: aggregate, poll for shares, finalize. It can be run even before voting ends. It waits until voting ends.
TALLY_AGGREGATOR_PRIVATE_KEY=0x... \
  ../.venv/bin/python tally_aggregator.py daemon \
    --rpc-url http://127.0.0.1:8545 --election $ELECTION_ADDR --poll 2

for kid in 1 2 3; do
  curl -X POST http://127.0.0.1:500$kid/decrypt/publish_on_chain \
    -H "Content-Type: application/json" \
    -d "{\"election_address\":\"$ELECTION_ADDR\"}"
done

# Read the final tally.
../.venv/bin/python voter.py \
  --rpc-url http://127.0.0.1:8545 --election $ELECTION_ADDR result
```

### 3c. Multi-operator — via Docker (authenticated, persisted)

§3b runs everything unauthenticated on one machine — fine for quick manual
testing, but not how a real deployment looks: independently-operated
keypers, each holding only their own key, talking over a network, with
bearer-token auth and encrypted state that survives a restart. This
section walks through that shape using the actual
`docker-compose.keyper.yml` / `docker-compose.coordinator.yml` files (see
`docker/README.md` for the reference doc) — not `admin_tui.py`, not bare
`keyper.py` processes.

Reuse the anvil instance, `KeyperSet`, `ElectionRegistry`, and `$ELECTION_ADDR`
from §3b above (same `ANVIL_KEYS[3..5]` committee) — but restart anvil so
containers can reach it:

```sh
# Ctrl-C the §3b anvil, then:
anvil --host 0.0.0.0 --port 8545 --block-time 1
```

`--host 0.0.0.0` lets the keyper/coordinator **containers** reach it via
`host.docker.internal`. `--block-time 1` mines a block every second
regardless of transaction activity — anvil otherwise only mines on-demand
per transaction, so with nothing happening on-chain, the "now" the
contract sees (the latest block's timestamp) never advances and
`votingEnd` never appears to arrive. This is not a time-cheat (no
`evm_increaseTime`), just continuous block production like a real chain.

Generate a coordinator identity (its address goes on every keyper; its
signing key stays with the administrator only):

```sh
.venv/bin/python -c "
from eth_account import Account
import secrets
k = secrets.token_bytes(32)
print('COORDINATOR_SIGNING_KEY=0x' + k.hex())
print('COORDINATOR_ADDRESS=' + Account.from_key(k).address)
"
```

Create one `.env` per keyper (copy `.env.keyper.example` and fill in per
operator in a real deployment; for 3 local instances, distinct ports and
state dirs — a real single-keyper-per-machine deployment never needs
`-p` or `KEYPER_STATE_DIR_HOST` at all):

```sh
for i in 1 2 3; do
  cp .env.keyper.example .env.keyper$i
done
# Edit each .env.keyper<i>: KEYPER_PRIVATE_KEY (ANVIL_KEYS[2+i], same
# keys §3b used), KEYPER_ID=<i>, KEYPER_PORT=1500<i>,
# RPC_URL=http://host.docker.internal:8545, COORDINATOR_ADDRESS=<from above>,
# KEYPER_STATE_DIR_HOST=./keyper-state-<i>
mkdir -p keyper-state-1 keyper-state-2 keyper-state-3

docker compose -p keyper1 -f docker-compose.keyper.yml --env-file .env.keyper1 up -d --build
docker compose -p keyper2 -f docker-compose.keyper.yml --env-file .env.keyper2 up -d --build
docker compose -p keyper3 -f docker-compose.keyper.yml --env-file .env.keyper3 up -d --build

curl -s http://127.0.0.1:15001/status | python3 -m json.tool
curl -s http://127.0.0.1:15002/status | python3 -m json.tool
curl -s http://127.0.0.1:15003/status | python3 -m json.tool
```

Create the coordinator's `.env` (copy `.env.coordinator.example`, fill in
`KEYPER_URLS=http://host.docker.internal:15001,...:15002,...:15003`,
`NUM_KEYPERS=3`, `DKG_THRESHOLD=1`, `RPC_URL=http://host.docker.internal:8545`,
`ELECTION_ADDRESS=$ELECTION_ADDR`, `ELECTION_ID`, the
`COORDINATOR_SIGNING_KEY` generated above, and
`TALLY_AGGREGATOR_PRIVATE_KEY`), then bring up the coordinator stack:

```sh
cp .env.coordinator.example .env.coordinator
mkdir -p coordinator-state
docker compose -f docker-compose.coordinator.yml --env-file .env.coordinator up -d --build
```

**When does DKG actually run?** The instant this creates the
`dkg-coordinator` container — its `command` is just `["dkg-runner"]`, no
schedule, no separate trigger. `docker/dkg-runner.sh` runs immediately on
container start: wait for all 3 keypers' `/status` → mint + push bearer
tokens via `/auth/bootstrap` (writes `./coordinator-state/bootstrap_tokens.json`)
→ check `Election.isDKGFinalized()` (skip the rest if already done — safe
to re-run) → run the full ceremony (`round1` → signed P2P
`distribute_commitments` → signed P2P `distribute_shares` → `round2` →
**each keyper calls `/dkg/publish_on_chain` itself** — this *is* "keyper
submits DKG result," the last step of the same ceremony, not a separate
action) → the container exits.

```sh
docker compose -f docker-compose.coordinator.yml --env-file .env.coordinator logs -f dkg-coordinator
# ... "[dkg] done", container Exited (0)
curl -s http://127.0.0.1:15001/status | python3 -m json.tool   # dkg_completed: true
```

Cast votes exactly as in §3b (same `voter.py` commands, same `$ELECTION_ADDR`),
then watch `tally-aggregator` — already running as the other service the
same `up` command started:

```sh
docker compose -f docker-compose.coordinator.yml --env-file .env.coordinator logs -f tally-aggregator
```

No manual "submit decryption shares" step here either — once `votingEnd`
passes it automatically: publishes the aggregate → reads
`bootstrap_tokens.json` and calls each keyper's `/decrypt/publish_on_chain`
with the right bearer token (each keyper submits its own share on-chain)
→ waits for the share threshold → finalizes the result and exits.

```sh
../.venv/bin/python src/voter.py --rpc-url http://127.0.0.1:8545 --election $ELECTION_ADDR result
```

Tear down:

```sh
docker compose -f docker-compose.coordinator.yml --env-file .env.coordinator down
docker compose -p keyper1 -f docker-compose.keyper.yml --env-file .env.keyper1 down
docker compose -p keyper2 -f docker-compose.keyper.yml --env-file .env.keyper2 down
docker compose -p keyper3 -f docker-compose.keyper.yml --env-file .env.keyper3 down
rm -rf coordinator-state keyper-state-1 keyper-state-2 keyper-state-3
```

## 4. Running tests

```sh
cd src

# 4a. On-chain pytest e2e (requires anvil + forge on PATH).
# Spins up anvil once for the session; each test publishes a fresh
# election and brings up its own keypers / WR oracle / vote proxy
# on free OS-allocated ports. DKG runs P2P among the keypers.
../.venv/bin/python -m pytest tests/test_e2e_onchain.py -v

# Covers:
#   - test_full_onchain_lifecycle_single_choice
#   - test_full_onchain_lifecycle_budget_election
#   - test_late_keyper_dkg_vote_no_ops          (AlreadyFinalized skip path)
#   - test_dleq_proofs_match_sdk_transcript     (cross-impl interop)
```

```sh
# 4b. Pure crypto unit + integration tests (no chain, no Flask).
../.venv/bin/python -m pytest tests/test_comprehensive.py -v

# 4c. Compressed G1/G2 codec tests (12 cases).
../.venv/bin/python -m pytest tests/test_compressed_codecs.py -v

# 4d. SDK-compat transcript + DLEQ tests (11 cases — including 3 that
# verify our Python port accepts the bytes the TypeScript SDK already
# verified in fixtures/decrypt-share/).
../.venv/bin/python -m pytest tests/test_sdk_compat.py -v
```

```sh
#4e. Security tests
../.venv/bin/python tests/test_security_fixes.py

# 4f. Stress + perf benchmarks (on-chain).
../.venv/bin/python tests/test_stress.py
../.venv/bin/python tests/test_tally_perf.py

```

### Cross-implementation interop fixtures

`scripts/gen_share_fixture.py` regenerates the SDK-verified vectors in
`fixtures/decrypt-share/` and `fixtures/tally/`:

```sh
../.venv/bin/python scripts/gen_share_fixture.py
```

Test 4d (`test_sdk_compat.py::test_verify_existing_fixture`) loads
those vectors and re-verifies them through our Python port — the
guarantee that on-chain shares produced by `keyper.py` will verify
under SDK-built auditors.

## 5. Troubleshooting

| Symptom                                                           | Likely cause / fix                                                                                       |
| ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `forge: command not found`                                        | Foundry isn't on `PATH`. `chain_setup.py` falls back to `~/.foundry/bin/forge`; install via `foundryup`. |
| `connection refused` to RPC URL                                   | `anvil` not running. Start it (`anvil --port 8545`).                                                     |
| `voteDKGResult ... AlreadyFinalized()`                            | Another keyper crossed the threshold first. Expected — the keyper handler maps it to `skipped:dkg_already_finalized`. |
| `submitVote ... VotingClosed(uint256)`                            | Chain timestamp is past `votingEnd`. In tests, use `_OnChainDeployment.fast_forward_to_voting_end()` only after all votes are cast. |
| `submitVote ... VotingNotStarted`                                 | `voting_start` is in the future. Default helper sets it to `now − 60s`.                                  |
| `submitVote ... InvalidVotePayload` (selector `0x76b847e4`)       | A length check failed: empty `wrAttestation` / `zkProof` / `voterSignature`, ciphertext count off, or `vk` not 48 B. Most common cause: `--wr` not pointing at a running `wr_oracle.py`. |
| `tally_aggregator ... pkWR length 0 != 48`                        | Election was published without a `pk_wr=` arg. Re-publish via `chain_setup.publish_election(..., pk_wr=<48-byte WR vk>)`. |
| `tally_aggregator ... wrAttestation verification failed`          | Aggregator correctly rejected a ballot whose attestation does not verify under the on-chain `pkWR`. Check that voter and aggregator point at the same WR keypair. |
| `tally_aggregator ... private key required`                       | Pass `--private-key` or set `TALLY_AGGREGATOR_PRIVATE_KEY`. The signer must hold `TALLY_AGGREGATOR_ROLE` on the Election contract. |
| `publishAggregate ... VotingStillOpen`                            | Chain time hasn't reached `votingEnd`. Run `anvil_setNextBlockTimestamp` past it (see test helpers).     |
| Pytest budget-election test fails after a single-choice test     | The session previously fast-forwarded the chain. Tests use `chain.w3.eth.get_block("latest").timestamp` for `now`. |
| `MismatchedABI` warning when calling `publishElection`            | Pre-fix; should be silent now (`RegistryClient` filters logs by emitter address).                        |
| Legacy Flask tests fail when run together                         | Pre-existing fixed-port collision between `test_e2e.py`, `test_security_fixes.py`, and the comprehensive tests. Run files individually or use the on-chain test (4a) which uses free ports. |
| §3c: a keyper's `/status` never flips `bootstrapped: true`        | `dkg-coordinator` needs to reach that keyper at `host.docker.internal:<port>`. Confirm `.env.coordinator`'s `KEYPER_URLS` ports match each keyper's `.env.keyper<i>`'s `KEYPER_PORT`. |
| §3c: `Unauthorized` from a keyper endpoint                        | All three `.env.keyper<i>` files' `COORDINATOR_ADDRESS` must be byte-identical to each other and to the address matching `.env.coordinator`'s `COORDINATOR_SIGNING_KEY`. |
| §3c: `tally-aggregator` loops `waiting: shares on chain 0/N`       | Check its logs for `decrypt trigger failed at <url>` — a keyper container may be down, or `coordinator-state/bootstrap_tokens.json` was never written (re-check the `dkg-coordinator` logs). |
| §3c: `BSGS failed for candidate N`                                 | `KeyperSet.threshold` (deploy-time, "shares needed") must equal `DKG_THRESHOLD` (env var, "polynomial degree") `+ 1` — `chain_setup.deploy_keyper_set`'s `threshold` argument and `.env.coordinator`'s `DKG_THRESHOLD` are two different numbers. `admin_tui.py` does this conversion for you (`t_degree = thresholdT - 1`); doing it by hand is where this usually goes wrong. |

## 6. Where things live

```
abis/                       Vendored contract ABIs (see abis/README.md)
fixtures/                   SDK-verified cross-impl test vectors
scripts/gen_share_fixture.py  Regenerate fixtures from the live DKG
docker-compose.keyper.yml         Multi-operator: one keyper (docker/README.md, RUNNING.md §3c)
.env.keyper.example              Template for docker-compose.keyper.yml
docker-compose.coordinator.yml    Multi-operator: dkg-coordinator + tally-aggregator
.env.coordinator.example         Template for docker-compose.coordinator.yml
docker/
  Dockerfile                 Shared image build (src/ + abis/ + dkg-runner)
  dkg-runner.sh              dkg-coordinator entry point: wait for keypers -> bootstrap -> run DKG if needed
  README.md                  Multi-operator deployment reference (auth, bootstrap, token hand-off)
src/
  keyper.py                 DKG (signed P2P commitments + shares) + on-chain submitDecryptionShare
  keyper_persistence.py     Fernet-encrypted DKG secret / bootstrap-token persistence
  token_bootstrap.py        X25519 seal/unseal + EIP-191 payload hashing for /auth/bootstrap
  coordinator_state.py      Plaintext bootstrap_tokens.json hand-off (dkg-coordinator -> tally-aggregator)
  tally_aggregator.py       On-chain tally aggregator (library + CLI; PLAN.md decision E)
  dkg_coodinator.py         coordinates the entire dkg process among keypers
  vote_proxy.py             Dev-only ballot forwarder
  wr_oracle.py              Dev Wahlregister-Server stub (Schnorr on G1)
  voter.py                  Voter CLI: builds real ballot via sdk_compat.build_ballot
  admin_tui.py              Interactive control panel
  chain_setup.py            anvil + forge create + publishElection helpers
  eth_client.py             web3.py wrappers around the contracts
  sdk_compat.py             SDK port: transcript + DLEQ + Schnorr + ballot codec
  crypto/                   BLS12-381, ElGamal, DKG, ZK proofs (off-chain core)
  tests/
    test_e2e_onchain.py     On-chain e2e (4 tests)
    test_comprehensive.py   Pure crypto unit + integration (78 tests)
    test_compressed_codecs.py  G1/G2 zcash-format codec
    test_sdk_compat.py      SDK transcript + DLEQ + cross-impl fixtures
    test_security_fixes.py  Audit-driven regression tests
    test_stress.py          Off-chain stress (100 votes)
    test_tally_perf.py      10k-ballot tally benchmark
```
