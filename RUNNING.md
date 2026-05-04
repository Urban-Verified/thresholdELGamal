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
cd /Users/9to5mac/Desktop/code/brainbot/thresholdELGamal

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
| `bulletin_board.py`   | DKG round-1 commitment log (decision A — kept temporarily)        |
| `keyper.py × N`       | Threshold committee members; publish DKG result + shares on chain |
| `wr_oracle.py`        | Dev Wahlregister-Server stub; signs ballot attestations on G1     |
| `vote_proxy.py`       | Dev stub holding `VOTE_PROXY_ROLE`; forwards ballots              |
| voter (CLI)           | Encrypts, signs, attests, and submits ballots through the proxy   |
| `tally_aggregator.py` (CLI / lib) | Holds `TALLY_AGGREGATOR_ROLE`; verifies ballots, publishes aggregate, finalises result. Library-only — no Flask. |

Note: the tally aggregator runs full SDK-shape ballot verification
(`sdk_compat.verify_ballot`) — range OR proofs, exact-budget DLEQ,
voter Schnorr signature, and WR attestation against the on-chain
`Election.pkWR`. Election creation must therefore set `pkWR` to the
WR oracle's public key (the `chain_setup.publish_election` helper
takes `pk_wr=` for this).

`backend.py` is **off-chain only** now — it hosts the legacy Flask
state machine that the off-chain test suite still exercises, but plays
no role in the on-chain pipeline.

### 3a. Interactive — via the admin TUI (recommended for demos)

```sh
cd src
../.venv/bin/python admin_tui.py --num-keypers 3
```

From the menu:

1. Press **`c`** — Start chain (anvil + KeyperSet + Registry). Logs the
   admin / tally aggregator / vote proxy / per-keyper addresses.
2. Press **`e`** — Create election (publishElection wizard). Walks
   through `numCandidates`, `budget`, voting window, fee.
3. Press **`x`** when done — terminates anvil.

The TUI does not yet auto-launch the keyper / proxy / backend processes
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

# Shell 2 — bulletin board (decision A)
cd src && ../.venv/bin/python bulletin_board.py --port 5500

# Shells 3–5 — keypers (each with its own anvil key)
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

# Shell 6 — WR oracle (deterministic dev keypair). Capture the printed vk —
# you'll need it as pkWR when publishing the election.
cd src
WR_PRIVATE_KEY=0x577200000000000000000000000000000000000000000000000000000000000001 \
  ../.venv/bin/python wr_oracle.py --port 5300

# Shell 7 — vote proxy
cd src
VOTE_PROXY_PRIVATE_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a \
  ../.venv/bin/python vote_proxy.py \
    --rpc-url http://127.0.0.1:8545 \
    --election $ELECTION_ADDR \
    --port 5400

```

(`backend.py` is **not** part of the on-chain pipeline — it's the
off-chain Flask process for the legacy test suite. Skip it for chain runs.)

Now drive the lifecycle (any shell). DKG orchestration still uses the
keyper HTTP endpoints directly:

```sh
# Run DKG round 1 → P2P share distribution → round 2 (off-chain steps).
EID=demo-election
for kid in 1 2 3; do
  curl -X POST http://127.0.0.1:500$kid/dkg/round1 \
    -H "Content-Type: application/json" \
    -d "{\"n\":3,\"t\":1,\"keyper_id\":$kid,\"bb_url\":\"http://127.0.0.1:5500\",\"election_id\":\"$EID\"}"
done
for kid in 1 2 3; do
  curl -X POST http://127.0.0.1:500$kid/dkg/distribute_shares \
    -H "Content-Type: application/json" \
    -d '{"keyper_urls":{"1":"http://127.0.0.1:5001","2":"http://127.0.0.1:5002","3":"http://127.0.0.1:5003"}}'
done
for kid in 1 2 3; do
  curl -X POST http://127.0.0.1:500$kid/dkg/round2 \
    -H "Content-Type: application/json" \
    -d "{\"bb_url\":\"http://127.0.0.1:5500\",\"election_id\":\"$EID\"}"
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

# After votingEnd: aggregator publishes, keypers post shares, aggregator finalises.
TALLY_AGGREGATOR_PRIVATE_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
  ../.venv/bin/python tally_aggregator.py aggregate \
    --rpc-url http://127.0.0.1:8545 \
    --election $ELECTION_ADDR

for kid in 1 2 3; do
  curl -X POST http://127.0.0.1:500$kid/decrypt/publish_on_chain \
    -H "Content-Type: application/json" \
    -d "{\"election_address\":\"$ELECTION_ADDR\"}"
done

TALLY_AGGREGATOR_PRIVATE_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
  ../.venv/bin/python tally_aggregator.py finalize \
    --rpc-url http://127.0.0.1:8545 \
    --election $ELECTION_ADDR

# Or use ``auto`` to combine: aggregate, poll for shares, finalize.
TALLY_AGGREGATOR_PRIVATE_KEY=0x... \
  ../.venv/bin/python tally_aggregator.py auto \
    --rpc-url http://127.0.0.1:8545 --election $ELECTION_ADDR --poll 2 --timeout 300

# Read the final tally.
../.venv/bin/python voter.py \
  --rpc-url http://127.0.0.1:8545 --election $ELECTION_ADDR result
```

### 3c. Legacy off-chain pipeline

The original Flask-only pipeline still works end-to-end without anvil
or contracts. See [`README.md`](README.md) §"Run an election manually"
or use the admin TUI options `0`–`7` (the off-chain numeric submenu).

## 4. Running tests

```sh
cd src

# 4a. On-chain pytest e2e (requires anvil + forge on PATH).
# Spins up anvil once for the session; each test publishes a fresh
# election and brings up its own bulletin board / keypers / proxy /
# backend on free OS-allocated ports.
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
# 4e. Legacy off-chain Flask tests (still pass individually; flaky
# under parallel runs due to fixed-port collisions — that flakiness
# pre-dates the migration).
../.venv/bin/python -m pytest tests/test_e2e.py tests/test_security_fixes.py -v
```

```sh
# 4f. Stress + perf benchmarks (off-chain).
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

## 6. Where things live

```
abis/                       Vendored contract ABIs (see abis/README.md)
fixtures/                   SDK-verified cross-impl test vectors
scripts/gen_share_fixture.py  Regenerate fixtures from the live DKG
src/
  bulletin_board.py         DKG round-1 commitment log
  keyper.py                 DKG + on-chain submitDecryptionShare
  backend.py                Off-chain Flask backend (legacy test path only)
  tally_aggregator.py       On-chain tally aggregator (library + CLI; PLAN.md decision E)
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
    test_e2e.py             Legacy off-chain e2e
    test_comprehensive.py   Pure crypto unit + integration (78 tests)
    test_compressed_codecs.py  G1/G2 zcash-format codec
    test_sdk_compat.py      SDK transcript + DLEQ + cross-impl fixtures
    test_security_fixes.py  Audit-driven regression tests
    test_stress.py          Off-chain stress (100 votes)
    test_tally_perf.py      10k-ballot tally benchmark
```
