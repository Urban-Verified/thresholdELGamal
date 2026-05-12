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
# (commitments + shares + reveals).
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
    --rpc-url http://127.0.0.1:8545 --election $ELECTION_ADDR --poll 2 --timeout 300

for kid in 1 2 3; do
  curl -X POST http://127.0.0.1:500$kid/decrypt/publish_on_chain \
    -H "Content-Type: application/json" \
    -d "{\"election_address\":\"$ELECTION_ADDR\"}"
done

# Read the final tally.
../.venv/bin/python voter.py \
  --rpc-url http://127.0.0.1:8545 --election $ELECTION_ADDR result
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

## 6. Where things live

```
abis/                       Vendored contract ABIs (see abis/README.md)
fixtures/                   SDK-verified cross-impl test vectors
scripts/gen_share_fixture.py  Regenerate fixtures from the live DKG
src/
  keyper.py                 DKG (signed P2P commitments + shares) + on-chain submitDecryptionShare
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
