# Vendored Contract ABIs

ABIs for the production voting contracts at
[`Urban-Verified/bulletin-board`](https://github.com/Urban-Verified/bulletin-board).

These are vendored (not loaded from a sibling repo at runtime) so this
repo's Python code can run without a parallel checkout for read-only
chain access.

## Contents

| File                       | Source artifact                                |
| -------------------------- | ---------------------------------------------- |
| `KeyperSet.json`           | `out/KeyperSet.sol/KeyperSet.json`             |
| `ElectionRegistry.json`    | `out/ElectionRegistry.sol/ElectionRegistry.json` |
| `Election.json`            | `out/Election.sol/Election.json`               |
| `IKeyperSet.json`          | `out/IKeyperSet.sol/IKeyperSet.json`           |
| `IElectionRegistry.json`   | `out/IElectionRegistry.sol/IElectionRegistry.json` |
| `IElection.json`           | `out/IElection.sol/IElection.json`             |

Each file holds **only** the `abi` array. Bytecode, metadata, and
`methodIdentifiers` are stripped — the Python side never deploys; that
is handled by `forge script` against a local clone of the contracts repo.

## Source commit

[`Urban-Verified/bulletin-board`](https://github.com/Urban-Verified/bulletin-board)
@ `55eba7e39bd61cc9489bf72b9ac422aed4d2bde9`

`Election.json` / `IElection.json` therefore differ from that commit:

- `getBallot` / `getBallots` return `BallotView`, whose `zkProofHash`
  (`bytes32`) replaces `zkProof` (`bytes`).
- `VoteSubmitted` carries a third, non-indexed `bytes zkProof` — the full
  proof now travels in the event rather than in contract storage.
- `submitVote`'s input is **unchanged**, so the ballot-building and
  submission path needs no changes.

## Refresh

Clone the contracts repo as a sibling of this one (or anywhere else and
set `VOTING_CONTRACTS_DIR`), then build it and run the extractor. The
repo's root **is** the Foundry project — `src/`, `out/`, `foundry.toml`
all live at the top level.

```sh
# 1. Clone (skip if already present). Default clone name is bulletin-board.
cd ..
git clone https://github.com/Urban-Verified/bulletin-board.git

# 2. Build the artifacts.
cd bulletin-board
forge build

# 3. Extract just the ``abi`` arrays.
cd ../thresholdELGamal
VOTING_CONTRACTS="${VOTING_CONTRACTS_DIR:-../bulletin-board}"
python3 - <<PY
import json, os
SRC = "$VOTING_CONTRACTS/out"
DST = "abis"
artifacts = [
    "KeyperSet.sol/KeyperSet.json",
    "ElectionRegistry.sol/ElectionRegistry.json",
    "Election.sol/Election.json",
    "IElection.sol/IElection.json",
    "IElectionRegistry.sol/IElectionRegistry.json",
    "IKeyperSet.sol/IKeyperSet.json",
]
for rel in artifacts:
    with open(os.path.join(SRC, rel)) as f:
        data = json.load(f)
    out = os.path.join(DST, os.path.basename(rel))
    with open(out, "w") as f:
        json.dump(data["abi"], f, indent=2)
    print(f"wrote {out}")
PY
```

After refreshing, update the source commit SHA above.
