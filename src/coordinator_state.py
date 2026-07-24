"""Plaintext file-based hand-off of keyper bearer tokens from
dkg-coordinator to tally-aggregator.

Both are one-shot/long-running processes with no shared database and no
overlapping lifetime guarantee -- dkg-coordinator runs once, early in the
election, and tally-aggregator only needs the tokens much later, after
votingEnd, to trigger each keyper's ``/decrypt/publish_on_chain``.

Deliberately plaintext, unlike keyper-side state (Fernet-encrypted): both
processes are run by the same administering party that already holds
TALLY_AGGREGATOR_PRIVATE_KEY and COORDINATOR_SIGNING_KEY in the same
.env/filesystem trust boundary, so this file adds no new secret exposure
for that party. It sits on a project-root-mounted Docker volume so it
survives both processes' container lifetimes independently.
"""
from __future__ import annotations

import json
import os
import pathlib

_DEFAULT_STATE_DIR = str(pathlib.Path(__file__).resolve().parent.parent / "coordinator-state")


def state_dir() -> pathlib.Path:
    d = pathlib.Path(os.environ.get("COORDINATOR_STATE_DIR", _DEFAULT_STATE_DIR))
    d.mkdir(parents=True, exist_ok=True)
    return d


def bootstrap_tokens_file() -> pathlib.Path:
    return state_dir() / "bootstrap_tokens.json"


def load_tokens() -> dict[str, dict[str, str]]:
    """{keyper_url: {"api_token": str, "peer_token": str}} -- empty if the
    file doesn't exist yet (dkg-coordinator hasn't bootstrapped, or
    single-operator dev mode where bootstrapping never runs)."""
    path = bootstrap_tokens_file()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def save_tokens(tokens: dict[str, dict[str, str]]) -> None:
    path = bootstrap_tokens_file()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(tokens, indent=2, sort_keys=True))
    os.replace(tmp, path)
