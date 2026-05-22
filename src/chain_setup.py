"""
Local anvil + forge deployment harness.

Provides the small amount of orchestration the dev loop needs on top of
``eth_client.py``:

  * ``start_anvil`` / ``stop_anvil`` — manage a local anvil node.
  * ``deploy_keyper_set`` / ``deploy_registry`` — ``forge create`` shells to
    the production contracts repo. We don't vendor bytecode (only ABIs),
    so deployment routes through ``forge`` regardless.
  * ``publish_election`` — wraps ``RegistryClient.publish_election``.
  * ``ANVIL_KEYS`` — the well-known prefunded anvil mnemonic keys, exposed
    so each role (admin / tally / vote-proxy / keyper-N) can take a
    distinct one in the dev loop.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import requests
from eth_account import Account

from eth_client import ElectionClient, EthChain, KeyperSetClient, RegistryClient


# ----------------------------------------------------------------------
#  Constants
# ----------------------------------------------------------------------

ANVIL_DEFAULT_PORT = 8545
ANVIL_DEFAULT_RPC = f"http://127.0.0.1:{ANVIL_DEFAULT_PORT}"

# Anvil's deterministic dev mnemonic prefunded keys (in deploy order).
# Public — these are the same keys every anvil instance ships with.
ANVIL_KEYS: tuple[str, ...] = (
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
    "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
    "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
    "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
    "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
)


def anvil_address(private_key: str) -> str:
    return Account.from_key(private_key).address


# ----------------------------------------------------------------------
#  Anvil lifecycle
# ----------------------------------------------------------------------

@dataclass
class AnvilProcess:
    proc: subprocess.Popen
    rpc_url: str
    port: int

    def stop(self, timeout: float = 5.0) -> None:
        if self.proc.poll() is not None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def _wait_for_rpc(rpc_url: str, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            r = requests.post(
                rpc_url,
                json={"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1},
                timeout=1,
            )
            if r.status_code == 200 and "result" in r.json():
                return
        except Exception as e:  # noqa: BLE001 — connection errors expected
            last_err = e
        time.sleep(0.1)
    raise TimeoutError(f"anvil at {rpc_url} did not respond in {timeout}s; last error: {last_err}")


def start_anvil(
    port: int = ANVIL_DEFAULT_PORT,
    *,
    accounts: int = 10,
    balance: int = 1000,
    log_path: str | None = None,
    silent: bool = True,
) -> AnvilProcess:
    """Launch anvil in the background and return a handle with ``stop()``.

    Raises if the ``anvil`` binary isn't on PATH.
    """
    binary = shutil.which("anvil") or "/Users/9to5mac/.foundry/bin/anvil"
    if not Path(binary).exists():
        raise FileNotFoundError("anvil binary not found; install foundryup")

    args = [
        binary,
        "--port", str(port),
        "--accounts", str(accounts),
        "--balance", str(balance),
    ]
    if silent:
        args.append("--silent")

    if log_path:
        log = open(log_path, "w")
    else:
        log = subprocess.DEVNULL
    proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)

    rpc_url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_rpc(rpc_url)
    except Exception:
        proc.terminate()
        raise

    return AnvilProcess(proc=proc, rpc_url=rpc_url, port=port)


def stop_anvil(handle: AnvilProcess) -> None:
    handle.stop()


# ----------------------------------------------------------------------
#  Production contracts repo location
# ----------------------------------------------------------------------

# Default to a sibling checkout of https://github.com/Urban-Verified/bulletin-board
# (this repo's parent directory, default clone name ``bulletin-board``).
# Override with ``VOTING_CONTRACTS_DIR`` if your clone lives elsewhere or
# you cloned it under a different name.
_REPO_PARENT = Path(__file__).resolve().parent.parent.parent
DEFAULT_VOTING_CONTRACTS = Path(
    os.environ.get(
        "VOTING_CONTRACTS_DIR",
        str(_REPO_PARENT / "bulletin-board"),
    )
)


def _forge_binary() -> str:
    return shutil.which("forge") or "/Users/9to5mac/.foundry/bin/forge"


_DEPLOYED_TO_RE = re.compile(r"Deployed to:\s*(0x[a-fA-F0-9]{40})")


def _forge_create(
    *,
    rpc_url: str,
    private_key: str,
    contract: str,
    constructor_args: Iterable[str] = (),
    contracts_dir: Path = DEFAULT_VOTING_CONTRACTS,
) -> str:
    """Run ``forge create`` against ``contracts_dir`` and return the deployed address.

    ``contract`` is e.g. ``"src/KeyperSet.sol:KeyperSet"``.
    """
    cmd = [
        _forge_binary(), "create",
        "--broadcast",
        "--rpc-url", rpc_url,
        "--private-key", private_key,
        contract,
    ]
    if constructor_args:
        cmd.append("--constructor-args")
        cmd.extend(str(a) for a in constructor_args)

    env = os.environ.copy()
    env.setdefault("FOUNDRY_DISABLE_NIGHTLY_WARNING", "1")

    res = subprocess.run(
        cmd, cwd=str(contracts_dir), env=env,
        capture_output=True, text=True, timeout=60,
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"forge create {contract} failed:\n--- stdout ---\n{res.stdout}\n--- stderr ---\n{res.stderr}"
        )

    m = _DEPLOYED_TO_RE.search(res.stdout)
    if not m:
        raise RuntimeError(f"could not parse 'Deployed to' from forge output:\n{res.stdout}")
    return m.group(1)


def deploy_keyper_set(
    *,
    rpc_url: str,
    deployer_key: str,
    members: list[str],
    threshold: int,
    contracts_dir: Path = DEFAULT_VOTING_CONTRACTS,
) -> str:
    """Deploy ``KeyperSet`` and return its address."""
    members_arg = "[" + ",".join(members) + "]"
    return _forge_create(
        rpc_url=rpc_url,
        private_key=deployer_key,
        contract="src/KeyperSet.sol:KeyperSet",
        constructor_args=[members_arg, str(threshold)],
        contracts_dir=contracts_dir,
    )


def deploy_registry(
    *,
    rpc_url: str,
    deployer_key: str,
    admin: str,
    contracts_dir: Path = DEFAULT_VOTING_CONTRACTS,
) -> str:
    """Deploy ``ElectionRegistry`` and return its address."""
    return _forge_create(
        rpc_url=rpc_url,
        private_key=deployer_key,
        contract="src/ElectionRegistry.sol:ElectionRegistry",
        constructor_args=[admin],
        contracts_dir=contracts_dir,
    )


# ----------------------------------------------------------------------
#  publishElection wrapper
# ----------------------------------------------------------------------

def publish_election(
    *,
    chain: EthChain,
    registry_address: str,
    keyper_set_address: str,
    voting_start: int,
    voting_end: int,
    num_candidates: int,
    budget: int,
    self_submit_fee: int = 0,
    pk_wr: bytes = b"",   # 48-byte compressed G1 of the WR oracle's Schnorr vk
    tally_aggregator: str,
    vote_proxy: str,
    signer=None,
) -> str:
    """Call ``ElectionRegistry.publishElection`` and return the new ``Election`` address."""
    registry = RegistryClient(chain, registry_address)
    params = {
        "votingStart": voting_start,
        "votingEnd": voting_end,
        "selfSubmitFee": self_submit_fee,
        "numCandidates": num_candidates,
        "budget": budget,
        "pkWR": pk_wr,
        "tallyAggregator": tally_aggregator,
        "voteProxy": vote_proxy,
    }
    election_addr, _receipt = registry.publish_election(
        keyper_set_address, params, signer=signer,
    )
    return election_addr


# ----------------------------------------------------------------------
#  Snapshot of a deployment, for dashboards / tests
# ----------------------------------------------------------------------

@dataclass
class ChainDeployment:
    """Captured addresses + the ``EthChain`` used to read them."""

    chain: EthChain
    keyper_set: str
    registry: str
    elections: list[str]

    def keyper_set_client(self) -> KeyperSetClient:
        return KeyperSetClient(self.chain, self.keyper_set)

    def registry_client(self) -> RegistryClient:
        return RegistryClient(self.chain, self.registry)

    def latest_election_client(self) -> ElectionClient | None:
        if not self.elections:
            return None
        return ElectionClient(self.chain, self.elections[-1])
