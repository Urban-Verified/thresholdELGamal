"""
On-chain tally performance smoke test.

Intent: time `tally_aggregator.aggregate()` and `tally_aggregator.finalize()` on a
moderate number of ballots and ensure correctness. We do not enforce strict
time budgets in CI; we simply surface timings.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
import threading
import time

import pytest
import requests

logging.getLogger("werkzeug").setLevel(logging.ERROR)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eth_account import Account  # noqa: E402
from chain_setup import (  # noqa: E402
    ANVIL_KEYS,
    anvil_address,
    deploy_keyper_set,
    deploy_registry,
    publish_election,
    start_anvil,
    stop_anvil,
)
from eth_client import ElectionClient, EthChain  # noqa: E402
from keyper import create_keyper_app  # noqa: E402
from vote_proxy import create_vote_proxy_app  # noqa: E402
from voter import cast_vote_via_proxy  # noqa: E402
from wr_oracle import create_wr_oracle_app  # noqa: E402
from sdk_compat import schnorr_keygen  # noqa: E402
from crypto.primitives import g1_to_compressed  # noqa: E402
import tally_aggregator  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve(app, port: int, host: str = "127.0.0.1") -> threading.Thread:
    t = threading.Thread(
        target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False),
        daemon=True,
    )
    t.start()
    return t


def _wait_http(url: str, retries: int = 80, delay: float = 0.05) -> None:
    for _ in range(retries):
        try:
            requests.get(url, timeout=0.5)
            return
        except requests.exceptions.ConnectionError:
            time.sleep(delay)
    raise TimeoutError(f"server at {url} never came up")


def _run_dkg(*, keyper_urls: list[str], keyper_addrs: list[str], election_id: str, election_address: str) -> None:
    url_map = {str(i + 1): keyper_urls[i] for i in range(3)}
    for kid, url in zip([1, 2, 3], keyper_urls):
        assert requests.post(
            f"{url}/dkg/round1",
            json={"n": 3, "t": 1, "keyper_id": kid, "election_id": election_id, "members": keyper_addrs},
            timeout=20,
        ).json().get("status") == "ok"
    for url in keyper_urls:
        assert requests.post(f"{url}/dkg/distribute_commitments", json={"keyper_urls": url_map}, timeout=30).json().get("status") == "ok"
    for url in keyper_urls:
        assert requests.post(f"{url}/dkg/distribute_shares", json={"keyper_urls": url_map}, timeout=30).json().get("status") == "ok"
    for url in keyper_urls:
        assert requests.post(f"{url}/dkg/round2", json={"election_id": election_id}, timeout=30).json().get("verified")
    for url in keyper_urls:
        r = requests.post(f"{url}/dkg/publish_on_chain", json={"election_address": election_address, "n": 3}, timeout=30).json()
        assert "error" not in r, r


@pytest.mark.parametrize(
    ("num_votes", "num_candidates"),
    [
        (25, 3),
        (25, 5),
    ],
)
def test_onchain_tally_perf_smoke(num_votes: int, num_candidates: int) -> None:
    anvil = start_anvil(port=_free_port(), log_path="/tmp/anvil-tally-perf.log")
    try:
        admin_key = ANVIL_KEYS[0]
        tally_key = ANVIL_KEYS[1]
        proxy_key = ANVIL_KEYS[2]
        keyper_keys = list(ANVIL_KEYS[3:6])
        keyper_addrs = [anvil_address(k) for k in keyper_keys]

        chain = EthChain.connect(anvil.rpc_url, private_key=admin_key)
        ks = deploy_keyper_set(rpc_url=anvil.rpc_url, deployer_key=admin_key, members=keyper_addrs, threshold=2)
        reg = deploy_registry(rpc_url=anvil.rpc_url, deployer_key=admin_key, admin=anvil_address(admin_key))

        wr_sk_int = int.from_bytes(b"WR-perf" + b"\x00" * 25, "big") + 1
        _, wr_vk = schnorr_keygen(wr_sk_int)
        wr_pk = g1_to_compressed(wr_vk)
        wr_port = _free_port()
        _serve(create_wr_oracle_app(private_key=wr_sk_int), wr_port)
        wr_url = f"http://127.0.0.1:{wr_port}"
        _wait_http(f"{wr_url}/status")

        now = int(chain.w3.eth.get_block("latest")["timestamp"])
        voting_end = now + 25
        election_address = publish_election(
            chain=chain,
            registry_address=reg,
            keyper_set_address=ks,
            voting_start=now - 60,
            voting_end=voting_end,
            num_candidates=num_candidates,
            budget=1,
            self_submit_fee=0,
            pk_wr=wr_pk,
            tally_aggregator=anvil_address(tally_key),
            vote_proxy=anvil_address(proxy_key),
        )
        election = ElectionClient(chain, election_address)

        keyper_ports = [_free_port(), _free_port(), _free_port()]
        keyper_urls = [f"http://127.0.0.1:{p}" for p in keyper_ports]
        for kid, port, key in zip([1, 2, 3], keyper_ports, keyper_keys):
            _serve(create_keyper_app(kid, chain_config={"rpc_url": anvil.rpc_url, "private_key": key}), port)
        proxy_port = _free_port()
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        _serve(create_vote_proxy_app(rpc_url=anvil.rpc_url, private_key=proxy_key, default_election_address=election_address), proxy_port)
        for url in keyper_urls:
            _wait_http(f"{url}/status")
        _wait_http(f"{proxy_url}/status")

        eid = f"perf-{election_address[2:10]}"
        _run_dkg(keyper_urls=keyper_urls, keyper_addrs=keyper_addrs, election_id=eid, election_address=election_address)
        assert election.is_dkg_finalized()

        expected = [0] * num_candidates
        # Deterministic pattern: cycle through candidates.
        for i in range(num_votes):
            c = i % num_candidates
            vec = [0] * num_candidates
            vec[c] = 1
            expected[c] += 1
            assert cast_vote_via_proxy(proxy_url, anvil.rpc_url, election_address, vec, wr_url=wr_url)

        chain.w3.provider.make_request("anvil_setNextBlockTimestamp", [voting_end + 1])
        chain.w3.provider.make_request("anvil_mine", [1])

        signer = Account.from_key(tally_key)
        t0 = time.perf_counter()
        tally_aggregator.aggregate(chain, election_address, signer)
        t_agg = time.perf_counter() - t0

        for url in keyper_urls:
            r = requests.post(f"{url}/decrypt/publish_on_chain", json={"election_address": election_address}, timeout=60).json()
            assert "error" not in r, r

        t1 = time.perf_counter()
        fin = tally_aggregator.finalize(chain, election_address, signer)
        t_fin = time.perf_counter() - t1

        assert fin.totals == expected
        assert election.get_result()["tally"] == expected

        # Print timings for operator visibility (pytest will capture unless -s).
        print(
            f"aggregate_seconds={t_agg:.3f} finalize_seconds={t_fin:.3f} "
            f"ballots={num_votes} candidates={num_candidates}"
        )
    finally:
        stop_anvil(anvil)
