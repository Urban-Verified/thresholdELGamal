"""
On-chain stress smoke test.

Exercises: publishElection → keyper DKG → vote proxy submissions → aggregate →
keyper decryption shares → finalize → assert tally.

We keep NUM_VOTES moderate to avoid tx-throughput flakiness.
"""

from __future__ import annotations

import logging
import os
import random
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
from voter import cast_vote_via_proxy, _fetch_wr_attestation  # noqa: E402
from wr_oracle import create_wr_oracle_app  # noqa: E402
from sdk_compat import schnorr_keygen  # noqa: E402
from crypto.primitives import g1_to_compressed, g2_from_compressed  # noqa: E402
from sdk_compat import build_ballot, election_id_to_bytes32  # noqa: E402
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
        r = requests.post(
            f"{url}/dkg/round1",
            json={"n": 3, "t": 1, "keyper_id": kid, "election_id": election_id, "members": keyper_addrs},
            timeout=20,
        ).json()
        assert r.get("status") == "ok", r
    for url in keyper_urls:
        assert requests.post(
            f"{url}/dkg/distribute_commitments", json={"keyper_urls": url_map}, timeout=30,
        ).json().get("status") == "ok"
    for url in keyper_urls:
        assert requests.post(
            f"{url}/dkg/distribute_shares", json={"keyper_urls": url_map}, timeout=30,
        ).json().get("status") == "ok"
    for url in keyper_urls:
        assert requests.post(
            f"{url}/dkg/round2", json={"election_id": election_id}, timeout=30,
        ).json().get("verified")
    for url in keyper_urls:
        r = requests.post(
            f"{url}/dkg/publish_on_chain", json={"election_address": election_address, "n": 3}, timeout=30,
        ).json()
        assert "error" not in r, r


@pytest.mark.parametrize("num_votes", [30])
def test_onchain_stress_smoke(num_votes: int) -> None:
    random.seed(42)
    anvil = start_anvil(port=_free_port(), log_path="/tmp/anvil-stress.log")
    try:
        admin_key = ANVIL_KEYS[0]
        tally_key = ANVIL_KEYS[1]
        proxy_key = ANVIL_KEYS[2]
        keyper_keys = list(ANVIL_KEYS[3:6])
        keyper_addrs = [anvil_address(k) for k in keyper_keys]

        chain = EthChain.connect(anvil.rpc_url, private_key=admin_key)
        ks = deploy_keyper_set(rpc_url=anvil.rpc_url, deployer_key=admin_key, members=keyper_addrs, threshold=2)
        reg = deploy_registry(rpc_url=anvil.rpc_url, deployer_key=admin_key, admin=anvil_address(admin_key))

        # WR oracle (deterministic)
        wr_sk_int = int.from_bytes(b"WR-stress" + b"\x00" * 24, "big") + 1
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
            num_candidates=3,
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

        eid = f"stress-{election_address[2:10]}"
        _run_dkg(keyper_urls=keyper_urls, keyper_addrs=keyper_addrs, election_id=eid, election_address=election_address)
        assert election.is_dkg_finalized()

        expected = [0, 0, 0]
        for _ in range(num_votes):
            choice = random.randint(0, 2)
            vec = [0, 0, 0]
            vec[choice] = 1
            expected[choice] += 1
            assert cast_vote_via_proxy(proxy_url, anvil.rpc_url, election_address, vec, wr_url=wr_url)
        assert election.get_num_ballots() == num_votes

        # Submit one additional ballot that is structurally valid but has a
        # tampered WR attestation. Contract accepts (length checks), but the
        # tally aggregator must reject it during aggregate verification.
        info = election.get_election()
        mpk = g2_from_compressed(info["dkg"]["pkElection"])
        eid_bytes = election_id_to_bytes32(info["config"]["electionId"])
        pseudonym = os.urandom(32)
        sk, vk = schnorr_keygen()
        vk_bytes = g1_to_compressed(vk)
        attest = _fetch_wr_attestation(wr_url, eid_bytes, pseudonym, vk_bytes)
        tampered = bytearray(attest)
        tampered[0] ^= 0x01
        built = build_ballot(
            mpk=mpk,
            election_id=eid_bytes,
            pseudonym=pseudonym,
            sk=sk,
            vk=vk,
            votes=[1, 0, 0],
            num_candidates=3,
            budget=1,
        )
        bad_payload = {
            "election_address": election_address,
            "ballot": {
                "pseudonym": built.pseudonym.hex(),
                "vk": built.vk.hex(),
                "ciphertexts": [{"c1": c1.hex(), "c2": c2.hex()} for (c1, c2) in built.ciphertexts],
                "zkProof": built.zk_proof.hex(),
                "voterSignature": built.voter_signature.hex(),
                "wrAttestation": bytes(tampered).hex(),
            },
        }
        r = requests.post(f"{proxy_url}/vote", json=bad_payload, timeout=30)
        assert r.status_code == 200, r.text
        assert election.get_num_ballots() == num_votes + 1

        chain.w3.provider.make_request("anvil_setNextBlockTimestamp", [voting_end + 1])
        chain.w3.provider.make_request("anvil_mine", [1])

        signer = Account.from_key(tally_key)
        agg = tally_aggregator.aggregate(chain, election_address, signer)
        assert agg.ballots_total == num_votes + 1
        assert agg.ballots_admitted == num_votes
        assert agg.ballots_rejected == 1
        assert "wrAttestation" in agg.rejections[0]["reason"]
        for url in keyper_urls:
            r = requests.post(f"{url}/decrypt/publish_on_chain", json={"election_address": election_address}, timeout=60).json()
            assert "error" not in r, r

        fin = tally_aggregator.finalize(chain, election_address, signer)
        assert fin.totals == expected
        assert election.get_result()["tally"] == expected
    finally:
        stop_anvil(anvil)
