"""
End-to-end test for the on-chain integration.

Drives the full Munich-shaped lifecycle against a live anvil node and the
production contracts at https://github.com/Urban-Verified/bulletin-board:

    publishElection
    → DKG (Feldman VSS via signed P2P keyper-to-keyper messages)
    → voteDKGResult per keyper
    → submitVote per ballot via vote_proxy.py
    → publishAggregate via tally_aggregator.aggregate (TALLY_AGGREGATOR_ROLE)
    → submitDecryptionShare per keyper (SDK transcript via sdk_compat)
    → publishResult via tally_aggregator.finalize
    → assert getResult().tally == expected counts

Anvil is started once per pytest session; each test gets fresh contracts,
fresh Flask servers, and fresh DKG state on distinct OS-allocated ports
(to avoid the port-collision flakiness that already plagues the legacy
off-chain Flask tests).
"""

from __future__ import annotations

import logging
import os
import socket
import sys
import threading
import time
from dataclasses import dataclass

import pytest
import requests

logging.getLogger("werkzeug").setLevel(logging.ERROR)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eth_account import Account  # noqa: E402
from eth_utils import keccak  # noqa: E402

from chain_setup import (  # noqa: E402
    ANVIL_KEYS,
    anvil_address,
    deploy_keyper_set,
    deploy_registry,
    publish_election,
    start_anvil,
    stop_anvil,
)
from eth_client import BallotProofError, ElectionClient, EthChain  # noqa: E402
from keyper import create_keyper_app  # noqa: E402
from vote_proxy import create_vote_proxy_app  # noqa: E402
from voter import cast_vote_via_proxy  # noqa: E402
from wr_oracle import create_wr_oracle_app  # noqa: E402
from sdk_compat import schnorr_keygen  # noqa: E402
from crypto.primitives import g1_to_compressed  # noqa: E402
import tally_aggregator  # noqa: E402
from tally_aggregator import TallyAggregatorError  # noqa: E402


# ---------------------------------------------------------------------------
#  Port allocation
# ---------------------------------------------------------------------------

def _free_port() -> int:
    """Ask the OS for an unused TCP port. Avoids hard-coded port collisions
    between tests (each test needs ~6 ports for WR + keypers + proxy).
    """
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


def _wait_http(url: str, retries: int = 50, delay: float = 0.05) -> None:
    for _ in range(retries):
        try:
            requests.get(url, timeout=0.5)
            return
        except requests.exceptions.ConnectionError:
            time.sleep(delay)
    raise TimeoutError(f"server at {url} never came up")


# ---------------------------------------------------------------------------
#  Session: one anvil + KeyperSet + Registry shared across tests
# ---------------------------------------------------------------------------

@dataclass
class _SessionChain:
    rpc_url: str
    chain: EthChain
    admin_key: str
    admin: str
    tally_key: str
    tally: str
    proxy_key: str
    proxy_addr: str
    keyper_keys: list[str]
    keyper_addrs: list[str]
    keyper_set: str
    registry: str
    # WR oracle (dev-mode Wahlregister stub) — Schnorr keypair on G1.
    wr_sk: int
    wr_pk: bytes              # 48-byte compressed G1
    wr_url: str               # http://127.0.0.1:<port>/


@pytest.fixture(scope="session")
def session_chain():
    """Boot anvil and deploy KeyperSet + ElectionRegistry once for the
    whole pytest session.
    """
    anvil = start_anvil(port=_free_port(), log_path="/tmp/anvil-pytest.log")
    try:
        admin_key = ANVIL_KEYS[0]
        tally_key = ANVIL_KEYS[1]
        proxy_key = ANVIL_KEYS[2]
        keyper_keys = list(ANVIL_KEYS[3:6])
        keyper_addrs = [anvil_address(k) for k in keyper_keys]

        chain = EthChain.connect(anvil.rpc_url, private_key=admin_key)
        ks = deploy_keyper_set(
            rpc_url=anvil.rpc_url, deployer_key=admin_key,
            members=keyper_addrs, threshold=2,
        )
        reg = deploy_registry(
            rpc_url=anvil.rpc_url, deployer_key=admin_key,
            admin=anvil_address(admin_key),
        )

        # Spin up a single WR oracle for the whole session. Deterministic
        # keypair so the resulting pkWR is stable across runs.
        wr_sk_int = int.from_bytes(b"WR-pytest" + b"\x00" * 23, "big") + 1
        _, wr_vk = schnorr_keygen(wr_sk_int)
        wr_pk = g1_to_compressed(wr_vk)
        wr_port = _free_port()
        _serve(create_wr_oracle_app(private_key=wr_sk_int), wr_port)
        wr_url = f"http://127.0.0.1:{wr_port}"
        _wait_http(f"{wr_url}/status")

        yield _SessionChain(
            rpc_url=anvil.rpc_url, chain=chain,
            admin_key=admin_key, admin=anvil_address(admin_key),
            tally_key=tally_key, tally=anvil_address(tally_key),
            proxy_key=proxy_key, proxy_addr=anvil_address(proxy_key),
            keyper_keys=keyper_keys, keyper_addrs=keyper_addrs,
            keyper_set=ks, registry=reg,
            wr_sk=wr_sk_int, wr_pk=wr_pk, wr_url=wr_url,
        )
    finally:
        stop_anvil(anvil)


# ---------------------------------------------------------------------------
#  Per-test deployment: fresh Election + fresh Flask servers
# ---------------------------------------------------------------------------

@dataclass
class _OnChainDeployment:
    sc: _SessionChain
    election_address: str
    election: ElectionClient
    keyper_urls: list[str]
    keyper_addrs: list[str]
    proxy_url: str
    voting_end: int
    election_id_str: str

    def tally_signer(self):
        return Account.from_key(self.sc.tally_key)

    def aggregate(self):
        return tally_aggregator.aggregate(
            self.sc.chain, self.election_address, self.tally_signer(),
        )

    def finalize(self):
        return tally_aggregator.finalize(
            self.sc.chain, self.election_address, self.tally_signer(),
        )

    def run_dkg(self) -> None:
        url_map = {str(i + 1): self.keyper_urls[i] for i in range(len(self.keyper_urls))}
        for kid, url in zip([1, 2, 3], self.keyper_urls):
            r = requests.post(
                f"{url}/dkg/round1",
                json={
                    "n": 3, "t": 1, "keyper_id": kid,
                    "election_id": self.election_id_str,
                    "members": self.keyper_addrs,
                },
                timeout=10,
            ).json()
            assert r.get("status") == "ok", r
        for url in self.keyper_urls:
            r = requests.post(
                f"{url}/dkg/distribute_commitments",
                json={"keyper_urls": url_map},
                timeout=10,
            ).json()
            assert r.get("status") == "ok", r
        for url in self.keyper_urls:
            r = requests.post(
                f"{url}/dkg/distribute_shares",
                json={"keyper_urls": url_map},
                timeout=10,
            ).json()
            assert r.get("status") == "ok", r
        for url in self.keyper_urls:
            r = requests.post(
                f"{url}/dkg/round2",
                json={"election_id": self.election_id_str},
                timeout=10,
            ).json()
            assert r.get("verified"), r
        for url in self.keyper_urls:
            r = requests.post(
                f"{url}/dkg/publish_on_chain",
                json={"election_address": self.election_address, "n": 3},
                timeout=30,
            ).json()
            assert "error" not in r, r
        assert self.election.is_dkg_finalized()

    def fast_forward_to_voting_end(self) -> None:
        self.sc.chain.w3.provider.make_request(
            "anvil_setNextBlockTimestamp", [self.voting_end + 1],
        )
        self.sc.chain.w3.provider.make_request("anvil_mine", [1])

    def request_decryption_shares(self) -> None:
        for url in self.keyper_urls:
            r = requests.post(
                f"{url}/decrypt/publish_on_chain",
                json={"election_address": self.election_address},
                timeout=30,
            ).json()
            assert "error" not in r, r


def _bring_up_election(sc: _SessionChain, *, num_candidates: int, budget: int,
                       voting_window_secs: int = 30,
                       self_submit_fee: int = 0,
                       voting_start_offset_secs: int = -60) -> _OnChainDeployment:
    # Use chain time, not wall-clock — earlier tests in the session may have
    # fast-forwarded the chain past now() to enable publishAggregate.
    now = int(sc.chain.w3.eth.get_block("latest")["timestamp"])
    voting_start = now + voting_start_offset_secs
    voting_end = now + voting_window_secs
    election_address = publish_election(
        chain=sc.chain, registry_address=sc.registry, keyper_set_address=sc.keyper_set,
        voting_start=voting_start, voting_end=voting_end,
        num_candidates=num_candidates, budget=budget, self_submit_fee=self_submit_fee,
        pk_wr=sc.wr_pk,
        tally_aggregator=sc.tally, vote_proxy=sc.proxy_addr,
    )

    keyper_ports = [_free_port(), _free_port(), _free_port()]
    keyper_urls = [f"http://127.0.0.1:{p}" for p in keyper_ports]
    keyper_addrs = [anvil_address(k) for k in sc.keyper_keys]
    for kid, port, key in zip([1, 2, 3], keyper_ports, sc.keyper_keys):
        _serve(
            create_keyper_app(kid, chain_config={"rpc_url": sc.rpc_url, "private_key": key}),
            port,
        )

    proxy_port = _free_port()
    proxy_url = f"http://127.0.0.1:{proxy_port}"
    _serve(
        create_vote_proxy_app(
            rpc_url=sc.rpc_url, private_key=sc.proxy_key,
            default_election_address=election_address,
        ),
        proxy_port,
    )

    # Wait for everything to be reachable.
    for url in keyper_urls:
        _wait_http(f"{url}/status")
    _wait_http(f"{proxy_url}/status")

    return _OnChainDeployment(
        sc=sc,
        election_address=election_address,
        election=ElectionClient(sc.chain, election_address),
        keyper_urls=keyper_urls,
        keyper_addrs=keyper_addrs,
        proxy_url=proxy_url,
        voting_end=voting_end,
        election_id_str=f"test-{election_address[2:10]}",
    )


# ---------------------------------------------------------------------------
#  Tests
# ---------------------------------------------------------------------------

def test_full_onchain_lifecycle_single_choice(session_chain: _SessionChain) -> None:
    """3 candidates, budget=1, 5 ballots → totals match expected."""
    dep = _bring_up_election(session_chain, num_candidates=3, budget=1)
    dep.run_dkg()

    votes = [
        [1, 0, 0], [1, 0, 0], [1, 0, 0],
        [0, 1, 0],
        [0, 0, 1],
    ]
    expected = [3, 1, 1]

    for v in votes:
        assert cast_vote_via_proxy(
            dep.proxy_url, session_chain.rpc_url, dep.election_address, v,
            wr_url=session_chain.wr_url,
        )
    assert dep.election.get_num_ballots() == len(votes)

    dep.fast_forward_to_voting_end()

    agg = dep.aggregate()
    assert agg.ballots_total == len(votes)
    assert agg.ballots_admitted == len(votes)
    assert agg.ballots_rejected == 0

    dep.request_decryption_shares()
    assert len(dep.election.get_decryption_shares()) == 3

    # Idempotency: each keyper should skip on second submission.
    for url in dep.keyper_urls:
        r = requests.post(
            f"{url}/decrypt/publish_on_chain",
            json={"election_address": dep.election_address},
            timeout=30,
        ).json()
        assert r.get("skipped") == "already_submitted", r
        assert r.get("tx_hash") is None, r

    fin = dep.finalize()
    assert fin.totals == expected

    assert dep.election.is_result_finalized()
    assert dep.election.get_result()["tally"] == expected


def test_full_onchain_lifecycle_budget_election(session_chain: _SessionChain) -> None:
    """4 candidates, budget=2 (multi-vote ballots) → totals match expected."""
    dep = _bring_up_election(session_chain, num_candidates=4, budget=2)
    dep.run_dkg()

    # 4 voters, each spends budget=2 across 4 candidates.
    votes = [
        [2, 0, 0, 0],
        [1, 1, 0, 0],
        [0, 0, 2, 0],
        [0, 1, 0, 1],
    ]
    expected = [3, 2, 2, 1]

    for v in votes:
        assert cast_vote_via_proxy(
            dep.proxy_url, session_chain.rpc_url, dep.election_address, v,
            wr_url=session_chain.wr_url,
        )

    dep.fast_forward_to_voting_end()
    dep.aggregate()
    dep.request_decryption_shares()

    fin = dep.finalize()
    assert fin.totals == expected
    assert dep.election.get_result()["tally"] == expected


def test_late_keyper_dkg_vote_no_ops(session_chain: _SessionChain) -> None:
    """Once the threshold-many keypers have submitted voteDKGResult, a third
    keyper's submission must be a graceful skip (the contract reverts with
    AlreadyFinalized; the keyper handler maps that to a structured response
    rather than an error).
    """
    dep = _bring_up_election(session_chain, num_candidates=3, budget=1)
    # Run DKG round-1 → P2P fan-out → round-2 manually so we can drive
    # the on-chain submission ordering for this test.
    url_map = {str(i + 1): dep.keyper_urls[i] for i in range(3)}
    for kid, url in zip([1, 2, 3], dep.keyper_urls):
        r = requests.post(
            f"{url}/dkg/round1",
            json={"n": 3, "t": 1, "keyper_id": kid,
                  "election_id": dep.election_id_str,
                  "members": dep.keyper_addrs},
            timeout=10,
        ).json()
        assert r.get("status") == "ok", r
    for url in dep.keyper_urls:
        requests.post(
            f"{url}/dkg/distribute_commitments",
            json={"keyper_urls": url_map}, timeout=10,
        ).json()
    for url in dep.keyper_urls:
        requests.post(
            f"{url}/dkg/distribute_shares",
            json={"keyper_urls": url_map}, timeout=10,
        ).json()
    for url in dep.keyper_urls:
        assert requests.post(
            f"{url}/dkg/round2",
            json={"election_id": dep.election_id_str},
            timeout=10,
        ).json().get("verified")

    # Threshold is 2 of 3. Submit from k1 and k2; k3 must skip.
    r1 = requests.post(
        f"{dep.keyper_urls[0]}/dkg/publish_on_chain",
        json={"election_address": dep.election_address, "n": 3}, timeout=30,
    ).json()
    r2 = requests.post(
        f"{dep.keyper_urls[1]}/dkg/publish_on_chain",
        json={"election_address": dep.election_address, "n": 3}, timeout=30,
    ).json()
    r3 = requests.post(
        f"{dep.keyper_urls[2]}/dkg/publish_on_chain",
        json={"election_address": dep.election_address, "n": 3}, timeout=30,
    ).json()

    assert r1.get("tx_hash"), r1
    assert r2.get("tx_hash"), r2
    assert r2.get("dkg_finalized") is True
    assert r3.get("tx_hash") is None
    assert r3.get("skipped") == "dkg_already_finalized"


def test_dleq_proofs_match_sdk_transcript(session_chain: _SessionChain) -> None:
    """Each on-chain decryption-share proof must verify under the SDK
    transcript shape we ship in sdk_compat (cross-impl interoperability).
    """
    from sdk_compat import (
        make_onchain_decrypt_transcript,
        verify_decryption_share,
    )
    from crypto.primitives import g2_from_compressed

    dep = _bring_up_election(session_chain, num_candidates=2, budget=1)
    dep.run_dkg()

    for v in ([1, 0], [0, 1], [1, 0]):
        assert cast_vote_via_proxy(
            dep.proxy_url, session_chain.rpc_url, dep.election_address, v,
            wr_url=session_chain.wr_url,
        )

    dep.fast_forward_to_voting_end()
    dep.aggregate()
    dep.request_decryption_shares()

    info = dep.election.get_election()
    eid = info["config"]["electionId"]
    committee_pks = [g2_from_compressed(p) for p in info["dkg"]["committeePKs"]]
    aggregate = dep.election.get_aggregate()
    agg_pts = [(g2_from_compressed(c[0]), g2_from_compressed(c[1])) for c in aggregate["aggregates"]]

    for share in dep.election.get_decryption_shares():
        k_member = share["keyperIndex"]
        k_dkg = k_member + 1
        for j, (sigma_bytes, (e, z)) in enumerate(zip(share["shares"], share["proofs"])):
            sigma = g2_from_compressed(sigma_bytes)
            t = make_onchain_decrypt_transcript(eid, j)
            assert verify_decryption_share(
                t, agg_pts[j][0], agg_pts[j][1],
                committee_pks[k_member], sigma, e, z,
                keyper_index=k_dkg,
            ), f"DLEQ verify failed: keyper {k_dkg}, candidate {j}"


def test_aggregate_rejects_ballot_with_tampered_wr_attestation(
    session_chain: _SessionChain,
) -> None:
    """A ballot whose WR attestation is mutated post-issuance must:
       1. still pass the contract's length / G2-subgroup checks (so it
          lands on chain), and
       2. be excluded by ``tally_aggregator.aggregate``'s verifier with a
          'wrAttestation' rejection reason — leaving the tally identical
          to what only the valid ballots would have produced.
    """
    import secrets as _secrets
    from voter import _fetch_wr_attestation
    from sdk_compat import (
        build_ballot,
        election_id_to_bytes32,
        schnorr_keygen,
    )
    from crypto.primitives import g1_to_compressed, g2_from_compressed

    dep = _bring_up_election(session_chain, num_candidates=3, budget=1)
    dep.run_dkg()

    # Three valid ballots through the proxy.
    valid_votes = [[1, 0, 0], [0, 1, 0], [1, 0, 0]]
    expected = [2, 1, 0]
    for v in valid_votes:
        assert cast_vote_via_proxy(
            dep.proxy_url, session_chain.rpc_url, dep.election_address, v,
            wr_url=session_chain.wr_url,
        )

    # One malicious ballot: real ZK proof + signature, but the WR
    # attestation has one byte flipped after the oracle issued it.
    info = dep.election.get_election()
    mpk = g2_from_compressed(info["dkg"]["pkElection"])
    eid_bytes = election_id_to_bytes32(info["config"]["electionId"])

    pseudonym = _secrets.token_bytes(32)
    sk, vk = schnorr_keygen()
    vk_bytes = g1_to_compressed(vk)
    real_attest = _fetch_wr_attestation(
        session_chain.wr_url, eid_bytes, pseudonym, vk_bytes,
    )
    tampered = bytearray(real_attest)
    tampered[10] ^= 0xFF

    result = build_ballot(
        mpk=mpk, election_id=eid_bytes, pseudonym=pseudonym,
        sk=sk, vk=vk, votes=[1, 0, 0], num_candidates=3, budget=1,
    )
    bad_payload = {
        "election_address": dep.election_address,
        "ballot": {
            "pseudonym": result.pseudonym.hex(),
            "vk": result.vk.hex(),
            "ciphertexts": [
                {"c1": c1.hex(), "c2": c2.hex()} for (c1, c2) in result.ciphertexts
            ],
            "zkProof": result.zk_proof.hex(),
            "voterSignature": result.voter_signature.hex(),
            "wrAttestation": bytes(tampered).hex(),
        },
    }
    r = requests.post(f"{dep.proxy_url}/vote", json=bad_payload, timeout=30)
    assert r.status_code == 200, r.text
    assert dep.election.get_num_ballots() == len(valid_votes) + 1

    # Aggregate — tally aggregator must admit 3, reject 1 with WR reason.
    dep.fast_forward_to_voting_end()
    agg = dep.aggregate()
    assert agg.ballots_total == 4
    assert agg.ballots_admitted == 3
    assert agg.ballots_rejected == 1
    assert "wrAttestation" in agg.rejections[0]["reason"]

    dep.request_decryption_shares()
    fin = dep.finalize()
    assert fin.totals == expected, (fin.totals, expected)


def test_vote_rejected_after_voting_end(session_chain: _SessionChain) -> None:
    """The contract must reject ballots after ``votingEnd`` (even via the proxy)."""
    dep = _bring_up_election(session_chain, num_candidates=3, budget=1, voting_window_secs=8)
    dep.run_dkg()

    dep.fast_forward_to_voting_end()
    ok = cast_vote_via_proxy(
        dep.proxy_url, session_chain.rpc_url, dep.election_address, [1, 0, 0],
        wr_url=session_chain.wr_url,
    )
    assert ok is False


def test_self_submit_fee_enforced_for_non_proxy_submitter(session_chain: _SessionChain) -> None:
    """A non-proxy submitter must pay ``selfSubmitFee``; the proxy can submit with value=0."""
    from voter import _fetch_wr_attestation
    from sdk_compat import build_ballot, election_id_to_bytes32, schnorr_keygen
    from crypto.primitives import g1_to_compressed, g2_from_compressed

    fee = 123
    dep = _bring_up_election(session_chain, num_candidates=3, budget=1, self_submit_fee=fee)
    dep.run_dkg()

    info = dep.election.get_election()
    mpk = g2_from_compressed(info["dkg"]["pkElection"])
    eid_bytes = election_id_to_bytes32(info["config"]["electionId"])

    pseudonym = os.urandom(32)
    sk, vk = schnorr_keygen()
    vk_bytes = g1_to_compressed(vk)
    wr_attestation = _fetch_wr_attestation(session_chain.wr_url, eid_bytes, pseudonym, vk_bytes)
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
    ballot = {
        "pseudonym": built.pseudonym,
        "vk": built.vk,
        "ciphertexts": built.ciphertexts,
        "zkProof": built.zk_proof,
        "voterSignature": built.voter_signature,
        "wrAttestation": wr_attestation,
    }

    # Admin is not the vote proxy; value=0 must revert.
    admin = Account.from_key(session_chain.admin_key)
    with pytest.raises(Exception):
        dep.election.submit_vote(ballot, signer=admin, value=0)

    # Paying the fee should succeed.
    dep.election.submit_vote(ballot, signer=admin, value=fee)
    assert dep.election.get_num_ballots() == 1


def test_publish_aggregate_requires_tally_aggregator_role(session_chain: _SessionChain) -> None:
    """Only the configured tally aggregator address can call publishAggregate."""
    dep = _bring_up_election(session_chain, num_candidates=3, budget=1, voting_window_secs=12)
    dep.run_dkg()

    assert cast_vote_via_proxy(
        dep.proxy_url, session_chain.rpc_url, dep.election_address, [1, 0, 0],
        wr_url=session_chain.wr_url,
    )
    dep.fast_forward_to_voting_end()

    # Wrong signer (admin) should revert publishAggregate.
    admin = Account.from_key(session_chain.admin_key)
    with pytest.raises(TallyAggregatorError, match="publishAggregate reverted"):
        tally_aggregator.aggregate(session_chain.chain, dep.election_address, admin)


def test_publish_aggregate_rejected_before_voting_end(session_chain: _SessionChain) -> None:
    """Even a valid aggregate may not be published while voting is still open."""
    dep = _bring_up_election(session_chain, num_candidates=3, budget=1, voting_window_secs=20)
    dep.run_dkg()
    assert cast_vote_via_proxy(
        dep.proxy_url, session_chain.rpc_url, dep.election_address, [1, 0, 0],
        wr_url=session_chain.wr_url,
    )

    # Voting is still open; contract should revert VotingStillOpen, which the
    # tally aggregator surfaces as a publishAggregate revert.
    with pytest.raises(TallyAggregatorError, match="publishAggregate reverted"):
        dep.aggregate()


def test_finalize_rejected_with_insufficient_decryption_shares(session_chain: _SessionChain) -> None:
    """Finalize must fail until threshold-many decryption shares exist on chain."""
    dep = _bring_up_election(session_chain, num_candidates=3, budget=1, voting_window_secs=10)
    dep.run_dkg()
    for v in ([1, 0, 0], [0, 1, 0]):
        assert cast_vote_via_proxy(
            dep.proxy_url, session_chain.rpc_url, dep.election_address, v,
            wr_url=session_chain.wr_url,
        )
    dep.fast_forward_to_voting_end()
    dep.aggregate()

    # Threshold is 2-of-3 but only one keyper submits shares.
    r = requests.post(
        f"{dep.keyper_urls[0]}/decrypt/publish_on_chain",
        json={"election_address": dep.election_address},
        timeout=30,
    ).json()
    assert "error" not in r, r

    with pytest.raises(TallyAggregatorError, match="need 2"):
        dep.finalize()


def test_publish_result_requires_tally_aggregator_role(session_chain: _SessionChain) -> None:
    """Only the configured tally aggregator address can call publishResult."""
    dep = _bring_up_election(session_chain, num_candidates=3, budget=1, voting_window_secs=12)
    dep.run_dkg()
    for v in ([1, 0, 0], [0, 1, 0], [1, 0, 0]):
        assert cast_vote_via_proxy(
            dep.proxy_url, session_chain.rpc_url, dep.election_address, v,
            wr_url=session_chain.wr_url,
        )
    dep.fast_forward_to_voting_end()
    dep.aggregate()
    dep.request_decryption_shares()

    admin = Account.from_key(session_chain.admin_key)
    with pytest.raises(TallyAggregatorError, match="publishResult reverted"):
        tally_aggregator.finalize(session_chain.chain, dep.election_address, admin)


def test_submit_vote_rejects_wrong_ciphertext_count(session_chain: _SessionChain) -> None:
    """Contract must reject ballots where ciphertext array length != numCandidates."""
    from voter import _fetch_wr_attestation
    from sdk_compat import build_ballot, election_id_to_bytes32, schnorr_keygen
    from crypto.primitives import g1_to_compressed, g2_from_compressed

    dep = _bring_up_election(session_chain, num_candidates=3, budget=1, voting_window_secs=12)
    dep.run_dkg()

    info = dep.election.get_election()
    mpk = g2_from_compressed(info["dkg"]["pkElection"])
    eid_bytes = election_id_to_bytes32(info["config"]["electionId"])

    pseudonym = os.urandom(32)
    sk, vk = schnorr_keygen()
    vk_bytes = g1_to_compressed(vk)
    wr_attestation = _fetch_wr_attestation(session_chain.wr_url, eid_bytes, pseudonym, vk_bytes)
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

    # Truncate ciphertexts so payload fails the contract's ciphertext-count check.
    bad_ballot = {
        "pseudonym": built.pseudonym,
        "vk": built.vk,
        "ciphertexts": built.ciphertexts[:2],
        "zkProof": built.zk_proof,
        "voterSignature": built.voter_signature,
        "wrAttestation": wr_attestation,
    }

    proxy_signer = Account.from_key(session_chain.proxy_key)
    with pytest.raises(Exception):
        dep.election.submit_vote(bad_ballot, signer=proxy_signer, value=0)


def test_vote_rejected_before_voting_start(session_chain: _SessionChain) -> None:
    """Contract must reject ballots before votingStart (VotingNotStarted)."""
    dep = _bring_up_election(
        session_chain,
        num_candidates=3,
        budget=1,
        voting_window_secs=90,
        voting_start_offset_secs=60,  # start in the future
    )
    dep.run_dkg()

    ok = cast_vote_via_proxy(
        dep.proxy_url, session_chain.rpc_url, dep.election_address, [1, 0, 0],
        wr_url=session_chain.wr_url,
    )
    assert ok is False


def test_finalize_rejected_before_aggregate_published(session_chain: _SessionChain) -> None:
    """Even with shares present, finalize must fail until an aggregate is published."""
    dep = _bring_up_election(session_chain, num_candidates=3, budget=1, voting_window_secs=12)
    dep.run_dkg()

    # No ballots and no aggregate published.
    dep.fast_forward_to_voting_end()

    with pytest.raises(TallyAggregatorError, match="Aggregate not yet published"):
        dep.finalize()


@pytest.mark.parametrize(
    "mutator",
    [
        ("vk_wrong_len",),
        ("empty_zkProof",),
        ("empty_voterSignature",),
        ("empty_wrAttestation",),
        ("ciphertext_wrong_g2_len",),
    ],
)
def test_submit_vote_rejects_invalid_payload_fields(session_chain: _SessionChain, mutator: tuple[str]) -> None:
    """Contract-level payload checks: these should revert with InvalidVotePayload / InvalidG2PointLength."""
    from voter import _fetch_wr_attestation
    from sdk_compat import build_ballot, election_id_to_bytes32, schnorr_keygen
    from crypto.primitives import g1_to_compressed, g2_from_compressed

    dep = _bring_up_election(session_chain, num_candidates=2, budget=1, voting_window_secs=30)
    dep.run_dkg()

    info = dep.election.get_election()
    mpk = g2_from_compressed(info["dkg"]["pkElection"])
    eid_bytes = election_id_to_bytes32(info["config"]["electionId"])

    pseudonym = os.urandom(32)
    sk, vk = schnorr_keygen()
    vk_bytes = g1_to_compressed(vk)
    wr_attestation = _fetch_wr_attestation(session_chain.wr_url, eid_bytes, pseudonym, vk_bytes)
    built = build_ballot(
        mpk=mpk,
        election_id=eid_bytes,
        pseudonym=pseudonym,
        sk=sk,
        vk=vk,
        votes=[1, 0],
        num_candidates=2,
        budget=1,
    )

    ballot = {
        "pseudonym": built.pseudonym,
        "vk": built.vk,
        "ciphertexts": built.ciphertexts,
        "zkProof": built.zk_proof,
        "voterSignature": built.voter_signature,
        "wrAttestation": wr_attestation,
    }

    which = mutator[0]
    if which == "vk_wrong_len":
        ballot["vk"] = ballot["vk"][:-1]
    elif which == "empty_zkProof":
        ballot["zkProof"] = b""
    elif which == "empty_voterSignature":
        ballot["voterSignature"] = b""
    elif which == "empty_wrAttestation":
        ballot["wrAttestation"] = b""
    elif which == "ciphertext_wrong_g2_len":
        c1, c2 = ballot["ciphertexts"][0]
        ballot["ciphertexts"][0] = (c1[:-1], c2)
    else:
        raise AssertionError(which)

    proxy_signer = Account.from_key(session_chain.proxy_key)
    with pytest.raises(Exception):
        dep.election.submit_vote(ballot, signer=proxy_signer, value=0)


def test_ballot_proof_recovered_from_logs_and_bound_to_commitment(
    session_chain: _SessionChain,
) -> None:
    """The proof lives in the VoteSubmitted log, not storage.

    Storage keeps only keccak256(zkProof), so the log is the only source of
    the bytes -- and the commitment is what makes trusting that source safe.
    """
    dep = _bring_up_election(session_chain, num_candidates=3, budget=1)
    dep.run_dkg()
    assert cast_vote_via_proxy(
        dep.proxy_url, session_chain.rpc_url, dep.election_address, [1, 0, 0],
        wr_url=session_chain.wr_url,
    )

    # storage row carries the commitment, not the bytes
    row = dep.election.get_ballots(0, 1)[0]
    assert "zkProof" not in row
    assert len(row["zkProofHash"]) == 32

    # the joined read restores the bytes and they satisfy the commitment
    ballots = dep.election.get_all_ballots_with_proofs()
    assert len(ballots) == 1
    assert len(ballots[0]["zkProof"]) > 0
    assert keccak(ballots[0]["zkProof"]) == ballots[0]["zkProofHash"]


def test_missing_proof_aborts_rather_than_rejecting_the_ballot(
    session_chain: _SessionChain,
) -> None:
    """A proof that cannot be found must abort, never count as a rejection.

    Downgrading it to a rejection would silently drop a valid vote and
    publish a wrong tally -- the failure mode this design exists to avoid.
    """
    dep = _bring_up_election(session_chain, num_candidates=3, budget=1)
    dep.run_dkg()
    assert cast_vote_via_proxy(
        dep.proxy_url, session_chain.rpc_url, dep.election_address, [1, 0, 0],
        wr_url=session_chain.wr_url,
    )

    # scan window starting after the vote finds no log for it
    future = session_chain.chain.w3.eth.block_number + 1_000
    with pytest.raises(BallotProofError, match="no VoteSubmitted log"):
        dep.election.get_all_ballots_with_proofs(from_block=future)


def test_tampered_proof_fails_the_commitment_check(
    session_chain: _SessionChain, monkeypatch,
) -> None:
    """A proof that does not hash to the stored commitment must be rejected."""
    dep = _bring_up_election(session_chain, num_candidates=3, budget=1)
    dep.run_dkg()
    assert cast_vote_via_proxy(
        dep.proxy_url, session_chain.rpc_url, dep.election_address, [1, 0, 0],
        wr_url=session_chain.wr_url,
    )

    original = ElectionClient.get_ballot_proofs

    def tampered(self, ballot_indexes, **kwargs):
        proofs = original(self, ballot_indexes, **kwargs)
        return {
            index: bytes([proof[0] ^ 0xFF]) + proof[1:]
            for index, proof in proofs.items()
        }

    monkeypatch.setattr(ElectionClient, "get_ballot_proofs", tampered)
    with pytest.raises(BallotProofError, match="does not match the on-chain commitment"):
        dep.election.get_all_ballots_with_proofs()
