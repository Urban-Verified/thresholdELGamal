"""Re-vote deduplication: LATEST VALID ballot per pseudonym wins.

The contract permits re-votes -- `submitVote` appends a record and repoints
`ballotIndexPlusOneByPseudonym` at the newest -- so one pseudonym can own
several ballots. Counting them all counts that voter more than once.

The selected rule is *latest valid*: walk a pseudonym's ballots newest to
oldest and count the first that verifies. This same rule must hold in
voting-dashboard's generated verify-aggregate.js, or an independent auditor
selects a different ballot and computes a different aggregate.
"""
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from tests.test_e2e_onchain import _bring_up_election, session_chain  # noqa: F401,E402
from voter import cast_vote_via_proxy  # noqa: E402
import sdk_compat  # noqa: E402


def _cast_with_corrupt_proof(dep, sc, pseudonym: bytes, votes: list[int]) -> None:
    """Submit a structurally valid ballot whose zkProof bytes are garbage.

    The contract only length-checks, so this lands on chain and is recovered
    from logs with a matching commitment (the contract hashes whatever it was
    given) -- it fails only at `verify_ballot`. That is exactly the shape a
    spoiled final submission takes.
    """
    cfg = dep.election.get_election()["config"]
    mpk_bytes = dep.election.get_election()["dkg"]["pkElection"]
    from crypto.primitives import g2_from_compressed
    sk, vk = sdk_compat.schnorr_keygen()
    election_id_bytes = sdk_compat.election_id_to_bytes32(cfg["electionId"])
    built = sdk_compat.build_ballot(
        mpk=g2_from_compressed(mpk_bytes), election_id=election_id_bytes,
        pseudonym=pseudonym, sk=sk, vk=vk, votes=votes,
        num_candidates=cfg["numCandidates"], budget=cfg["budget"],
    )
    att = requests.post(
        f"{sc.wr_url}/attest",
        json={"electionId": election_id_bytes.hex(), "pseudonym": pseudonym.hex(),
              "vk": built.vk.hex()},
        timeout=10,
    ).json()["attestation"]

    corrupt = bytes([built.zk_proof[0] ^ 0xFF]) + built.zk_proof[1:]
    ballot = {
        "pseudonym": built.pseudonym.hex(),
        "vk": built.vk.hex(),
        "ciphertexts": [{"c1": c1.hex(), "c2": c2.hex()} for (c1, c2) in built.ciphertexts],
        "zkProof": corrupt.hex(),
        "voterSignature": built.voter_signature.hex(),
        "wrAttestation": att,
    }
    r = requests.post(f"{dep.proxy_url}/vote",
                      json={"election_address": dep.election_address, "ballot": ballot},
                      timeout=60).json()
    assert "error" not in r, r


def test_revote_counts_only_the_latest(session_chain) -> None:
    """Two valid ballots from one pseudonym: only the newer is counted."""
    dep = _bring_up_election(session_chain, num_candidates=3, budget=1)
    dep.run_dkg()

    ps = secrets.token_bytes(32)
    assert cast_vote_via_proxy(dep.proxy_url, session_chain.rpc_url, dep.election_address,
                               [1, 0, 0], pseudonym=ps, wr_url=session_chain.wr_url)
    assert cast_vote_via_proxy(dep.proxy_url, session_chain.rpc_url, dep.election_address,
                               [0, 1, 0], pseudonym=ps, wr_url=session_chain.wr_url)
    assert dep.election.get_num_ballots() == 2

    dep.fast_forward_to_voting_end()
    agg = dep.aggregate()
    assert agg.ballots_total == 2
    assert agg.ballots_admitted == 1, "one voter must contribute one ballot"
    assert agg.voters_counted == 1
    assert agg.ballots_superseded == 1
    assert agg.superseded[0]["ballot_index"] == 0
    assert agg.superseded[0]["superseded_by"] == 1

    dep.request_decryption_shares()
    fin = dep.finalize()
    assert fin.totals == [0, 1, 0], f"latest ballot must win, got {fin.totals}"


def test_revote_falls_back_when_the_latest_is_invalid(session_chain) -> None:
    """Latest-valid, not latest-by-index.

    A voter's final submission is spoiled. Under latest-by-index they would be
    disenfranchised; under latest-valid their earlier good ballot counts.
    """
    dep = _bring_up_election(session_chain, num_candidates=3, budget=1)
    dep.run_dkg()

    ps = secrets.token_bytes(32)
    assert cast_vote_via_proxy(dep.proxy_url, session_chain.rpc_url, dep.election_address,
                               [1, 0, 0], pseudonym=ps, wr_url=session_chain.wr_url)
    _cast_with_corrupt_proof(dep, session_chain, ps, [0, 0, 1])
    assert dep.election.get_num_ballots() == 2

    dep.fast_forward_to_voting_end()
    agg = dep.aggregate()
    assert agg.ballots_admitted == 1
    assert agg.ballots_rejected == 1, "the spoiled newer ballot is tried and rejected"
    assert agg.rejections[0]["ballot_index"] == 1

    dep.request_decryption_shares()
    fin = dep.finalize()
    assert fin.totals == [1, 0, 0], f"older valid ballot must count, got {fin.totals}"


def test_distinct_pseudonyms_are_untouched(session_chain) -> None:
    """No re-votes: dedup must be a no-op."""
    dep = _bring_up_election(session_chain, num_candidates=3, budget=1)
    dep.run_dkg()
    for v in ([1, 0, 0], [0, 1, 0], [1, 0, 0]):
        assert cast_vote_via_proxy(dep.proxy_url, session_chain.rpc_url,
                                   dep.election_address, v, wr_url=session_chain.wr_url)
    dep.fast_forward_to_voting_end()
    agg = dep.aggregate()
    assert agg.ballots_admitted == 3
    assert agg.ballots_superseded == 0
    dep.request_decryption_shares()
    assert dep.finalize().totals == [2, 1, 0]
