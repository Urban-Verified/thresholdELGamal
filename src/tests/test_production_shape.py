"""Full lifecycle at the production election shape, on anvil.

10 candidates / budget 10 is the shape that could not be submitted at all
before the ballot-storage migration -- submitVote cost 22.3M gas against a
17M block limit. This drives the whole pipeline at those parameters:
deploy -> DKG -> ballots -> aggregate -> decryption shares -> publishResult.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_e2e_onchain import _bring_up_election, session_chain  # noqa: F401,E402
from voter import cast_vote_via_proxy  # noqa: E402
from eth_utils import keccak  # noqa: E402

BLOCK_GAS_LIMIT = 17_000_000  # Gnosis + Chiado


def test_full_lifecycle_at_production_shape(session_chain) -> None:
    dep = _bring_up_election(session_chain, num_candidates=10, budget=10)
    dep.run_dkg()

    votes = [
        [10, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 5, 5, 0, 0, 0, 0, 0, 0, 0],
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
    ]
    expected = [11, 6, 6, 1, 1, 1, 1, 1, 1, 1]

    for v in votes:
        assert cast_vote_via_proxy(
            dep.proxy_url, session_chain.rpc_url, dep.election_address, v,
            wr_url=session_chain.wr_url,
        )
    assert dep.election.get_num_ballots() == 3

    # proofs are recoverable from logs and bound to their commitments
    ballots = dep.election.get_all_ballots_with_proofs()
    assert len(ballots) == 3
    for b in ballots:
        assert len(b["zkProof"]) == 28249, "proof size at 10 candidates / budget 10"
        assert keccak(b["zkProof"]) == b["zkProofHash"]

    dep.fast_forward_to_voting_end()
    dep.aggregate()
    dep.request_decryption_shares()
    fin = dep.finalize()

    assert fin.totals == expected, f"tally {fin.totals} != {expected}"
    assert dep.election.get_result()["tally"] == expected
    print(f"\n@@ tally at 10 candidates / budget 10: {fin.totals}")
