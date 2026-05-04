#!/usr/bin/env python3
"""
Voter CLI — Encrypts votes client-side and submits them.

Two paths are supported:

  * **Vote proxy + chain** (production-shaped): voter reads election
    parameters from the on-chain ``Election`` contract, encrypts ballots
    locally against ``mpk``, and POSTs a contract-shaped ``Ballot`` to
    the dev ``vote_proxy.py`` server. The proxy holds
    ``VOTE_PROXY_ROLE`` and forwards the call to ``submitVote``.

  * **Legacy backend** (off-chain path, kept for the existing tests):
    voter POSTs encrypted ciphertexts + range/budget proofs to the
    backend's ``/election/vote`` endpoint.

Per PLAN.md decision C, the voter currently sends fixed-size **dummy**
bytes for ``vk``, ``voterSignature``, ``wrAttestation``, and ``zkProof``.
Real Schnorr signing + ballot-validity-proof encoding are tracked in
TODO.md.

Usage (chain path):
    python voter.py params --rpc-url http://127.0.0.1:8545 --election 0x...
    python voter.py vote   --proxy   http://127.0.0.1:5400 \\
                           --rpc-url http://127.0.0.1:8545 \\
                           --election 0x... --choice 2
    python voter.py result --rpc-url http://127.0.0.1:8545 --election 0x...

Usage (legacy backend path):
    python voter.py params --backend http://127.0.0.1:5000
    python voter.py vote   --backend http://127.0.0.1:5000 --votes 0,0,1
    python voter.py result --backend http://127.0.0.1:5000
"""

import argparse
import secrets
import sys

import requests

from crypto.elgamal import aggregate_ciphertexts, encrypt
from crypto.primitives import (
    CURVE_ORDER,
    dict_to_point,
    g2_from_compressed,
    g2_to_compressed,
    point_to_dict,
)
from crypto.proofs import prove_exact_budget, prove_range
import sdk_compat


# ----------------------------------------------------------------------
#  Helpers shared by both paths
# ----------------------------------------------------------------------

def _validate_vote_vector(vote_vector, num_candidates, B):
    if len(vote_vector) != num_candidates:
        raise ValueError(f"Expected {num_candidates} vote values, got {len(vote_vector)}")
    if sum(vote_vector) != B:
        raise ValueError(f"Vote values must sum to {B} (exact budget), got {sum(vote_vector)}")
    for j, v in enumerate(vote_vector):
        if v < 0 or v > B:
            raise ValueError(f"Vote for candidate {j} = {v} not in [0, {B}]")


def _encrypt_ballot(mpk, vote_vector):
    """Encrypt each component; return ``(ciphertexts, randomness)``."""
    ciphertexts = []
    randomness = []
    for v in vote_vector:
        C1, C2, r = encrypt(mpk, v)
        ciphertexts.append((C1, C2))
        randomness.append(r)
    return ciphertexts, randomness


# ----------------------------------------------------------------------
#  Chain + vote-proxy path
# ----------------------------------------------------------------------

def _read_election_from_chain(rpc_url, election_address):
    from eth_client import ElectionClient, EthChain  # lazy: web3 not always installed
    chain = EthChain.connect(rpc_url)
    election = ElectionClient(chain, election_address)
    info = election.get_election()
    if not info["dkg"]["pkElection"]:
        raise RuntimeError("On-chain DKG has not been finalized yet")
    return {
        "election": election,
        "election_id": info["config"]["electionId"],
        "num_candidates": info["config"]["numCandidates"],
        "budget": info["config"]["budget"],
        "mpk": g2_from_compressed(info["dkg"]["pkElection"]),
        "pk_wr": bytes(info["config"]["pkWR"]),
        "phase": election.get_phase(),
    }


def _fetch_wr_attestation(wr_url: str, election_id: bytes, pseudonym: bytes,
                          vk_bytes: bytes) -> bytes:
    """Ask the dev WR oracle for an attestation over (electionId, pseudonym, vk)."""
    resp = requests.post(
        f"{wr_url}/attest",
        json={
            "electionId": election_id.hex(),
            "pseudonym": pseudonym.hex(),
            "vk": vk_bytes.hex(),
        },
        timeout=10,
    )
    resp.raise_for_status()
    return bytes.fromhex(resp.json()["attestation"])


def cast_vote_via_proxy(proxy_url, rpc_url, election_address, vote_vector,
                        *, pseudonym=None, wr_url: str | None = None):
    """Encrypt locally, build a real ballot, POST to ``vote_proxy``.

    Real bytes everywhere — Schnorr-signed Variant-A / exact ballot, with a
    WR attestation fetched from ``wr_url`` (or fixed-bytes if no WR oracle
    is configured, which the backend will reject). See PLAN.md decision C.
    """
    cfg = _read_election_from_chain(rpc_url, election_address)
    mpk = cfg["mpk"]
    num_cand = cfg["num_candidates"]
    B = cfg["budget"]
    election_id_int = cfg["election_id"]
    _validate_vote_vector(vote_vector, num_cand, B)

    if pseudonym is None:
        pseudonym = secrets.token_bytes(32)
    elif len(pseudonym) != 32:
        raise ValueError(f"pseudonym must be 32 bytes, got {len(pseudonym)}")

    election_id_bytes = sdk_compat.election_id_to_bytes32(election_id_int)
    sk, vk = sdk_compat.schnorr_keygen()
    vk_bytes = sdk_compat.g1_to_compressed(vk)

    # Fetch WR attestation. In production the WR-Server returns this only
    # to authenticated voters. Here the dev oracle returns one to anyone.
    if wr_url:
        wr_attestation = _fetch_wr_attestation(wr_url, election_id_bytes, pseudonym, vk_bytes)
    else:
        wr_attestation = b""   # backend will reject unless its verifier is permissive

    result = sdk_compat.build_ballot(
        mpk=mpk,
        election_id=election_id_bytes,
        pseudonym=pseudonym,
        sk=sk, vk=vk,
        votes=list(vote_vector),
        num_candidates=num_cand,
        budget=B,
    )

    ballot = {
        "pseudonym": result.pseudonym.hex(),
        "vk": result.vk.hex(),
        "ciphertexts": [
            {"c1": c1.hex(), "c2": c2.hex()} for (c1, c2) in result.ciphertexts
        ],
        "zkProof": result.zk_proof.hex(),
        "voterSignature": result.voter_signature.hex(),
        "wrAttestation": wr_attestation.hex(),
    }

    resp = requests.post(
        f"{proxy_url}/vote",
        json={"election_address": election_address, "ballot": ballot},
        timeout=60,
    )
    body = resp.json()
    if resp.status_code == 200 and "error" not in body:
        print(f"Vote accepted: ballot #{body.get('ballot_index')} "
              f"(tx {body.get('tx_hash', '')[:14]}…)")
        return True
    print(f"Vote rejected: {body.get('error', f'HTTP {resp.status_code}')}")
    return False


def show_params_chain(rpc_url, election_address):
    cfg = _read_election_from_chain(rpc_url, election_address)
    print(f"Election:        {election_address}")
    print(f"Election ID:     {cfg['election_id']}")
    print(f"Phase:           {cfg['phase']}  [0=preDKG  2=dkgFinalized  3=voting  4=closed]")
    print(f"Candidates:      {cfg['num_candidates']}")
    print(f"Budget:          {cfg['budget']}")
    print(f"DKG mpk:         on chain (96B compressed G2)")


def show_result_chain(rpc_url, election_address):
    from eth_client import ElectionClient, EthChain
    chain = EthChain.connect(rpc_url)
    election = ElectionClient(chain, election_address)
    if not election.is_result_finalized():
        print("No result published yet.")
        return
    res = election.get_result()
    print(f"Total tally vector: {res['tally']}")
    print(f"Used keyper member-indices: {res['keyperIndices']}")


# ----------------------------------------------------------------------
#  Legacy backend path (used by the off-chain test suite until step 11)
# ----------------------------------------------------------------------

def get_election_params(backend_url):
    resp = requests.get(f"{backend_url}/election/params", timeout=10)
    resp.raise_for_status()
    return resp.json()


def cast_vote_via_backend(backend_url, vote_vector):
    params = get_election_params(backend_url)
    if params["phase"] != "voting":
        print(f"Error: Election is in phase '{params['phase']}', not accepting votes.")
        return False

    mpk = dict_to_point(params["mpk"])
    num_cand = params["num_candidates"]
    B = params["budget"]
    election_id = params.get("election_id", "")
    _validate_vote_vector(vote_vector, num_cand, B)

    ciphertexts, randomness = _encrypt_ballot(mpk, vote_vector)
    range_proofs = [
        prove_range(mpk, ct[0], ct[1], v, r, B, election_id=election_id)
        for ct, v, r in zip(ciphertexts, vote_vector, randomness)
    ]
    sum_ct = aggregate_ciphertexts(ciphertexts)
    r_sum = sum(randomness) % CURVE_ORDER
    budget_proof = prove_exact_budget(mpk, sum_ct[0], sum_ct[1], B, r_sum, election_id=election_id)

    payload = {
        "ciphertexts": [
            {"c1": point_to_dict(ct[0]), "c2": point_to_dict(ct[1])} for ct in ciphertexts
        ],
        "range_proofs": [
            [{"e": str(e), "z": str(z)} for (e, z) in proof] for proof in range_proofs
        ],
        "budget_proof": {"e": str(budget_proof[0]), "z": str(budget_proof[1])},
    }
    resp = requests.post(f"{backend_url}/election/vote", json=payload, timeout=30)
    result = resp.json()
    if resp.status_code == 200 and result.get("status") == "ok":
        print(f"Vote accepted: {result.get('message', '')}")
        return True
    print(f"Vote rejected: {result.get('error', 'Unknown error')}")
    return False


def show_params_backend(backend_url):
    params = get_election_params(backend_url)
    print(f"Phase:          {params['phase']}")
    print(f"Curve:          {params.get('curve', 'BLS12-381')}")
    print(f"Group:          {params.get('group', 'G2')}")
    print(f"Candidates:     {params['num_candidates']}")
    for i, name in enumerate(params.get("candidate_names", [])):
        print(f"  [{i}] {name}")
    print(f"Budget:         {params['budget']}")
    print(f"Keypers:        {params['n']} (threshold t={params['t']}, need {params['t']+1} for decryption)")
    print(f"Public key set: {'yes' if params.get('mpk') else 'no'}")


def show_result_backend(backend_url):
    resp = requests.get(f"{backend_url}/election/result", timeout=10)
    if resp.status_code == 404:
        print("No results available yet.")
        return
    resp.raise_for_status()
    data = resp.json()
    print(f"Phase:         {data['phase']}")
    print(f"Total ballots: {data['total_ballots']}")
    print("Results:")
    for name, count in data["results"].items():
        print(f"  {name}: {count}")


def show_status_backend(backend_url):
    resp = requests.get(f"{backend_url}/election/status", timeout=10)
    resp.raise_for_status()
    data = resp.json()
    print(f"Phase:           {data['phase']}")
    print(f"Candidates:      {data['num_candidates']}")
    print(f"Budget:          {data['budget']}")
    print(f"Ballots:         {data['ballots_received']}")
    print(f"Has result:      {data['has_result']}")


# ----------------------------------------------------------------------
#  CLI
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Voter CLI for threshold ElGamal voting")

    # Mutually exclusive at logic level: either (--proxy + --rpc-url + --election)
    # for chain mode, or --backend for legacy mode. We allow both flags so each
    # subcommand can decide.
    parser.add_argument("--proxy", default=None, help="Vote proxy URL (chain mode)")
    parser.add_argument("--rpc-url", default=None, help="Ethereum RPC URL (chain mode)")
    parser.add_argument("--election", default=None, help="Election address (chain mode)")
    parser.add_argument("--wr", default=None, help="WR oracle URL (chain mode)")
    parser.add_argument("--backend", default=None, help="Off-chain backend URL (legacy mode)")
    sub = parser.add_subparsers(dest="command", help="Command to run")

    sub.add_parser("params", help="Show election parameters")

    vote_p = sub.add_parser("vote", help="Cast a vote")
    vote_g = vote_p.add_mutually_exclusive_group(required=True)
    vote_g.add_argument("--choice", type=int, help="Single-choice: candidate index (0-based)")
    vote_g.add_argument("--votes", type=str, help="Budget vote: comma-separated values per candidate")

    sub.add_parser("result", help="Show election result")
    sub.add_parser("status", help="Show election status (legacy backend only)")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        return

    chain_mode = bool(args.proxy or args.rpc_url or args.election)
    backend_mode = bool(args.backend)
    if chain_mode and backend_mode:
        parser.error("Pass either chain flags (--proxy / --rpc-url / --election) OR --backend, not both")
    if not chain_mode and not backend_mode:
        # Default to legacy backend if nothing specified, for backwards compatibility.
        args.backend = "http://127.0.0.1:5000"
        backend_mode = True

    try:
        if args.command == "params":
            if chain_mode:
                if not (args.rpc_url and args.election):
                    parser.error("Chain mode requires --rpc-url and --election")
                show_params_chain(args.rpc_url, args.election)
            else:
                show_params_backend(args.backend)

        elif args.command == "vote":
            # Resolve config to validate the vote vector before submitting.
            if chain_mode:
                if not (args.proxy and args.rpc_url and args.election):
                    parser.error("Chain vote requires --proxy, --rpc-url, and --election")
                cfg = _read_election_from_chain(args.rpc_url, args.election)
                num_cand, B = cfg["num_candidates"], cfg["budget"]
            else:
                params = get_election_params(args.backend)
                num_cand, B = params["num_candidates"], params["budget"]

            if args.choice is not None:
                if args.choice < 0 or args.choice >= num_cand:
                    print(f"Error: --choice must be 0..{num_cand - 1}")
                    sys.exit(1)
                if B != 1:
                    print(f"Error: --choice only works with budget=1, current budget={B}")
                    sys.exit(1)
                vote_vector = [0] * num_cand
                vote_vector[args.choice] = 1
            else:
                vote_vector = [int(x.strip()) for x in args.votes.split(",")]

            ok = (
                cast_vote_via_proxy(args.proxy, args.rpc_url, args.election, vote_vector,
                                    wr_url=args.wr)
                if chain_mode else
                cast_vote_via_backend(args.backend, vote_vector)
            )
            if not ok:
                sys.exit(1)

        elif args.command == "result":
            if chain_mode:
                if not (args.rpc_url and args.election):
                    parser.error("Chain mode requires --rpc-url and --election")
                show_result_chain(args.rpc_url, args.election)
            else:
                show_result_backend(args.backend)

        elif args.command == "status":
            if chain_mode:
                # On-chain status equivalent.
                show_params_chain(args.rpc_url, args.election)
            else:
                show_status_backend(args.backend)

    except requests.exceptions.ConnectionError as e:
        print(f"Connection error: {e}")
        sys.exit(1)
    except (ValueError, RuntimeError) as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
