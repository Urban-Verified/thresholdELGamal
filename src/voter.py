#!/usr/bin/env python3
"""
Voter CLI — Encrypts votes client-side and submits them to the election backend.

All cryptographic operations (encryption, ZK proof generation) happen locally
using BLS12-381 G2. The backend never sees plaintext votes.

Usage:
    # Get election parameters
    python voter.py params --backend http://127.0.0.1:5000

    # Cast a single-choice vote (pick candidate index)
    python voter.py vote --backend http://127.0.0.1:5000 --choice 2

    # Cast a budget vote (distribute points among candidates)
    python voter.py vote --backend http://127.0.0.1:5000 --votes 3,1,0,2

    # Check election result
    python voter.py result --backend http://127.0.0.1:5000
"""

import argparse
import json
import sys
import requests

from crypto.primitives import CURVE_ORDER, dict_to_point, point_to_dict
from crypto.elgamal import encrypt, aggregate_ciphertexts
from crypto.proofs import prove_range, prove_exact_budget


def get_election_params(backend_url):
    """Fetch election parameters from the backend."""
    resp = requests.get(f"{backend_url}/election/params", timeout=10)
    resp.raise_for_status()
    return resp.json()


def cast_vote(backend_url, vote_vector):
    """Encrypt a vote vector and submit it with ZK proofs.

    vote_vector: list of integers, one per candidate, each in [0, B], summing to B.
    """
    params = get_election_params(backend_url)

    if params["phase"] != "voting":
        print(f"Error: Election is in phase '{params['phase']}', not accepting votes.")
        return False

    mpk = dict_to_point(params["mpk"])
    num_candidates = params["num_candidates"]
    B = params["budget"]
    candidate_names = params["candidate_names"]
    election_id = params.get("election_id", "")

    if len(vote_vector) != num_candidates:
        print(f"Error: Expected {num_candidates} vote values, got {len(vote_vector)}")
        return False

    total = sum(vote_vector)
    if total != B:
        print(f"Error: Vote values must sum to {B} (exact budget), got {total}")
        return False

    for j, v in enumerate(vote_vector):
        if v < 0 or v > B:
            print(f"Error: Vote for candidate {j} ({candidate_names[j]}) = {v} not in [0, {B}]")
            return False

    # --- Client-side encryption ---
    ciphertexts = []
    randomness = []
    for j in range(num_candidates):
        C1, C2, r = encrypt(mpk, vote_vector[j])
        ciphertexts.append((C1, C2))
        randomness.append(r)

    # --- Generate range proofs ---
    range_proofs = []
    for j in range(num_candidates):
        C1, C2 = ciphertexts[j]
        proof = prove_range(mpk, C1, C2, vote_vector[j], randomness[j], B, election_id=election_id)
        range_proofs.append(proof)

    # --- Generate budget proof ---
    sum_ct = aggregate_ciphertexts(ciphertexts)
    r_sum = sum(randomness) % CURVE_ORDER
    budget_proof = prove_exact_budget(mpk, sum_ct[0], sum_ct[1], B, r_sum, election_id=election_id)

    # --- Serialize and submit ---
    payload = {
        "ciphertexts": [
            {"c1": point_to_dict(ct[0]), "c2": point_to_dict(ct[1])} for ct in ciphertexts
        ],
        "range_proofs": [
            [{"e": str(e), "z": str(z)} for (e, z) in proof]
            for proof in range_proofs
        ],
        "budget_proof": {"e": str(budget_proof[0]), "z": str(budget_proof[1])},
    }

    resp = requests.post(f"{backend_url}/election/vote", json=payload, timeout=30)
    result = resp.json()

    if resp.status_code == 200 and result.get("status") == "ok":
        print(f"Vote accepted: {result.get('message', '')}")
        return True
    else:
        print(f"Vote rejected: {result.get('error', 'Unknown error')}")
        return False


def show_params(backend_url):
    """Display current election parameters."""
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


def show_result(backend_url):
    """Display election results."""
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


def show_status(backend_url):
    """Display election status."""
    resp = requests.get(f"{backend_url}/election/status", timeout=10)
    resp.raise_for_status()
    data = resp.json()
    print(f"Phase:           {data['phase']}")
    print(f"Candidates:      {data['num_candidates']}")
    print(f"Budget:          {data['budget']}")
    print(f"Ballots:         {data['ballots_received']}")
    print(f"Has result:      {data['has_result']}")


def main():
    parser = argparse.ArgumentParser(description="Voter CLI for threshold ElGamal voting")
    parser.add_argument("--backend", default="http://127.0.0.1:5000",
                        help="Backend server URL")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # params command
    subparsers.add_parser("params", help="Show election parameters")

    # vote command
    vote_parser = subparsers.add_parser("vote", help="Cast a vote")
    vote_group = vote_parser.add_mutually_exclusive_group(required=True)
    vote_group.add_argument("--choice", type=int,
                            help="Single-choice: candidate index (0-based)")
    vote_group.add_argument("--votes", type=str,
                            help="Budget vote: comma-separated values per candidate")

    # result command
    subparsers.add_parser("result", help="Show election result")

    # status command
    subparsers.add_parser("status", help="Show election status")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    try:
        if args.command == "params":
            show_params(args.backend)

        elif args.command == "vote":
            params = get_election_params(args.backend)
            num_cand = params["num_candidates"]
            B = params["budget"]

            if args.choice is not None:
                if args.choice < 0 or args.choice >= num_cand:
                    print(f"Error: Choice must be 0..{num_cand - 1}")
                    sys.exit(1)
                if B != 1:
                    print(f"Error: --choice only works with budget=1, current budget={B}")
                    sys.exit(1)
                vote_vector = [0] * num_cand
                vote_vector[args.choice] = 1
            else:
                vote_vector = [int(x.strip()) for x in args.votes.split(",")]

            if not cast_vote(args.backend, vote_vector):
                sys.exit(1)

        elif args.command == "result":
            show_result(args.backend)

        elif args.command == "status":
            show_status(args.backend)

    except requests.exceptions.ConnectionError:
        print(f"Error: Cannot connect to backend at {args.backend}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
