#!/usr/bin/env python3
"""
Voter CLI — Encrypts votes client-side and submits them.

The canonical path is **Vote proxy + chain** (production-shaped): voter reads election
    parameters from the on-chain ``Election`` contract, encrypts ballots
    locally against ``mpk``, and POSTs a contract-shaped ``Ballot`` to
    the dev ``vote_proxy.py`` server. The proxy holds
    ``VOTE_PROXY_ROLE`` and forwards the call to ``submitVote``.

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
"""

import argparse
import secrets
import sys

import requests

from crypto.elgamal import aggregate_ciphertexts, encrypt
from crypto.primitives import (
    g2_from_compressed,
)
import sdk_compat


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
#  CLI
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Voter CLI for threshold ElGamal voting")

    parser.add_argument("--proxy", default=None, help="Vote proxy URL (chain mode)")
    parser.add_argument("--rpc-url", default=None, help="Ethereum RPC URL (chain mode)")
    parser.add_argument("--election", default=None, help="Election address (chain mode)")
    parser.add_argument("--wr", default=None, help="WR oracle URL (chain mode)")
    sub = parser.add_subparsers(dest="command", help="Command to run")

    sub.add_parser("params", help="Show election parameters")

    vote_p = sub.add_parser("vote", help="Cast a vote")
    vote_g = vote_p.add_mutually_exclusive_group(required=True)
    vote_g.add_argument("--choice", type=int, help="Single-choice: candidate index (0-based)")
    vote_g.add_argument("--votes", type=str, help="Budget vote: comma-separated values per candidate")

    sub.add_parser("result", help="Show election result")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        return

    if not (args.rpc_url and args.election):
        parser.error("--rpc-url and --election are required")

    try:
        if args.command == "params":
            show_params_chain(args.rpc_url, args.election)

        elif args.command == "vote":
            if not args.proxy:
                parser.error("vote requires --proxy")
            cfg = _read_election_from_chain(args.rpc_url, args.election)
            num_cand, B = cfg["num_candidates"], cfg["budget"]

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

            ok = cast_vote_via_proxy(
                args.proxy, args.rpc_url, args.election, vote_vector,
                wr_url=args.wr,
            )
            if not ok:
                sys.exit(1)

        elif args.command == "result":
            show_result_chain(args.rpc_url, args.election)

    except requests.exceptions.ConnectionError as e:
        print(f"Connection error: {e}")
        sys.exit(1)
    except (ValueError, RuntimeError) as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
