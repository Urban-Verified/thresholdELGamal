#!/usr/bin/env python3
"""
Stress test: 10 candidates, budget=10, 10000 randomized votes.
Starts servers in-process, submits votes, tallies, and verifies correctness.
"""

import random
import threading
import time
import sys
import os
import logging
import requests

logging.getLogger("werkzeug").setLevel(logging.ERROR)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keyper import create_keyper_app
from backend import create_backend_app
from bulletin_board import create_bb_app
from crypto.primitives import CURVE_ORDER, point_to_dict, dict_to_point
from crypto.elgamal import encrypt, aggregate_ciphertexts
from crypto.proofs import prove_range, prove_exact_budget

NUM_CANDIDATES = 10
BUDGET = 10
NUM_VOTES = 100
N_KEYPERS = 3
THRESHOLD = 1  # need t+1 = 2 for decryption

BACKEND_PORT = 9000
KEYPER_BASE_PORT = 9001
BB_PORT = 9099


def start_flask(app, port):
    t = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False),
        daemon=True,
    )
    t.start()
    return t


def wait_for(url, retries=40, delay=0.25):
    for _ in range(retries):
        try:
            requests.get(url, timeout=1)
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(delay)
    return False


def random_vote_vector(num_candidates, budget):
    """Generate a random vote vector summing to exactly budget."""
    vec = [0] * num_candidates
    for _ in range(budget):
        vec[random.randint(0, num_candidates - 1)] += 1
    return vec


def submit_vote(backend_url, vote_vector, election_id, mpk, B):
    """Encrypt + prove + submit a single vote. Returns response JSON."""
    num_candidates = len(vote_vector)

    ciphertexts = []
    randomnesses = []
    for v in vote_vector:
        C1, C2, r = encrypt(mpk, v)
        ciphertexts.append((C1, C2))
        randomnesses.append(r)

    range_proofs = []
    for j in range(num_candidates):
        proof = prove_range(mpk, ciphertexts[j][0], ciphertexts[j][1],
                            vote_vector[j], randomnesses[j], B, election_id=election_id)
        range_proofs.append(proof)

    agg = aggregate_ciphertexts(ciphertexts)
    r_sum = sum(randomnesses) % CURVE_ORDER
    budget_proof = prove_exact_budget(mpk, agg[0], agg[1], B, r_sum, election_id=election_id)

    payload = {
        "ciphertexts": [
            {"c1": point_to_dict(ct[0]), "c2": point_to_dict(ct[1])}
            for ct in ciphertexts
        ],
        "range_proofs": [
            [{"e": str(e), "z": str(z)} for (e, z) in proof]
            for proof in range_proofs
        ],
        "budget_proof": {"e": str(budget_proof[0]), "z": str(budget_proof[1])},
    }

    resp = requests.post(f"{backend_url}/election/vote", json=payload, timeout=60)
    return resp.json()


def main():
    random.seed(42)  # reproducible
    backend_url = f"http://127.0.0.1:{BACKEND_PORT}"
    bb_url = f"http://127.0.0.1:{BB_PORT}"

    # --- Start servers ---
    print(f"Starting {N_KEYPERS} keypers, bulletin board, and backend...")
    bb_app = create_bb_app()
    start_flask(bb_app, BB_PORT)

    keyper_urls = []
    for i in range(N_KEYPERS):
        port = KEYPER_BASE_PORT + i
        app = create_keyper_app(i + 1)
        start_flask(app, port)
        keyper_urls.append(f"http://127.0.0.1:{port}")

    backend_app = create_backend_app(keyper_urls, bb_url)
    start_flask(backend_app, BACKEND_PORT)

    assert wait_for(f"{bb_url}/bb/status"), "Bulletin board not ready"
    for url in keyper_urls:
        assert wait_for(f"{url}/status"), f"Keyper {url} not ready"
    assert wait_for(f"{backend_url}/election/status"), "Backend not ready"
    print("All servers ready.")

    # --- Create election ---
    candidate_names = [f"Candidate_{i}" for i in range(NUM_CANDIDATES)]
    resp = requests.post(f"{backend_url}/election/create", json={
        "n": N_KEYPERS, "t": THRESHOLD,
        "num_candidates": NUM_CANDIDATES, "budget": BUDGET,
        "candidate_names": candidate_names,
    }, timeout=30)
    assert resp.status_code == 200, f"Create failed: {resp.text}"
    print(f"Election created: {NUM_CANDIDATES} candidates, B={BUDGET}")

    # --- DKG ---
    print("Running DKG...", end=" ", flush=True)
    t0 = time.time()
    resp = requests.post(f"{backend_url}/election/dkg", timeout=300)
    assert resp.status_code == 200, f"DKG failed: {resp.text}"
    print(f"done in {time.time()-t0:.1f}s")

    # Fetch params once for all votes
    params = requests.get(f"{backend_url}/election/params", timeout=5).json()
    mpk = dict_to_point(params["mpk"])
    election_id = params.get("election_id", "")

    # --- Generate all random votes and track expected tally ---
    print(f"Generating {NUM_VOTES} random vote vectors...")
    expected_tally = [0] * NUM_CANDIDATES
    vote_vectors = []
    for _ in range(NUM_VOTES):
        vec = random_vote_vector(NUM_CANDIDATES, BUDGET)
        vote_vectors.append(vec)
        for j in range(NUM_CANDIDATES):
            expected_tally[j] += vec[j]

    print(f"Expected tally: {expected_tally}")
    print(f"Expected total:  {sum(expected_tally)} (should be {NUM_VOTES * BUDGET})")

    # --- Submit votes ---
    print(f"Submitting {NUM_VOTES} votes...", flush=True)
    t0 = time.time()
    accepted = 0
    rejected = 0
    for i, vec in enumerate(vote_vectors):
        t_vote = time.time()
        result = submit_vote(backend_url, vec, election_id, mpk, BUDGET)
        vote_dur = time.time() - t_vote
        if result.get("status") == "ok":
            accepted += 1
        else:
            rejected += 1
            print(f"  Vote {i} REJECTED: {result.get('error', '?')}", flush=True)

        elapsed = time.time() - t0
        rate = (i + 1) / elapsed
        eta = (NUM_VOTES - i - 1) / rate if rate > 0 else 0
        print(f"  [{i+1}/{NUM_VOTES}] {vote_dur:.1f}s this vote | {rate:.2f} votes/s avg | ETA {eta:.0f}s", flush=True)

    vote_time = time.time() - t0
    print(f"Voting done: {accepted} accepted, {rejected} rejected in {vote_time:.1f}s "
          f"({accepted/vote_time:.1f} votes/s)")

    if rejected > 0:
        print(f"ERROR: {rejected} votes rejected!")
        sys.exit(1)

    # --- Tally ---
    print("Running tally (homomorphic aggregation + threshold decryption)...", end=" ", flush=True)
    t0 = time.time()
    resp = requests.post(f"{backend_url}/election/tally", timeout=600)
    tally_time = time.time() - t0
    assert resp.status_code == 200, f"Tally failed: {resp.text}"
    results = resp.json()["results"]
    print(f"done in {tally_time:.1f}s")

    # --- Verify ---
    print(f"\n{'Candidate':<15} {'Expected':>8} {'Got':>8} {'Match':>6}")
    print("-" * 40)
    all_match = True
    for j in range(NUM_CANDIDATES):
        name = candidate_names[j]
        exp = expected_tally[j]
        got = results[name]
        match = "OK" if got == exp else "FAIL"
        if got != exp:
            all_match = False
        print(f"{name:<15} {exp:>8} {got:>8} {match:>6}")

    print("-" * 40)
    if all_match:
        print(f"ALL CORRECT — {NUM_VOTES} votes, {NUM_CANDIDATES} candidates, B={BUDGET}")
        print(f"Timings: DKG={resp.elapsed.total_seconds() if hasattr(resp, 'elapsed') else '?'}s, "
              f"Voting={vote_time:.1f}s, Tally={tally_time:.1f}s")
    else:
        print("MISMATCH DETECTED — tally does not match expected values!")
        sys.exit(1)


if __name__ == "__main__":
    main()
