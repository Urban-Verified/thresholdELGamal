#!/usr/bin/env python3
"""
Tally-only performance test: encrypt ONE vote, inject it N times directly
into the backend ballot store (no proof generation or server-side verification),
then trigger tally to measure aggregation + threshold decryption time.
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
from crypto.primitives import point_to_dict, dict_to_point
from crypto.elgamal import encrypt

NUM_CANDIDATES = 10
BUDGET = 10
NUM_VOTES = 10000
N_KEYPERS = 3
THRESHOLD = 1

BACKEND_PORT = 9500
KEYPER_BASE_PORT = 9501


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


def main():
    random.seed(42)
    backend_url = f"http://127.0.0.1:{BACKEND_PORT}"

    # --- Start servers ---
    print(f"Starting {N_KEYPERS} keypers and backend...", flush=True)
    keyper_urls = []
    for i in range(N_KEYPERS):
        port = KEYPER_BASE_PORT + i
        app = create_keyper_app(i + 1)
        start_flask(app, port)
        keyper_urls.append(f"http://127.0.0.1:{port}")

    backend_app = create_backend_app(keyper_urls)
    start_flask(backend_app, BACKEND_PORT)

    for url in keyper_urls:
        assert wait_for(f"{url}/status"), f"Keyper {url} not ready"
    assert wait_for(f"{backend_url}/election/status"), "Backend not ready"
    print("All servers ready.", flush=True)

    # --- Create election ---
    candidate_names = [f"Candidate_{i}" for i in range(NUM_CANDIDATES)]
    resp = requests.post(f"{backend_url}/election/create", json={
        "n": N_KEYPERS, "t": THRESHOLD,
        "num_candidates": NUM_CANDIDATES, "budget": BUDGET,
        "candidate_names": candidate_names,
    }, timeout=30)
    assert resp.status_code == 200, f"Create failed: {resp.text}"
    print(f"Election created: {NUM_CANDIDATES} candidates, B={BUDGET}", flush=True)

    # --- DKG ---
    print("Running DKG...", end=" ", flush=True)
    t0 = time.time()
    resp = requests.post(f"{backend_url}/election/dkg", timeout=300)
    assert resp.status_code == 200, f"DKG failed: {resp.text}"
    print(f"done in {time.time()-t0:.1f}s", flush=True)

    # Fetch params
    params = requests.get(f"{backend_url}/election/params", timeout=5).json()
    mpk = dict_to_point(params["mpk"])

    # --- Encrypt ONE vote (no proofs needed) ---
    vote_vector = [0] * NUM_CANDIDATES
    for _ in range(BUDGET):
        vote_vector[random.randint(0, NUM_CANDIDATES - 1)] += 1
    print(f"Vote vector: {vote_vector} (sum={sum(vote_vector)})", flush=True)

    print("Encrypting one vote...", end=" ", flush=True)
    t0 = time.time()
    ciphertexts = []
    for v in vote_vector:
        C1, C2, _r = encrypt(mpk, v)
        ciphertexts.append((C1, C2))
    enc_time = time.time() - t0
    print(f"done in {enc_time:.1f}s", flush=True)

    # --- Inject ballots directly into backend state (skip verification) ---
    state = backend_app._election_state

    print(f"Injecting {NUM_VOTES} identical ballots into backend state...", end=" ", flush=True)
    t0 = time.time()
    with state["lock"]:
        for i in range(NUM_VOTES):
            state["ballots"].append(list(ciphertexts))
    inject_time = time.time() - t0
    print(f"done in {inject_time:.3f}s ({len(state['ballots'])} ballots stored)", flush=True)

    # Expected tally
    expected_tally = [v * NUM_VOTES for v in vote_vector]
    print(f"Expected tally: {expected_tally}", flush=True)

    # --- Tally ---
    print(f"\nRunning tally ({NUM_VOTES} ballots × {NUM_CANDIDATES} candidates)...", flush=True)
    t0 = time.time()
    resp = requests.post(f"{backend_url}/election/tally", timeout=1800)
    tally_time = time.time() - t0
    assert resp.status_code == 200, f"Tally failed: {resp.text}"
    results = resp.json()["results"]
    print(f"Tally done in {tally_time:.1f}s", flush=True)

    # --- Verify ---
    print(f"\n{'Candidate':<15} {'Expected':>8} {'Got':>8} {'Match':>6}")
    print("-" * 40)
    all_match = True
    for j in range(NUM_CANDIDATES):
        name = candidate_names[j]
        exp = expected_tally[j]
        got = results[name]
        ok = "OK" if got == exp else "FAIL"
        if got != exp:
            all_match = False
        print(f"{name:<15} {exp:>8} {got:>8} {ok:>6}")

    print("-" * 40)
    print(f"\nTimings:")
    print(f"  Encryption (1 vote, {NUM_CANDIDATES} candidates): {enc_time:.1f}s")
    print(f"  Ballot injection ({NUM_VOTES} votes):       {inject_time:.3f}s")
    print(f"  Tally + decryption:                  {tally_time:.1f}s")

    if all_match:
        print(f"\nALL CORRECT — {NUM_VOTES} ballots, {NUM_CANDIDATES} candidates, B={BUDGET}")
    else:
        print("\nMISMATCH DETECTED!")
        sys.exit(1)


if __name__ == "__main__":
    main()
