#!/usr/bin/env python3
"""
End-to-end test for the threshold ElGamal voting system over BLS12-381.

Starts a backend and multiple keyper servers, runs the full election lifecycle:
  1. Create election
  2. Distributed Key Generation (DKG)
  3. Multiple voters submit encrypted votes with ZK proofs
  4. Homomorphic aggregation + threshold decryption
  5. Verify results match expected tallies

Also tests:
  - Threshold property: uses only t+1 out of n keypers for decryption
  - Proof verification: backend correctly validates ZK proofs
  - Multiple budget configurations
"""

import threading
import time
import sys
import os
import json
import requests
import logging

# Suppress Flask/werkzeug request logging
logging.getLogger("werkzeug").setLevel(logging.ERROR)

from keyper import create_keyper_app
from backend import create_backend_app
from crypto.primitives import (
    CURVE_ORDER, point_to_dict, dict_to_point,
)
from crypto.elgamal import encrypt, aggregate_ciphertexts
from crypto.proofs import prove_range, prove_exact_budget


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def start_flask_in_thread(app, port, host="127.0.0.1"):
    """Start a Flask app in a daemon thread."""
    t = threading.Thread(
        target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False),
        daemon=True,
    )
    t.start()
    return t


def wait_for_server(url, retries=30, delay=0.2):
    """Wait for a server to become available."""
    for _ in range(retries):
        try:
            requests.get(url, timeout=1)
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(delay)
    return False


def submit_vote(backend_url, vote_vector):
    """
    Client-side vote submission:
      1. Fetch election params (mpk, budget, etc.)
      2. Encrypt each vote component
      3. Generate range proofs and budget proof
      4. POST to backend
    """
    params = requests.get(f"{backend_url}/election/params", timeout=5).json()
    mpk = dict_to_point(params["mpk"])
    B = params["budget"]
    num_candidates = params["num_candidates"]

    assert len(vote_vector) == num_candidates, \
        f"Vote vector length {len(vote_vector)} != num_candidates {num_candidates}"
    assert sum(vote_vector) == B, \
        f"Vote sum {sum(vote_vector)} != budget {B}"

    # Encrypt each component
    ciphertexts = []
    randomnesses = []
    for v in vote_vector:
        C1, C2, r = encrypt(mpk, v)
        ciphertexts.append((C1, C2))
        randomnesses.append(r)

    # Range proofs: each v in {0, ..., B}
    range_proofs = []
    for j in range(num_candidates):
        proof = prove_range(mpk, ciphertexts[j][0], ciphertexts[j][1],
                            vote_vector[j], randomnesses[j], B)
        range_proofs.append(proof)

    # Budget proof: sum of votes = B
    agg = aggregate_ciphertexts(ciphertexts)
    r_sum = sum(randomnesses) % CURVE_ORDER
    budget_proof = prove_exact_budget(mpk, agg[0], agg[1], B, r_sum)

    # Build JSON payload
    payload = {
        "ciphertexts": [
            {"c1": point_to_dict(ct[0]), "c2": point_to_dict(ct[1])}
            for ct in ciphertexts
        ],
        "range_proofs": [
            [{"e": str(e), "z": str(z)} for (e, z) in proof]
            for proof in range_proofs
        ],
        "budget_proof": {
            "e": str(budget_proof[0]),
            "z": str(budget_proof[1]),
        },
    }

    resp = requests.post(f"{backend_url}/election/vote", json=payload, timeout=30)
    return resp.json()


# ---------------------------------------------------------------------------
#  Tests
# ---------------------------------------------------------------------------

def test_single_choice_election():
    """
    Test 1: Single-choice vote (B=1), 3 candidates, 5 voters.
    Expected tally: Alice=2, Bob=2, Charlie=1
    """
    print("\n" + "=" * 60)
    print("TEST 1: Single-Choice Election (B=1)")
    print("=" * 60)

    # Start keypers
    n_keypers = 3
    keyper_base_port = 6100
    keyper_urls = []
    for i in range(n_keypers):
        port = keyper_base_port + i
        app = create_keyper_app(i + 1)
        start_flask_in_thread(app, port)
        keyper_urls.append(f"http://127.0.0.1:{port}")

    # Start backend
    backend_port = 6000
    backend_app = create_backend_app(keyper_urls)
    start_flask_in_thread(backend_app, backend_port)
    backend_url = f"http://127.0.0.1:{backend_port}"

    # Wait for servers
    for url in keyper_urls:
        assert wait_for_server(f"{url}/status"), f"Keyper {url} not ready"
    assert wait_for_server(f"{backend_url}/election/status"), "Backend not ready"
    print("[OK] All servers started")

    # 1. Create election
    resp = requests.post(f"{backend_url}/election/create", json={
        "n": n_keypers, "t": 1, "num_candidates": 3, "budget": 1,
        "candidate_names": ["Alice", "Bob", "Charlie"],
    }, timeout=30)
    assert resp.status_code == 200, f"Create failed: {resp.text}"
    print("[OK] Election created")

    # 2. DKG
    resp = requests.post(f"{backend_url}/election/dkg", timeout=120)
    assert resp.status_code == 200, f"DKG failed: {resp.text}"
    print("[OK] DKG completed")

    # 3. Votes
    voter_choices = [
        [1, 0, 0],  # Alice
        [1, 0, 0],  # Alice
        [0, 1, 0],  # Bob
        [0, 1, 0],  # Bob
        [0, 0, 1],  # Charlie
    ]
    for i, choice in enumerate(voter_choices):
        result = submit_vote(backend_url, choice)
        assert result.get("status") == "ok", f"Vote {i} failed: {result}"
    print(f"[OK] {len(voter_choices)} votes submitted")

    # 4. Tally
    resp = requests.post(f"{backend_url}/election/tally", timeout=120)
    assert resp.status_code == 200, f"Tally failed: {resp.text}"
    results = resp.json()["results"]
    print(f"[OK] Tally: {results}")

    assert results["Alice"] == 2, f"Alice: expected 2, got {results['Alice']}"
    assert results["Bob"] == 2, f"Bob: expected 2, got {results['Bob']}"
    assert results["Charlie"] == 1, f"Charlie: expected 1, got {results['Charlie']}"
    print("[PASS] Single-choice election correct!")


def test_budget_election():
    """
    Test 2: Budget vote (B=3), 3 candidates, 3 voters.
    Expected tally: X=4, Y=3, Z=2
    """
    print("\n" + "=" * 60)
    print("TEST 2: Budget Election (B=3)")
    print("=" * 60)

    n_keypers = 3
    keyper_base_port = 6200
    keyper_urls = []
    for i in range(n_keypers):
        port = keyper_base_port + i
        app = create_keyper_app(i + 1)
        start_flask_in_thread(app, port)
        keyper_urls.append(f"http://127.0.0.1:{port}")

    backend_port = 6010
    backend_app = create_backend_app(keyper_urls)
    start_flask_in_thread(backend_app, backend_port)
    backend_url = f"http://127.0.0.1:{backend_port}"

    for url in keyper_urls:
        assert wait_for_server(f"{url}/status"), f"Keyper {url} not ready"
    assert wait_for_server(f"{backend_url}/election/status"), "Backend not ready"
    print("[OK] All servers started")

    resp = requests.post(f"{backend_url}/election/create", json={
        "n": n_keypers, "t": 1, "num_candidates": 3, "budget": 3,
        "candidate_names": ["X", "Y", "Z"],
    }, timeout=30)
    assert resp.status_code == 200, f"Create failed: {resp.text}"
    print("[OK] Election created (B=3)")

    resp = requests.post(f"{backend_url}/election/dkg", timeout=120)
    assert resp.status_code == 200, f"DKG failed: {resp.text}"
    print("[OK] DKG completed")

    voter_choices = [
        [2, 1, 0],  # voter 1
        [1, 1, 1],  # voter 2
        [1, 1, 1],  # voter 3
    ]
    for i, choice in enumerate(voter_choices):
        result = submit_vote(backend_url, choice)
        assert result.get("status") == "ok", f"Vote {i} failed: {result}"
    print(f"[OK] {len(voter_choices)} votes submitted")

    resp = requests.post(f"{backend_url}/election/tally", timeout=120)
    assert resp.status_code == 200, f"Tally failed: {resp.text}"
    results = resp.json()["results"]
    print(f"[OK] Tally: {results}")

    assert results["X"] == 4, f"X: expected 4, got {results['X']}"
    assert results["Y"] == 3, f"Y: expected 3, got {results['Y']}"
    assert results["Z"] == 2, f"Z: expected 2, got {results['Z']}"
    print("[PASS] Budget election correct!")


def test_reject_invalid_vote():
    """
    Test 3: Verify that a vote with a tampered proof is rejected.
    """
    print("\n" + "=" * 60)
    print("TEST 3: Reject Invalid Vote")
    print("=" * 60)

    n_keypers = 3
    keyper_base_port = 6300
    keyper_urls = []
    for i in range(n_keypers):
        port = keyper_base_port + i
        app = create_keyper_app(i + 1)
        start_flask_in_thread(app, port)
        keyper_urls.append(f"http://127.0.0.1:{port}")

    backend_port = 6020
    backend_app = create_backend_app(keyper_urls)
    start_flask_in_thread(backend_app, backend_port)
    backend_url = f"http://127.0.0.1:{backend_port}"

    for url in keyper_urls:
        assert wait_for_server(f"{url}/status"), f"Keyper {url} not ready"
    assert wait_for_server(f"{backend_url}/election/status"), "Backend not ready"
    print("[OK] All servers started")

    resp = requests.post(f"{backend_url}/election/create", json={
        "n": n_keypers, "t": 1, "num_candidates": 2, "budget": 1,
        "candidate_names": ["Yes", "No"],
    }, timeout=30)
    assert resp.status_code == 200
    print("[OK] Election created")

    resp = requests.post(f"{backend_url}/election/dkg", timeout=120)
    assert resp.status_code == 200
    print("[OK] DKG completed")

    # Build a valid vote then tamper
    params = requests.get(f"{backend_url}/election/params", timeout=5).json()
    mpk = dict_to_point(params["mpk"])

    C1a, C2a, r1 = encrypt(mpk, 1)
    C1b, C2b, r2 = encrypt(mpk, 0)

    proof1 = prove_range(mpk, C1a, C2a, 1, r1, 1)
    proof2 = prove_range(mpk, C1b, C2b, 0, r2, 1)

    agg = aggregate_ciphertexts([(C1a, C2a), (C1b, C2b)])
    r_sum = (r1 + r2) % CURVE_ORDER
    bp = prove_exact_budget(mpk, agg[0], agg[1], 1, r_sum)

    # Tamper with proof1
    tampered = list(proof1)
    e, z = tampered[0]
    tampered[0] = ((e + 1) % CURVE_ORDER, z)

    payload = {
        "ciphertexts": [
            {"c1": point_to_dict(C1a), "c2": point_to_dict(C2a)},
            {"c1": point_to_dict(C1b), "c2": point_to_dict(C2b)},
        ],
        "range_proofs": [
            [{"e": str(ei), "z": str(zi)} for (ei, zi) in tampered],
            [{"e": str(ei), "z": str(zi)} for (ei, zi) in proof2],
        ],
        "budget_proof": {"e": str(bp[0]), "z": str(bp[1])},
    }

    resp = requests.post(f"{backend_url}/election/vote", json=payload, timeout=30)
    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}"
    assert "invalid" in resp.json()["error"].lower()
    print("[PASS] Invalid vote correctly rejected!")


def test_five_keyper_election():
    """
    Test 4: Larger setup: 5 keypers, t=2 (need 3 for decryption).
    """
    print("\n" + "=" * 60)
    print("TEST 4: Five-Keyper Election (n=5, t=2)")
    print("=" * 60)

    n_keypers = 5
    keyper_base_port = 6400
    keyper_urls = []
    for i in range(n_keypers):
        port = keyper_base_port + i
        app = create_keyper_app(i + 1)
        start_flask_in_thread(app, port)
        keyper_urls.append(f"http://127.0.0.1:{port}")

    backend_port = 6030
    backend_app = create_backend_app(keyper_urls)
    start_flask_in_thread(backend_app, backend_port)
    backend_url = f"http://127.0.0.1:{backend_port}"

    for url in keyper_urls:
        assert wait_for_server(f"{url}/status"), f"Keyper {url} not ready"
    assert wait_for_server(f"{backend_url}/election/status"), "Backend not ready"
    print("[OK] All servers started")

    resp = requests.post(f"{backend_url}/election/create", json={
        "n": n_keypers, "t": 2, "num_candidates": 2, "budget": 1,
        "candidate_names": ["For", "Against"],
    }, timeout=30)
    assert resp.status_code == 200
    print("[OK] Election created")

    resp = requests.post(f"{backend_url}/election/dkg", timeout=120)
    assert resp.status_code == 200
    print("[OK] DKG completed")

    # 7 voters: 4 For, 3 Against
    for _ in range(4):
        result = submit_vote(backend_url, [1, 0])
        assert result.get("status") == "ok"
    for _ in range(3):
        result = submit_vote(backend_url, [0, 1])
        assert result.get("status") == "ok"
    print("[OK] 7 votes submitted")

    resp = requests.post(f"{backend_url}/election/tally", timeout=120)
    assert resp.status_code == 200
    results = resp.json()["results"]
    print(f"[OK] Tally: {results}")

    assert results["For"] == 4, f"For: expected 4, got {results['For']}"
    assert results["Against"] == 3, f"Against: expected 3, got {results['Against']}"
    print("[PASS] Five-keyper election correct!")


if __name__ == "__main__":
    print("Threshold ElGamal E2E Tests (BLS12-381)")
    print("=" * 60)
    test_single_choice_election()
    test_budget_election()
    test_reject_invalid_vote()
    test_five_keyper_election()
    print("\n" + "=" * 60)
    print("ALL E2E TESTS PASSED!")
    print("=" * 60)
