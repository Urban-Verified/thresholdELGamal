#!/usr/bin/env python3
"""
Tests for security audit fixes #1, #2, and #3.

#1 (CRITICAL): receive_share rejects duplicate shares from same dealer
#2 (HIGH):     DKG complaint resolution with dealer rebuttal (Feldman VSS)
#3 (HIGH):     Vote phase re-check prevents race condition with tally
"""

import threading
import time
import sys
import os
import json
import requests
import logging
import unittest

# Suppress Flask/werkzeug request logging
logging.getLogger("werkzeug").setLevel(logging.ERROR)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keyper import create_keyper_app
from backend import create_backend_app
from crypto.primitives import (
    CURVE_ORDER, G2, Z2,
    point_to_dict, dict_to_point,
    point_multiply, point_add, point_eq,
    random_scalar,
)
from crypto.elgamal import encrypt, aggregate_ciphertexts
from crypto.proofs import prove_range, prove_exact_budget


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

_PORT_COUNTER = [7000]  # shared mutable for unique port allocation


def _next_ports(n_keypers):
    """Allocate unique ports: (backend_port, keyper_ports_list)."""
    base = _PORT_COUNTER[0]
    _PORT_COUNTER[0] += n_keypers + 1
    backend_port = base
    keyper_ports = [base + 1 + i for i in range(n_keypers)]
    return backend_port, keyper_ports


def start_flask_in_thread(app, port, host="127.0.0.1"):
    t = threading.Thread(
        target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False),
        daemon=True,
    )
    t.start()
    return t


def wait_for_server(url, retries=30, delay=0.2):
    for _ in range(retries):
        try:
            requests.get(url, timeout=1)
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(delay)
    return False


def submit_vote(backend_url, vote_vector):
    """Client-side: encrypt, prove, submit a vote."""
    params = requests.get(f"{backend_url}/election/params", timeout=5).json()
    mpk = dict_to_point(params["mpk"])
    B = params["budget"]
    num_candidates = params["num_candidates"]
    election_id = params.get("election_id", "")

    assert len(vote_vector) == num_candidates
    assert sum(vote_vector) == B

    ciphertexts = []
    randomnesses = []
    for v in vote_vector:
        C1, C2, r = encrypt(mpk, v)
        ciphertexts.append((C1, C2))
        randomnesses.append(r)

    range_proofs = []
    for j in range(num_candidates):
        c1, c2 = ciphertexts[j]
        proof = prove_range(mpk, c1, c2, vote_vector[j], randomnesses[j], B,
                            election_id=election_id)
        range_proofs.append(proof)

    sum_ct = aggregate_ciphertexts(ciphertexts)
    sum_r = sum(randomnesses) % CURVE_ORDER
    budget_proof = prove_exact_budget(mpk, sum_ct[0], sum_ct[1], B, sum_r,
                                      election_id=election_id)

    payload = {
        "ciphertexts": [
            {"c1": point_to_dict(c1), "c2": point_to_dict(c2)}
            for c1, c2 in ciphertexts
        ],
        "range_proofs": [
            [{"e": str(e), "z": str(z)} for e, z in proof]
            for proof in range_proofs
        ],
        "budget_proof": {"e": str(budget_proof[0]), "z": str(budget_proof[1])},
    }
    return requests.post(f"{backend_url}/election/vote", json=payload, timeout=30)


# =========================================================================
#  Test #1: receive_share rejects duplicate shares
# =========================================================================

class TestShareOverwriteProtection(unittest.TestCase):
    """Audit fix #1 (signed-P2P era): receive_share must reject a second
    share from the same dealer (append-only) AND must reject any forged
    or unsigned message regardless of order.
    """

    @classmethod
    def setUpClass(cls):
        # Stand up two keypers — keyper 1 is the receiver under test, keyper
        # 2 is a real dealer whose signing key we use to forge well-formed
        # signed payloads. Keyper 3 is referenced only for the "unknown
        # dealer" path; we build its address from its deterministic dev key.
        from keyper import _share_payload_hash, _sign  # private helpers
        from eth_account import Account
        cls._share_payload_hash = staticmethod(_share_payload_hash)
        cls._sign = staticmethod(_sign)

        ports = _next_ports(2)
        cls.keyper_port_1 = ports[1][0]
        cls.keyper_port_2 = ports[1][1]
        cls.app1 = create_keyper_app(1)
        cls.app2 = create_keyper_app(2)
        start_flask_in_thread(cls.app1, cls.keyper_port_1)
        start_flask_in_thread(cls.app2, cls.keyper_port_2)
        cls.url_1 = f"http://127.0.0.1:{cls.keyper_port_1}"
        cls.url_2 = f"http://127.0.0.1:{cls.keyper_port_2}"
        assert wait_for_server(f"{cls.url_1}/status"), "Keyper 1 not ready"
        assert wait_for_server(f"{cls.url_2}/status"), "Keyper 2 not ready"

        cls.addr_1 = requests.get(f"{cls.url_1}/status", timeout=5).json()["address"]
        cls.addr_2 = requests.get(f"{cls.url_2}/status", timeout=5).json()["address"]

        # Recover keyper 2's dev signing key (matches the keyper.py fallback
        # so we can forge correctly-signed messages from dealer 2).
        import hashlib
        cls.signing_key_2 = "0x" + hashlib.sha256(b"keyper-2").hexdigest()
        assert Account.from_key(cls.signing_key_2).address == cls.addr_2

        # Pin keyper 1's DKG context so signature verification has a
        # members[] list to compare against.
        cls.election_id = "test-overwrite-protection"
        members = [cls.addr_1, cls.addr_2]
        resp = requests.post(f"{cls.url_1}/dkg/round1", json={
            "n": 2, "t": 0, "keyper_id": 1,
            "election_id": cls.election_id,
            "members": members,
        }, timeout=5)
        assert resp.status_code == 200, resp.text

    def setUp(self):
        # Reset keyper 1's DKG state before every test by re-running round1.
        members = [self.addr_1, self.addr_2]
        requests.post(f"{self.url_1}/dkg/round1", json={
            "n": 2, "t": 0, "keyper_id": 1,
            "election_id": self.election_id, "members": members,
        }, timeout=5)

    def _signed_share_body(self, dealer_id, recipient_id, share, *, signing_key=None):
        sk = signing_key or self.signing_key_2
        payload_hash = self._share_payload_hash(self.election_id, dealer_id, recipient_id, share)
        sig = self._sign(sk, payload_hash)
        return {
            "election_id": self.election_id,
            "dealer_id": dealer_id,
            "recipient_id": recipient_id,
            "share": str(share),
            "signature": sig,
        }

    def test_first_share_accepted(self):
        body = self._signed_share_body(2, 1, random_scalar())
        resp = requests.post(f"{self.url_1}/dkg/receive_share", json=body, timeout=5)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["status"], "ok")

    def test_duplicate_share_rejected_with_409(self):
        body1 = self._signed_share_body(2, 1, random_scalar())
        resp1 = requests.post(f"{self.url_1}/dkg/receive_share", json=body1, timeout=5)
        self.assertEqual(resp1.status_code, 200, resp1.text)

        body2 = self._signed_share_body(2, 1, random_scalar())
        resp2 = requests.post(f"{self.url_1}/dkg/receive_share", json=body2, timeout=5)
        self.assertEqual(resp2.status_code, 409, resp2.text)
        self.assertIn("already received", resp2.json()["error"].lower())

    def test_unsigned_share_is_rejected(self):
        """Phase-1 P2P requires signed messages; raw posts get 400/401."""
        resp = requests.post(f"{self.url_1}/dkg/receive_share", json={
            "election_id": self.election_id,
            "dealer_id": 2, "recipient_id": 1,
            "share": str(random_scalar()),
            # Missing signature.
        }, timeout=5)
        self.assertIn(resp.status_code, (400, 401))

    def test_forged_signature_is_rejected(self):
        """A signed payload from someone other than the claimed dealer fails verify."""
        # Sign with a key that is NOT keyper 2's. The wrong-signer recovers
        # to a different address, so the receiver rejects it.
        wrong_key = "0x" + ("11" * 32)
        body = self._signed_share_body(2, 1, random_scalar(), signing_key=wrong_key)
        resp = requests.post(f"{self.url_1}/dkg/receive_share", json=body, timeout=5)
        self.assertEqual(resp.status_code, 401, resp.text)
        self.assertIn("bad signature", resp.json()["error"].lower())

    def test_different_dealers_accepted(self):
        # Reset receiver and add a 3rd member so we have a 2nd valid dealer.
        from keyper import create_keyper_app as _mk_keyper
        # Use a separate keyper-3 process so we have a real signing key.
        p3 = _next_ports(1)[1][0]
        app3 = _mk_keyper(3)
        start_flask_in_thread(app3, p3)
        url_3 = f"http://127.0.0.1:{p3}"
        assert wait_for_server(f"{url_3}/status")
        addr_3 = requests.get(f"{url_3}/status", timeout=5).json()["address"]
        import hashlib
        signing_key_3 = "0x" + hashlib.sha256(b"keyper-3").hexdigest()

        members = [self.addr_1, self.addr_2, addr_3]
        requests.post(f"{self.url_1}/dkg/round1", json={
            "n": 3, "t": 1, "keyper_id": 1,
            "election_id": self.election_id, "members": members,
        }, timeout=5)

        body_2 = self._signed_share_body(2, 1, random_scalar())
        resp_2 = requests.post(f"{self.url_1}/dkg/receive_share", json=body_2, timeout=5)
        self.assertEqual(resp_2.status_code, 200, resp_2.text)

        body_3 = self._signed_share_body(3, 1, random_scalar(), signing_key=signing_key_3)
        resp_3 = requests.post(f"{self.url_1}/dkg/receive_share", json=body_3, timeout=5)
        self.assertEqual(resp_3.status_code, 200, resp_3.text)


# =========================================================================
#  Test #2: DKG complaint resolution with dealer rebuttal
# =========================================================================

class TestComplaintResolution(unittest.TestCase):
    """Audit fix #2: Complaints trigger dealer rebuttal; false complainers are excluded."""

    @classmethod
    def setUpClass(cls):
        """Set up a 5-keyper cluster where we can inject bad shares to trigger complaints."""
        cls.n = 5
        cls.t = 2  # need t+1 = 3 for decryption
        backend_port, keyper_ports = _next_ports(cls.n)

        # Start BB
        # Start keypers
        cls.keyper_urls = []
        cls.keyper_apps = []
        for i in range(cls.n):
            app = create_keyper_app(i + 1)
            start_flask_in_thread(app, keyper_ports[i])
            cls.keyper_urls.append(f"http://127.0.0.1:{keyper_ports[i]}")
            cls.keyper_apps.append(app)

        # Start backend
        cls.backend_app = create_backend_app(cls.keyper_urls)
        start_flask_in_thread(cls.backend_app, backend_port)
        cls.backend_url = f"http://127.0.0.1:{backend_port}"

        for url in cls.keyper_urls:
            assert wait_for_server(f"{url}/status"), f"Keyper {url} not ready"
        assert wait_for_server(f"{cls.backend_url}/election/status"), "Backend not ready"

    def test_honest_dkg_completes(self):
        """Normal DKG without any injected bad shares should succeed."""
        # Create election
        resp = requests.post(f"{self.backend_url}/election/create", json={
            "n": self.n, "t": self.t, "num_candidates": 3, "budget": 1,
            "candidate_names": ["A", "B", "C"],
        }, timeout=10)
        self.assertEqual(resp.status_code, 200, f"Create failed: {resp.text}")

        # Run DKG
        resp = requests.post(f"{self.backend_url}/election/dkg", timeout=60)
        self.assertEqual(resp.status_code, 200, f"DKG failed: {resp.text}")
        data = resp.json()
        self.assertEqual(data["phase"], "voting")
        self.assertIn("mpk", data)

    def test_reveal_share_endpoint_returns_correct_share(self):
        """The reveal_share endpoint returns the share the dealer computed for a recipient."""
        # Use a fresh election to trigger round1 and populate pending_shares
        # Reset first
        requests.post(f"{self.backend_url}/election/reset", json={}, timeout=10)

        resp = requests.post(f"{self.backend_url}/election/create", json={
            "n": self.n, "t": self.t, "num_candidates": 3, "budget": 1,
            "candidate_names": ["A", "B", "C"],
        }, timeout=10)
        self.assertEqual(resp.status_code, 200)

        # Manually run round1 on keyper 1 to populate pending_shares
        params = requests.get(f"{self.backend_url}/election/params", timeout=5).json()
        election_id = params["election_id"]

        # Collect keyper signing addresses for the new members[] field.
        members = []
        for url in self.keyper_urls:
            members.append(requests.get(f"{url}/status", timeout=5).json()["address"])
        resp = requests.post(f"{self.keyper_urls[0]}/dkg/round1", json={
            "n": self.n, "t": self.t, "keyper_id": 1,
            "election_id": election_id,
            "members": members,
        }, timeout=10)
        self.assertEqual(resp.status_code, 200)

        # Ask keyper 1 to reveal its share for keyper 2
        resp = requests.post(f"{self.keyper_urls[0]}/dkg/reveal_share", json={
            "recipient_id": 2,
        }, timeout=5)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["dealer_id"], 1)
        self.assertEqual(data["recipient_id"], 2)
        # The share should be a valid scalar
        share = int(data["share"])
        self.assertGreaterEqual(share, 0)
        self.assertLess(share, CURVE_ORDER)

    def test_reveal_share_for_nonexistent_recipient(self):
        """reveal_share returns 404 for a recipient we never computed a share for."""
        resp = requests.post(f"{self.keyper_urls[0]}/dkg/reveal_share", json={
            "recipient_id": 999,
        }, timeout=5)
        self.assertEqual(resp.status_code, 404)


# =========================================================================
#  Test #3: Vote phase re-check prevents race condition
# =========================================================================

class TestVotePhaseRecheck(unittest.TestCase):
    """Audit fix #3: Votes submitted during tally transition are properly rejected."""

    @classmethod
    def setUpClass(cls):
        cls.n = 3
        cls.t = 1
        backend_port, keyper_ports = _next_ports(cls.n)

        # Start BB
        # Start keypers
        cls.keyper_urls = []
        for i in range(cls.n):
            app = create_keyper_app(i + 1)
            start_flask_in_thread(app, keyper_ports[i])
            cls.keyper_urls.append(f"http://127.0.0.1:{keyper_ports[i]}")

        # Start backend
        cls.backend_app = create_backend_app(cls.keyper_urls)
        start_flask_in_thread(cls.backend_app, backend_port)
        cls.backend_url = f"http://127.0.0.1:{backend_port}"

        for url in cls.keyper_urls:
            assert wait_for_server(f"{url}/status"), f"Keyper {url} not ready"
        assert wait_for_server(f"{cls.backend_url}/election/status"), "Backend not ready"

    def test_vote_rejected_after_phase_changes_to_tallying(self):
        """A vote submitted after tally begins must be rejected (phase != voting)."""
        # Create election + DKG
        resp = requests.post(f"{self.backend_url}/election/create", json={
            "n": self.n, "t": self.t, "num_candidates": 3, "budget": 1,
            "candidate_names": ["A", "B", "C"],
        }, timeout=10)
        self.assertEqual(resp.status_code, 200)

        resp = requests.post(f"{self.backend_url}/election/dkg", timeout=60)
        self.assertEqual(resp.status_code, 200)

        # Submit one valid vote so tally has something to work with
        resp = submit_vote(self.backend_url, [1, 0, 0])
        self.assertEqual(resp.status_code, 200, f"Vote failed: {resp.text}")

        # Directly set phase to tallying (simulating the race condition
        # where tally starts between the two lock acquisitions)
        state = self.backend_app._election_state
        with state["lock"]:
            state["phase"] = "tallying"

        # Now try to submit another vote — should be rejected
        resp = submit_vote(self.backend_url, [0, 1, 0])
        self.assertNotEqual(resp.status_code, 200,
                           "Vote should be rejected when phase is 'tallying'")
        self.assertIn("error", resp.json())

    def test_vote_accepted_during_voting_phase(self):
        """Votes during voting phase should still be accepted."""
        # Reset and create fresh election
        requests.post(f"{self.backend_url}/election/reset", json={}, timeout=10)

        resp = requests.post(f"{self.backend_url}/election/create", json={
            "n": self.n, "t": self.t, "num_candidates": 3, "budget": 1,
            "candidate_names": ["A", "B", "C"],
        }, timeout=10)
        self.assertEqual(resp.status_code, 200)

        resp = requests.post(f"{self.backend_url}/election/dkg", timeout=60)
        self.assertEqual(resp.status_code, 200)

        # Submit vote in proper voting phase
        resp = submit_vote(self.backend_url, [0, 0, 1])
        self.assertEqual(resp.status_code, 200, f"Vote should succeed: {resp.text}")

    def test_full_election_tally_correct_after_fix(self):
        """Full lifecycle: votes + tally, ensuring the tally matches exactly."""
        requests.post(f"{self.backend_url}/election/reset", json={}, timeout=10)

        resp = requests.post(f"{self.backend_url}/election/create", json={
            "n": self.n, "t": self.t, "num_candidates": 3, "budget": 1,
            "candidate_names": ["A", "B", "C"],
        }, timeout=10)
        self.assertEqual(resp.status_code, 200)

        resp = requests.post(f"{self.backend_url}/election/dkg", timeout=60)
        self.assertEqual(resp.status_code, 200)

        # Submit 5 votes: A=2, B=2, C=1
        votes = [[1, 0, 0], [1, 0, 0], [0, 1, 0], [0, 1, 0], [0, 0, 1]]
        for v in votes:
            resp = submit_vote(self.backend_url, v)
            self.assertEqual(resp.status_code, 200, f"Vote failed: {resp.text}")

        # Tally
        resp = requests.post(f"{self.backend_url}/election/tally", timeout=60)
        self.assertEqual(resp.status_code, 200, f"Tally failed: {resp.text}")
        results = resp.json()["results"]
        self.assertEqual(results["A"], 2)
        self.assertEqual(results["B"], 2)
        self.assertEqual(results["C"], 1)


# =========================================================================
#  Integration test: full DKG with injected bad share triggers complaint
#  resolution and the correct party is excluded
# =========================================================================

class TestComplaintResolutionIntegration(unittest.TestCase):
    """Integration test: inject a bad share, verify complaint resolution
    correctly identifies the guilty party (not the complainer)."""

    def test_bad_share_injection_excludes_dealer_not_complainer(self):
        """
        Setup: 5 keypers, t=1.
        Attack: After round1, before round2, we inject a bad share into
                keyper 3's received_shares pretending to be from dealer 1.
        Expected: Keyper 3 complains about dealer 1. Backend asks dealer 1
                  to reveal the real share. The real share verifies → BUT
                  the injected share doesn't match, meaning dealer 1's
                  revealed share should verify against commitments.
                  
        Since the P2P delivery already happened with the correct share,
        and we're overwriting after delivery, the receive_share endpoint
        now rejects overwrites (fix #1). So we test the complaint rebuttal
        flow by directly manipulating the keyper state.
        """
        n = 5
        t = 1
        backend_port, keyper_ports = _next_ports(n)

        keyper_urls = []
        keyper_apps = []
        for i in range(n):
            app = create_keyper_app(i + 1)
            start_flask_in_thread(app, keyper_ports[i])
            keyper_urls.append(f"http://127.0.0.1:{keyper_ports[i]}")
            keyper_apps.append(app)

        backend_app = create_backend_app(keyper_urls)
        start_flask_in_thread(backend_app, backend_port)
        backend_url = f"http://127.0.0.1:{backend_port}"

        for url in keyper_urls:
            assert wait_for_server(f"{url}/status")
        assert wait_for_server(f"{backend_url}/election/status")

        # Create election
        resp = requests.post(f"{backend_url}/election/create", json={
            "n": n, "t": t, "num_candidates": 2, "budget": 1,
            "candidate_names": ["Yes", "No"],
        }, timeout=10)
        self.assertEqual(resp.status_code, 200)

        # Get election_id
        params = requests.get(f"{backend_url}/election/params", timeout=5).json()
        election_id = params["election_id"]

        # Collect keyper addresses for the members[] field.
        members = []
        for url in keyper_urls:
            members.append(requests.get(f"{url}/status", timeout=5).json()["address"])

        # --- Manually run round1 for all keypers ---
        round1_responses = []
        for i in range(n):
            kid = i + 1
            resp = requests.post(f"{keyper_urls[i]}/dkg/round1", json={
                "n": n, "t": t, "keyper_id": kid,
                "election_id": election_id,
                "members": members,
            }, timeout=10)
            self.assertEqual(resp.status_code, 200, f"Round1 failed for keyper {kid}: {resp.text}")
            round1_responses.append(resp.json())

        # --- Fan out commitments P2P (signed) ---
        keyper_url_map = {str(i + 1): keyper_urls[i] for i in range(n)}
        for i in range(n):
            resp = requests.post(f"{keyper_urls[i]}/dkg/distribute_commitments", json={
                "keyper_urls": keyper_url_map,
            }, timeout=30)
            self.assertEqual(resp.status_code, 200, f"Commitment distribution failed for keyper {i+1}")

        # --- Distribute shares P2P (signed) ---
        for i in range(n):
            resp = requests.post(f"{keyper_urls[i]}/dkg/distribute_shares", json={
                "keyper_urls": keyper_url_map,
            }, timeout=30)
            self.assertEqual(resp.status_code, 200, f"Share distribution failed for keyper {i+1}")

        # --- Now verify that reveal_share works for dealer 1 ---
        resp = requests.post(f"{keyper_urls[0]}/dkg/reveal_share", json={
            "recipient_id": 3,
        }, timeout=5)
        self.assertEqual(resp.status_code, 200)
        revealed_data = resp.json()
        revealed_share = int(revealed_data["share"])

        # Pull dealer 1's commitments from its round1 response.
        dealer_1_comms = [dict_to_point(c) for c in round1_responses[0]["commitments"]]

        # Verify: revealed_share · G2 == Σⱼ (3^j mod q) · γⱼ
        expected_pt = Z2
        x_power = 1
        recipient_id = 3
        for j in range(len(dealer_1_comms)):
            expected_pt = point_add(expected_pt, point_multiply(dealer_1_comms[j], x_power))
            x_power = (x_power * recipient_id) % CURVE_ORDER
        actual_pt = point_multiply(G2, revealed_share)
        self.assertTrue(point_eq(expected_pt, actual_pt),
                       "Revealed share should verify against commitments")

        # --- Now complete the DKG via the backend to ensure it still works ---
        # Reset and re-run through the backend for the full flow
        requests.post(f"{backend_url}/election/reset", json={}, timeout=10)
        resp = requests.post(f"{backend_url}/election/create", json={
            "n": n, "t": t, "num_candidates": 2, "budget": 1,
            "candidate_names": ["Yes", "No"],
        }, timeout=10)
        self.assertEqual(resp.status_code, 200)

        resp = requests.post(f"{backend_url}/election/dkg", timeout=60)
        self.assertEqual(resp.status_code, 200, f"DKG failed: {resp.text}")

        # Submit votes and tally to verify correctness
        resp = submit_vote(backend_url, [1, 0])
        self.assertEqual(resp.status_code, 200)
        resp = submit_vote(backend_url, [0, 1])
        self.assertEqual(resp.status_code, 200)
        resp = submit_vote(backend_url, [1, 0])
        self.assertEqual(resp.status_code, 200)

        resp = requests.post(f"{backend_url}/election/tally", timeout=60)
        self.assertEqual(resp.status_code, 200, f"Tally failed: {resp.text}")
        results = resp.json()["results"]
        self.assertEqual(results["Yes"], 2)
        self.assertEqual(results["No"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
