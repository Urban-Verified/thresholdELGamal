#!/usr/bin/env python3
"""
Tests for security audit fixes #1, #2, and #3.

#1 (CRITICAL): receive_share rejects duplicate shares from same dealer
#2 (HIGH):     DKG complaint resolution with dealer rebuttal (Feldman VSS)
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
    """Allocate unique ports for n_keypers keyper servers."""
    base = _PORT_COUNTER[0]
    _PORT_COUNTER[0] += n_keypers
    keyper_ports = [base + i for i in range(n_keypers)]
    return keyper_ports


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
        cls.keyper_port_1 = ports[0]
        cls.keyper_port_2 = ports[1]
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

    def test_election_id_mismatch_is_rejected(self):
        """Signed P2P messages must be bound to a single election_id context."""
        body = self._signed_share_body(2, 1, random_scalar())
        body["election_id"] = "some-other-election"
        resp = requests.post(f"{self.url_1}/dkg/receive_share", json=body, timeout=5)
        self.assertEqual(resp.status_code, 400, resp.text)
        self.assertIn("election id mismatch", resp.json()["error"].lower())

    def test_different_dealers_accepted(self):
        # Reset receiver and add a 3rd member so we have a 2nd valid dealer.
        from keyper import create_keyper_app as _mk_keyper
        # Use a separate keyper-3 process so we have a real signing key.
        p3 = _next_ports(1)[0]
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
        keyper_ports = _next_ports(cls.n)

        # Start keypers
        cls.keyper_urls = []
        cls.keyper_apps = []
        for i in range(cls.n):
            app = create_keyper_app(i + 1)
            start_flask_in_thread(app, keyper_ports[i])
            cls.keyper_urls.append(f"http://127.0.0.1:{keyper_ports[i]}")
            cls.keyper_apps.append(app)

        for url in cls.keyper_urls:
            assert wait_for_server(f"{url}/status"), f"Keyper {url} not ready"

    def test_honest_dkg_completes(self):
        """Normal DKG without any injected bad shares should succeed."""
        election_id = "test-honest-dkg"
        members = [requests.get(f"{u}/status", timeout=5).json()["address"] for u in self.keyper_urls]
        url_map = {str(i + 1): self.keyper_urls[i] for i in range(self.n)}
        for kid, url in enumerate(self.keyper_urls, start=1):
            r = requests.post(f"{url}/dkg/round1", json={
                "n": self.n, "t": self.t, "keyper_id": kid,
                "election_id": election_id, "members": members,
            }, timeout=20)
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json().get("status"), "ok", r.json())
        for url in self.keyper_urls:
            r = requests.post(f"{url}/dkg/distribute_commitments", json={"keyper_urls": url_map}, timeout=30)
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json().get("status"), "ok", r.json())
        for url in self.keyper_urls:
            r = requests.post(f"{url}/dkg/distribute_shares", json={"keyper_urls": url_map}, timeout=30)
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json().get("status"), "ok", r.json())
        for url in self.keyper_urls:
            r = requests.post(f"{url}/dkg/round2", json={"election_id": election_id}, timeout=30)
            self.assertEqual(r.status_code, 200, r.text)
            self.assertTrue(r.json().get("verified"), r.json())

    def test_reveal_share_endpoint_returns_correct_share(self):
        """The reveal_share endpoint returns the share the dealer computed for a recipient."""
        election_id = "test-reveal-share"
        members = [requests.get(f"{u}/status", timeout=5).json()["address"] for u in self.keyper_urls]
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

if __name__ == "__main__":
    unittest.main(verbosity=2)
