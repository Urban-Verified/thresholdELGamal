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


def _dev_signing_key(kid):
    """The deterministic dev signing key ``create_keyper_app(kid)`` derives
    when given only a keyper_id (mirrors keyper.py's fallback), so a test can
    sign as any keyper."""
    import hashlib
    return "0x" + hashlib.sha256(f"keyper-{kid}".encode()).hexdigest()


def _make_accusation(election_id, accused_dealer_id, recipient_id, *, signer_kid=None):
    """Build a DKG-ACCUSE-v1 accusation. ``signer_kid`` defaults to
    ``recipient_id`` (the honest case: the recipient signs its own
    accusation); override it to simulate a forged/wrong signer."""
    from keyper import _accusation_payload_hash, _sign
    if signer_kid is None:
        signer_kid = recipient_id
    h = _accusation_payload_hash(election_id, accused_dealer_id, recipient_id)
    return {
        "election_id": election_id,
        "accused_dealer_id": accused_dealer_id,
        "recipient_id": recipient_id,
        "signature": _sign(_dev_signing_key(signer_kid), h),
    }


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

    def _round1_keyper1(self, election_id):
        """Run round1 on keyper 1 so it holds pending_shares and pins the
        election context, and return the members list."""
        members = [requests.get(f"{u}/status", timeout=5).json()["address"] for u in self.keyper_urls]
        resp = requests.post(f"{self.keyper_urls[0]}/dkg/round1", json={
            "n": self.n, "t": self.t, "keyper_id": 1,
            "election_id": election_id, "members": members,
        }, timeout=10)
        self.assertEqual(resp.status_code, 200, resp.text)
        return members

    def test_reveal_share_with_valid_accusation_returns_share(self):
        """A valid recipient-signed accusation unlocks exactly that recipient's share."""
        election_id = "test-reveal-share"
        self._round1_keyper1(election_id)
        # Keyper 2 (the recipient) signs an accusation against dealer 1.
        acc = _make_accusation(election_id, accused_dealer_id=1, recipient_id=2)
        resp = requests.post(f"{self.keyper_urls[0]}/dkg/reveal_share",
                             json={"accusation": acc}, timeout=5)
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()
        self.assertEqual(data["dealer_id"], 1)
        self.assertEqual(data["recipient_id"], 2)
        share = int(data["share"])
        self.assertGreaterEqual(share, 0)
        self.assertLess(share, CURVE_ORDER)

    def test_reveal_share_without_accusation_is_rejected(self):
        """The old ungated {recipient_id} shape discloses nothing now (closes H-1)."""
        election_id = "test-reveal-noacc"
        self._round1_keyper1(election_id)
        resp = requests.post(f"{self.keyper_urls[0]}/dkg/reveal_share",
                             json={"recipient_id": 2}, timeout=5)
        self.assertEqual(resp.status_code, 400, resp.text)

    def test_reveal_share_wrong_signer_is_rejected(self):
        """An accusation not signed by the named recipient is refused."""
        election_id = "test-reveal-wrongsigner"
        self._round1_keyper1(election_id)
        # recipient_id claims 2, but keyper 3 actually signed it.
        acc = _make_accusation(election_id, accused_dealer_id=1, recipient_id=2, signer_kid=3)
        resp = requests.post(f"{self.keyper_urls[0]}/dkg/reveal_share",
                             json={"accusation": acc}, timeout=5)
        self.assertEqual(resp.status_code, 401, resp.text)

    def test_reveal_share_wrong_accused_dealer_is_rejected(self):
        """An accusation naming a different dealer must not unlock this dealer's share."""
        election_id = "test-reveal-wrongdealer"
        self._round1_keyper1(election_id)
        # Validly signed by recipient 2, but names dealer 3 -- sent to keyper 1,
        # which must refuse (accused_dealer_id != self.kid).
        acc = _make_accusation(election_id, accused_dealer_id=3, recipient_id=2)
        resp = requests.post(f"{self.keyper_urls[0]}/dkg/reveal_share",
                             json={"accusation": acc}, timeout=5)
        self.assertEqual(resp.status_code, 401, resp.text)

    def test_reveal_share_election_mismatch_is_rejected(self):
        """An accusation scoped to a different election is refused."""
        election_id = "test-reveal-election"
        self._round1_keyper1(election_id)
        acc = _make_accusation("some-other-election", accused_dealer_id=1, recipient_id=2)
        resp = requests.post(f"{self.keyper_urls[0]}/dkg/reveal_share",
                             json={"accusation": acc}, timeout=5)
        self.assertEqual(resp.status_code, 401, resp.text)

    def test_receive_share_accepts_sealed_share(self):
        """receive_share unseals a `sealed_share` to the recipient's X25519 key,
        then applies the same signature/append-only checks as plaintext. A
        passive observer of this request sees only ciphertext."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        from keyper import seal_share, _share_payload_hash, _sign

        election_id = "test-sealed-receive"
        members = [requests.get(f"{u}/status", timeout=5).json()["address"] for u in self.keyper_urls]
        # Keyper 1 is the recipient; keyper 2 is the dealer.
        r = requests.post(f"{self.keyper_urls[0]}/dkg/round1", json={
            "n": self.n, "t": self.t, "keyper_id": 1,
            "election_id": election_id, "members": members,
        }, timeout=10)
        self.assertEqual(r.status_code, 200, r.text)

        # Recipient's published X25519 key (bound to its address on /status).
        enc_hex = requests.get(f"{self.keyper_urls[0]}/status", timeout=5).json()["encryption_pubkey"]
        recipient_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(enc_hex.removeprefix("0x")))

        share_val = 4242
        sealed = seal_share(share_val, recipient_pub)
        sig = _sign(_dev_signing_key(2), _share_payload_hash(election_id, 2, 1, share_val))
        body = {"election_id": election_id, "dealer_id": 2, "recipient_id": 1,
                "sealed_share": sealed, "signature": sig}

        r1 = requests.post(f"{self.keyper_urls[0]}/dkg/receive_share", json=body, timeout=5)
        self.assertEqual(r1.status_code, 200, r1.text)
        # Append-only: a duplicate from the same dealer is rejected -> proves it stored.
        r2 = requests.post(f"{self.keyper_urls[0]}/dkg/receive_share", json=body, timeout=5)
        self.assertEqual(r2.status_code, 409, r2.text)

    def test_round2_emits_signed_accusation_on_bad_share(self):
        """A recipient handed a share inconsistent with the dealer's commitments
        returns verified:false with a recipient-signed DKG-ACCUSE-v1 accusation,
        and that accusation unlocks the accused dealer's reveal (emission → gate)."""
        from keyper import (
            _commitments_payload_hash, _share_payload_hash, _sign,
            _accusation_payload_hash, _recover,
        )
        from crypto.primitives import dict_to_point

        election_id = "test-bad-share-accusation"
        members = [requests.get(f"{u}/status", timeout=5).json()["address"] for u in self.keyper_urls]

        # Keyper 1 is the victim recipient; keyper 2 is the accused dealer.
        r1 = requests.post(f"{self.keyper_urls[0]}/dkg/round1", json={
            "n": self.n, "t": self.t, "keyper_id": 1,
            "election_id": election_id, "members": members,
        }, timeout=10)
        self.assertEqual(r1.status_code, 200, r1.text)

        # Dealer 2's own round1 gives us its real commitments.
        r2 = requests.post(f"{self.keyper_urls[1]}/dkg/round1", json={
            "n": self.n, "t": self.t, "keyper_id": 2,
            "election_id": election_id, "members": members,
        }, timeout=10)
        self.assertEqual(r2.status_code, 200, r2.text)
        commitments = r2.json()["commitments"]

        key2 = _dev_signing_key(2)

        # Deliver dealer 2's (valid) commitments to keyper 1, signed by dealer 2.
        comm_points = [dict_to_point(c) for c in commitments]
        comm_sig = _sign(key2, _commitments_payload_hash(election_id, 2, comm_points))
        rc = requests.post(f"{self.keyper_urls[0]}/dkg/receive_commitments", json={
            "election_id": election_id, "dealer_id": 2,
            "commitments": commitments, "signature": comm_sig,
        }, timeout=5)
        self.assertEqual(rc.status_code, 200, rc.text)

        # Deliver a share that does NOT satisfy those commitments -- validly
        # signed by dealer 2, so the only fault is the value itself.
        bad_share = 12345
        share_sig = _sign(key2, _share_payload_hash(election_id, 2, 1, bad_share))
        rs = requests.post(f"{self.keyper_urls[0]}/dkg/receive_share", json={
            "election_id": election_id, "dealer_id": 2, "recipient_id": 1,
            "share": str(bad_share), "signature": share_sig,
        }, timeout=5)
        self.assertEqual(rs.status_code, 200, rs.text)

        # round2 on keyper 1 -> complaint against dealer 2 + a signed accusation.
        rr = requests.post(f"{self.keyper_urls[0]}/dkg/round2",
                           json={"election_id": election_id}, timeout=10)
        self.assertEqual(rr.status_code, 200, rr.text)
        body = rr.json()
        self.assertFalse(body.get("verified"), body)
        self.assertIn(2, body.get("complaints", []))
        accs = body.get("accusations", [])
        acc = next((a for a in accs if a["accused_dealer_id"] == 2 and a["recipient_id"] == 1), None)
        self.assertIsNotNone(acc, accs)
        # The accusation is signed by the recipient itself (keyper 1).
        recovered = _recover(_accusation_payload_hash(election_id, 2, 1), acc["signature"])
        self.assertEqual(recovered.lower(), members[0].lower())

        # End-to-end: that emitted accusation unlocks dealer 2's reveal for recipient 1.
        rev = requests.post(f"{self.keyper_urls[1]}/dkg/reveal_share",
                            json={"accusation": acc}, timeout=5)
        self.assertEqual(rev.status_code, 200, rev.text)
        self.assertEqual(rev.json()["dealer_id"], 2)
        self.assertEqual(rev.json()["recipient_id"], 1)

class TestCoordinatorHaltOnComplaint(unittest.TestCase):
    """run_dkg must stop before publishing when any round2 reports a complaint,
    and surface the signed accusations (scope A: halt + evidence, not
    auto-resolve). Pure unit test -- no Flask, no chain -- via a mocked _post.
    """

    def test_run_dkg_halts_before_publish_on_complaint(self):
        import dkg_coordinator
        from unittest import mock

        election_id = "halt-election"
        urls = ["http://kp1", "http://kp2", "http://kp3"]
        members = ["0x" + f"{i:040x}" for i in range(1, 4)]
        calls = []

        def fake_post(url, path, payload, *, timeout, headers=None):
            calls.append(path)
            if path == "/dkg/round2":
                return {
                    "verified": False,
                    "complaints": [2],
                    "accusations": [{
                        "election_id": election_id, "accused_dealer_id": 2,
                        "recipient_id": 1, "signature": "0xdeadbeef",
                    }],
                }
            return {}

        with mock.patch.object(dkg_coordinator, "_post", side_effect=fake_post):
            with self.assertRaises(dkg_coordinator.DKGCoordinatorError) as ctx:
                dkg_coordinator.run_dkg(
                    keyper_urls=urls, election_id=election_id,
                    election_address="0xelection", n=3, t=1,
                    members=members, api_tokens=None, rpc_url=None,
                    verbose=False,
                )
        self.assertIn("halted", str(ctx.exception).lower())
        # Complaint detected at round2 -> publish must never be attempted.
        self.assertIn("/dkg/round2", calls)
        self.assertNotIn("/dkg/publish_on_chain", calls)


class TestShareSealing(unittest.TestCase):
    """C-1 Leg A: DKG secret shares are sealed to the recipient's X25519 key
    before hitting the wire, so a passive network observer sees only ciphertext.
    Unit tests for the seal_share/unseal_share primitive."""

    def _keypair(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        priv = X25519PrivateKey.generate()
        return priv, priv.public_key()

    def test_seal_unseal_round_trips_scalar(self):
        from keyper import seal_share, unseal_share
        priv, pub = self._keypair()
        share = 0x1234567890abcdef1122334455667788
        sealed = seal_share(share, pub)
        self.assertIsInstance(sealed, str)
        self.assertEqual(unseal_share(sealed, priv), share)

    def test_unseal_rejects_blob_without_share_domain_tag(self):
        """A box sealed to the same key but lacking the DKG-SHARE-SEAL-v1 tag
        (e.g. a bootstrap-shaped payload) must not unseal as a share."""
        import base64
        from keyper import unseal_share
        from token_bootstrap import x25519_seal
        priv, pub = self._keypair()
        # Validly sealed to `pub`, but the plaintext carries no share tag.
        foreign = base64.b64encode(x25519_seal(b'{"payload":"not-a-share"}', pub)).decode()
        with self.assertRaises(Exception):
            unseal_share(foreign, priv)

    def test_build_share_body_seals_when_key_present(self):
        """The outgoing /dkg/receive_share body carries a sealed_share (and no
        plaintext) when the recipient's key is known, and the dealer signature
        still verifies over the recovered value."""
        from keyper import _build_share_body, unseal_share, _share_payload_hash, _recover
        priv, pub = self._keypair()
        key1 = _dev_signing_key(1)
        addr1 = __import__("eth_account").Account.from_key(key1).address
        body = _build_share_body("e1", dealer_id=1, recipient_id=2, share=77,
                                 signing_key=key1, recipient_enc_pubkey=pub)
        self.assertIn("sealed_share", body)
        self.assertNotIn("share", body)
        self.assertEqual(unseal_share(body["sealed_share"], priv), 77)
        recovered = _recover(_share_payload_hash("e1", 1, 2, 77), body["signature"])
        self.assertEqual(recovered.lower(), addr1.lower())

    def test_build_share_body_plaintext_when_no_key(self):
        """With no recipient key (single-operator dev mode) the body falls back
        to a plaintext share."""
        from keyper import _build_share_body
        body = _build_share_body("e1", dealer_id=1, recipient_id=2, share=77,
                                 signing_key=_dev_signing_key(1), recipient_enc_pubkey=None)
        self.assertEqual(body["share"], "77")
        self.assertNotIn("sealed_share", body)

    def test_verify_encryption_pubkey_binds_to_member_address(self):
        """A peer's X25519 key is accepted only when its self-signature recovers
        to the expected (on-chain member) address -- so a lying coordinator
        can't substitute its own key to redirect a sealed share."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from eth_account import Account
        from token_bootstrap import verify_encryption_pubkey, enc_pubkey_hash
        from keyper import _sign

        key = _dev_signing_key(1)
        addr = Account.from_key(key).address
        xpriv = X25519PrivateKey.generate()
        pub_bytes = xpriv.public_key().public_bytes_raw()
        pub_hex = "0x" + pub_bytes.hex()
        sig = _sign(key, enc_pubkey_hash(pub_bytes))

        got = verify_encryption_pubkey(addr, pub_hex, sig)
        self.assertEqual(got.public_bytes_raw(), pub_bytes)

        wrong_addr = Account.from_key(_dev_signing_key(2)).address
        with self.assertRaises(Exception):
            verify_encryption_pubkey(wrong_addr, pub_hex, sig)

    def test_unseal_rejects_tampered_ciphertext(self):
        """Flipping a byte of the sealed box fails AES-GCM authentication."""
        import base64
        from keyper import seal_share, unseal_share
        priv, pub = self._keypair()
        sealed = seal_share(999, pub)
        raw = bytearray(base64.b64decode(sealed))
        raw[-1] ^= 0x01  # flip a ciphertext byte
        tampered = base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(Exception):
            unseal_share(tampered, priv)


if __name__ == "__main__":
    unittest.main(verbosity=2)
