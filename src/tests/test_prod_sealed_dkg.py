#!/usr/bin/env python3
"""End-to-end test of the multi-operator (production) DKG path.

Exercises what the on-chain e2e (test_e2e_onchain.py) does not: auth enabled,
coordinator token bootstrap over the sealed + EIP-191-signed /auth/bootstrap
channel, and a full DKG ceremony in which every secret share is SEALED to the
recipient's X25519 key on the wire.

Runs fully in-process (no chain): drives round1 -> distribute_commitments ->
distribute_shares -> round2 with auth on, and asserts every keyper's round2
verifies. This is a strong end-to-end check of the C-1 sealing work because in
production mode receive_share REJECTS a plaintext share -- so a verified round2
here is only reachable if each share was sealed by the dealer and unsealed by
the recipient. The on-chain publish step is covered by test_e2e_onchain.py.
"""
from __future__ import annotations

import hashlib
import logging
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

import requests

logging.getLogger("werkzeug").setLevel(logging.ERROR)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eth_account import Account

import coordinator_state  # noqa: E402  (kept for symmetry / future assertions)
import dkg_coordinator
import keyper

_PORT = [7600]


def _ports(n):
    base = _PORT[0]
    _PORT[0] += n
    return [base + i for i in range(n)]


def _serve(app, port):
    threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False),
        daemon=True,
    ).start()


def _wait(url, tries=40, delay=0.2):
    for _ in range(tries):
        try:
            requests.get(url, timeout=1)
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(delay)
    return False


class TestProdSealedDKG(unittest.TestCase):
    n, t = 3, 1

    def setUp(self):
        # Save and flip the process-wide auth globals; restored in tearDown so
        # other test classes (which assume single-operator/no-auth) are unaffected.
        self._saved_auth = keyper.AUTH_REQUIRED
        self._saved_addr = keyper.COORDINATOR_ADDRESS
        self._saved_env = {k: os.environ.get(k) for k in ("KEYPER_STATE_DIR", "COORDINATOR_STATE_DIR")}

        self._tmp = tempfile.mkdtemp()
        os.environ["KEYPER_STATE_DIR"] = os.path.join(self._tmp, "keyper-state")
        os.environ["COORDINATOR_STATE_DIR"] = os.path.join(self._tmp, "coord-state")

        self.coord_key = "0x" + hashlib.sha256(b"e2e-coordinator").hexdigest()
        keyper.COORDINATOR_ADDRESS = Account.from_key(self.coord_key).address
        keyper.AUTH_REQUIRED = True

    def tearDown(self):
        keyper.AUTH_REQUIRED = self._saved_auth
        keyper.COORDINATOR_ADDRESS = self._saved_addr
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_prod_sealed_dkg_ceremony(self):
        keys = ["0x" + hashlib.sha256(f"e2e-keyper-{i}".encode()).hexdigest()
                for i in range(1, self.n + 1)]
        urls = []
        for key, port in zip(keys, _ports(self.n)):
            _serve(keyper.create_keyper_app(signing_key=key), port)
            urls.append(f"http://127.0.0.1:{port}")
        for u in urls:
            self.assertTrue(_wait(f"{u}/status"), f"{u} not up")

        # Auth is enforced before bootstrap: a DKG call with no token is 401.
        self.assertEqual(
            requests.post(f"{urls[0]}/dkg/round1", json={}, timeout=5).status_code, 401)

        # Coordinator mints + pushes tokens over the sealed+signed bootstrap
        # channel (position-based kids -- no chain needed for this path).
        api_tokens = dkg_coordinator.bootstrap_keypers(urls, self.coord_key)
        self.assertEqual(len(api_tokens), self.n)
        for u in urls:
            self.assertTrue(requests.get(f"{u}/status", timeout=5).json()["bootstrapped"], u)

        def hdr(u):
            return {"Authorization": f"Bearer {api_tokens[u.rstrip('/')]}"}

        members = [requests.get(f"{u}/status", timeout=5).json()["address"] for u in urls]
        eid = "e2e-sealed"

        for kid, u in enumerate(urls, start=1):
            r = requests.post(f"{u}/dkg/round1", json={
                "n": self.n, "t": self.t, "keyper_id": kid,
                "election_id": eid, "members": members,
            }, headers=hdr(u), timeout=10)
            self.assertEqual(r.status_code, 200, r.text)

        for u in urls:  # commitments fan out P2P (peer_token)
            r = requests.post(f"{u}/dkg/distribute_commitments", json={}, headers=hdr(u), timeout=15)
            self.assertEqual(r.status_code, 200, r.text)

        for u in urls:  # shares fan out SEALED to each peer's X25519 key
            r = requests.post(f"{u}/dkg/distribute_shares", json={}, headers=hdr(u), timeout=15)
            self.assertEqual(r.status_code, 200, r.text)

        for u in urls:  # verified only if every sealed share was unsealed + Feldman-checked
            r = requests.post(f"{u}/dkg/round2", json={"election_id": eid}, headers=hdr(u), timeout=10)
            self.assertEqual(r.status_code, 200, r.text)
            self.assertTrue(r.json().get("verified"), r.json())


if __name__ == "__main__":
    unittest.main(verbosity=2)
