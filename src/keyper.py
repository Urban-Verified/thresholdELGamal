#!/usr/bin/env python3
"""
Keyper Server — Individual threshold committee member.

Each keyper runs as an independent HTTP server and participates in:
  1. Distributed Key Generation (DKG) — generates secret share, verifies others' shares
  2. Partial Decryption — computes decryption shares with DLEQ correctness proofs

All operations use BLS12-381 G2.

Usage:
    python keyper.py --id 1 --port 5001
    python keyper.py --id 2 --port 5002
    python keyper.py --id 3 --port 5003
"""

import argparse
import json
import sys
import requests
from flask import Flask, request, jsonify

from crypto.primitives import point_to_dict, dict_to_point, CURVE_ORDER
from crypto.dkg import KeyperDKGState
from crypto.proofs import prove_decryption_share


def create_keyper_app(keyper_id):
    """Create a Flask app for a single keyper."""
    app = Flask(f"keyper_{keyper_id}")
    dkg_state = KeyperDKGState()
    keyper_meta = {"id": keyper_id}
    # Stores shares generated in round1 for peer-to-peer distribution
    pending_shares = {}
    # Stores shares received from other keypers via peer-to-peer
    received_shares = {}

    @app.route("/status", methods=["GET"])
    def status():
        return jsonify({
            "keyper_id": keyper_meta["id"],
            "dkg_completed": dkg_state.combined_share is not None,
            "public_key_share": point_to_dict(dkg_state.public_key_share) if dkg_state.public_key_share else None,
        })

    @app.route("/dkg/round1", methods=["POST"])
    def dkg_round1():
        """DKG Round 1: Generate secret, polynomial, commitments, and shares.

        Returns ONLY commitments to the backend. Shares are kept locally
        for peer-to-peer distribution (backend never sees secret shares).
        """
        data = request.get_json()
        n = int(data["n"])
        t = int(data["t"])
        kid = int(data["keyper_id"])
        if kid != keyper_meta["id"]:
            return jsonify({"error": f"Keyper ID mismatch: configured as {keyper_meta['id']}, received {kid}"}), 400

        commitments, shares = dkg_state.round1(kid, n, t)

        # Store shares locally for peer-to-peer delivery
        pending_shares.clear()
        pending_shares.update(shares)
        received_shares.clear()

        return jsonify({
            "keyper_id": kid,
            "commitments": [point_to_dict(c) for c in commitments],
            # Shares are NOT sent to the backend
        })

    @app.route("/dkg/distribute_shares", methods=["POST"])
    def distribute_shares():
        """Send our secret shares directly to each recipient keyper (peer-to-peer).

        The backend provides keyper URLs but never sees the shares.
        """
        data = request.get_json()
        keyper_urls = data["keyper_urls"]  # {keyper_id_str: url}
        kid = keyper_meta["id"]

        for recipient_id_str, url in keyper_urls.items():
            recipient_id = int(recipient_id_str)
            if recipient_id == kid:
                # Deliver our own share locally
                received_shares[kid] = pending_shares[kid]
                continue
            share_val = pending_shares[recipient_id]
            try:
                resp = requests.post(f"{url}/dkg/receive_share", json={
                    "dealer_id": kid,
                    "share": str(share_val),
                }, timeout=10)
                resp.raise_for_status()
            except Exception as e:
                return jsonify({"error": f"Failed to send share to keyper {recipient_id}: {e}"}), 500

        return jsonify({"status": "ok"})

    @app.route("/dkg/receive_share", methods=["POST"])
    def receive_share():
        """Receive a secret share from another keyper (peer-to-peer)."""
        data = request.get_json()
        dealer_id = int(data["dealer_id"])
        share = int(data["share"])
        if share < 0 or share >= CURVE_ORDER:
            return jsonify({"error": "Share value out of scalar field range"}), 400
        received_shares[dealer_id] = share
        return jsonify({"status": "ok"})

    @app.route("/dkg/round2", methods=["POST"])
    def dkg_round2():
        """DKG Round 2: Verify received shares and compute combined secret share.

        Shares were received peer-to-peer. Backend sends only commitments (public).
        """
        data = request.get_json()

        # Parse commitments: {dealer_id_str: [G2 point dicts, ...]}
        all_commitments = {}
        for dealer_id_str, comms in data["all_commitments"].items():
            all_commitments[int(dealer_id_str)] = [dict_to_point(c) for c in comms]

        try:
            combined_share, public_key_share = dkg_state.round2(all_commitments, received_shares)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        # Zeroize share material after DKG completes
        pending_shares.clear()
        received_shares.clear()

        return jsonify({
            "keyper_id": keyper_meta["id"],
            "public_key_share": point_to_dict(public_key_share),
            "verified": True,
        })

    @app.route("/decrypt", methods=["POST"])
    def decrypt():
        """Compute partial decryption shares with DLEQ proofs for each candidate."""
        data = request.get_json()
        ciphertexts_c1 = [dict_to_point(c) for c in data["ciphertexts_c1"]]

        if dkg_state.combined_share is None:
            return jsonify({"error": "DKG not completed"}), 400

        msk_k = dkg_state.combined_share
        mpk_k = dkg_state.public_key_share

        results = []
        for c1 in ciphertexts_c1:
            sigma = dkg_state.partial_decrypt(c1)
            proof_e, proof_z = prove_decryption_share(c1, msk_k, mpk_k, sigma)
            results.append({
                "sigma": point_to_dict(sigma),
                "proof": {"e": str(proof_e), "z": str(proof_z)},
            })

        return jsonify({
            "keyper_id": keyper_meta["id"],
            "public_key_share": point_to_dict(mpk_k),
            "shares": results,
        })

    return app


def main():
    parser = argparse.ArgumentParser(description="Keyper server for threshold ElGamal voting")
    parser.add_argument("--id", type=int, required=True, help="Keyper ID (1-indexed)")
    parser.add_argument("--port", type=int, required=True, help="Port to listen on")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    args = parser.parse_args()

    app = create_keyper_app(args.id)
    print(f"[Keyper {args.id}] Starting on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
