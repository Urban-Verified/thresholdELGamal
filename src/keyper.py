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
import os
import sys
import requests
from flask import Flask, request, jsonify

from crypto.primitives import (
    point_to_dict, dict_to_point, CURVE_ORDER,
    g2_to_compressed, g2_from_compressed,
    point_multiply,
)
from crypto.dkg import KeyperDKGState, derive_joint_mpk, derive_mpk_share
from crypto.proofs import prove_decryption_share
from bulletin_board import BBClient
import sdk_compat


def create_keyper_app(keyper_id, *, chain_config=None):
    """Create a Flask app for a single keyper.

    ``chain_config`` is an optional dict ``{"rpc_url": str, "private_key": str}``
    that enables the on-chain DKG-publication endpoint. Without it, the
    keyper still participates in the off-chain DKG dance but cannot submit
    ``voteDKGResult``.
    """
    app = Flask(f"keyper_{keyper_id}")
    dkg_state = KeyperDKGState()
    keyper_meta = {"id": keyper_id, "chain_config": chain_config}
    # Stores shares generated in round1 for peer-to-peer distribution
    pending_shares = {}
    # Stores shares received from other keypers via peer-to-peer
    received_shares = {}
    # Snapshot of the commitments + dealer set used in the most recent
    # round-2 success. Reused by ``/dkg/publish_on_chain`` so the keyper
    # publishes the same DKG result it locally validated.
    last_round2 = {"all_commitments": None, "active_dealers": None}

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

        Posts commitments to the bulletin board (not returned to backend).
        Shares are kept locally for peer-to-peer distribution.
        """
        data = request.get_json()
        n = int(data["n"])
        t = int(data["t"])
        kid = int(data["keyper_id"])
        bb_url = data["bb_url"]
        election_id = data["election_id"]

        if kid != keyper_meta["id"]:
            return jsonify({"error": f"Keyper ID mismatch: configured as {keyper_meta['id']}, received {kid}"}), 400

        commitments, shares = dkg_state.round1(kid, n, t)

        # Store shares locally for peer-to-peer delivery
        pending_shares.clear()
        pending_shares.update(shares)
        received_shares.clear()

        # Post commitments to the bulletin board (anti-equivocation)
        bb = BBClient(bb_url)
        comms_dicts = [point_to_dict(c) for c in commitments]
        ok = bb.post(f"dkg/{election_id}/commitments", str(kid), comms_dicts)
        if not ok:
            return jsonify({"error": "Failed to post commitments to bulletin board"}), 500

        return jsonify({
            "keyper_id": kid,
            "status": "ok",
            # Commitments are on the bulletin board, not returned here
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
        """Receive a secret share from another keyper (peer-to-peer).

        Append-only: rejects a second share from the same dealer to prevent
        unauthenticated overwrite attacks (audit issue #1).
        """
        data = request.get_json()
        dealer_id = int(data["dealer_id"])
        share = int(data["share"])
        if share < 0 or share >= CURVE_ORDER:
            return jsonify({"error": "Share value out of scalar field range"}), 400
        if dealer_id in received_shares:
            return jsonify({"error": "Share already received from this dealer"}), 409
        received_shares[dealer_id] = share
        return jsonify({"status": "ok"})

    @app.route("/dkg/reveal_share", methods=["POST"])
    def reveal_share():
        """Reveal the share this dealer generated for a specific recipient.

        Used during complaint resolution (Feldman VSS rebuttal): the backend
        asks the accused dealer to publicly reveal the share it computed for
        the complaining keyper. All participants can then verify the share
        against the dealer's published commitments to determine who is at fault.
        """
        data = request.get_json()
        recipient_id = int(data["recipient_id"])
        if recipient_id not in pending_shares:
            return jsonify({"error": f"No pending share for recipient {recipient_id}"}), 404
        return jsonify({
            "dealer_id": keyper_meta["id"],
            "recipient_id": recipient_id,
            "share": str(pending_shares[recipient_id]),
        })

    @app.route("/dkg/round2", methods=["POST"])
    def dkg_round2():
        """DKG Round 2: Verify received shares and compute combined secret share.

        Reads commitments from the bulletin board (same view as everyone).
        Verifies the board digest matches the expected value to detect tampering.
        """
        data = request.get_json()
        bb_url = data["bb_url"]
        election_id = data["election_id"]
        expected_digest = data.get("expected_digest")

        # Read commitments from the bulletin board (anti-equivocation)
        bb = BBClient(bb_url)
        topic = f"dkg/{election_id}/commitments"

        # Verify digest if provided (cross-check with what backend computed)
        if expected_digest:
            actual_digest = bb.get_digest(topic)
            if actual_digest != expected_digest:
                return jsonify({
                    "keyper_id": keyper_meta["id"],
                    "verified": False,
                    "error": f"Bulletin board digest mismatch: expected {expected_digest}, got {actual_digest}",
                }), 200

        raw_entries = bb.read_topic(topic)

        # Parse commitments: {dealer_id_str: [G2 point dicts, ...]}
        all_commitments = {}
        for dealer_id_str, comms in raw_entries.items():
            all_commitments[int(dealer_id_str)] = [dict_to_point(c) for c in comms]

        try:
            combined_share, public_key_share = dkg_state.round2(all_commitments, received_shares)
        except ValueError as e:
            # Use structured bad_dealers attribute from DKG (no regex parsing)
            bad_dealers = getattr(e, "bad_dealers", [])
            return jsonify({
                "keyper_id": keyper_meta["id"],
                "verified": False,
                "complaints": bad_dealers,
                "error": str(e),
            }), 200  # 200 so backend can parse the complaint

        # Snapshot what we just consumed so a subsequent on-chain publish
        # uses the identical commitment set.
        last_round2["all_commitments"] = dict(all_commitments)
        last_round2["active_dealers"] = sorted(received_shares.keys())

        # Zeroize received shares after DKG completes.
        # Keep pending_shares alive until complaint resolution completes;
        # they will be cleared at the start of the next round1.
        received_shares.clear()

        return jsonify({
            "keyper_id": keyper_meta["id"],
            "public_key_share": point_to_dict(public_key_share),
            "verified": True,
        })

    @app.route("/dkg/publish_on_chain", methods=["POST"])
    def publish_on_chain():
        """Submit ``Election.voteDKGResult(pkElection, committeePKs)`` from this keyper.

        Reuses the commitments captured during the most recent successful
        round-2 so the on-chain submission matches what was locally validated.
        Each keyper computes the same joint mpk and the same ordered list of
        committee public keys; threshold-many matching submissions finalize
        the on-chain DKG result.
        """
        if keyper_meta["chain_config"] is None:
            return jsonify({"error": "Keyper not configured with chain credentials"}), 400

        if last_round2["all_commitments"] is None:
            return jsonify({"error": "No completed round-2 to publish; run DKG first"}), 400

        data = request.get_json() or {}
        election_address = data.get("election_address")
        if not election_address:
            return jsonify({"error": "Missing election_address"}), 400

        all_commitments = last_round2["all_commitments"]
        active_dealers = last_round2["active_dealers"]

        # The on-chain committee size is the number of members of the
        # KeyperSet, not the number of *active* DKG dealers. The keypers
        # voted into the keyperSet are 1..n; if some dealers were excluded
        # during complaint resolution, their commitments are absent from
        # ``all_commitments`` and the resulting mpk_shares for those slots
        # would still be computable from the surviving dealers.
        n = data.get("n") or len(active_dealers)

        try:
            pk_election_pt = derive_joint_mpk(all_commitments)
            pk_election = g2_to_compressed(pk_election_pt)
            committee_pks = []
            for k in range(1, n + 1):
                mpk_k = derive_mpk_share(k, all_commitments)
                committee_pks.append(g2_to_compressed(mpk_k))
        except Exception as e:
            return jsonify({"error": f"Failed to derive on-chain DKG result: {e}"}), 500

        # Lazy imports — these pull in web3 and require the chain to be up.
        from eth_account import Account
        from eth_client import ElectionClient, EthChain
        cfg = keyper_meta["chain_config"]
        chain = EthChain.connect(cfg["rpc_url"], private_key=cfg["private_key"])
        signer = Account.from_key(cfg["private_key"])
        election = ElectionClient(chain, election_address)

        # Skip if the threshold has already been reached by other keypers.
        # Without this guard ``voteDKGResult`` reverts with
        # ``AlreadyFinalized()``, which is the expected outcome of a race
        # between threshold submission and a late voter — not a real error.
        if election.is_dkg_finalized():
            return jsonify({
                "keyper_id": keyper_meta["id"],
                "tx_hash": None,
                "skipped": "dkg_already_finalized",
                "pk_election": pk_election.hex(),
                "committee_pks": [p.hex() for p in committee_pks],
                "dkg_finalized": True,
            })

        try:
            receipt = election.vote_dkg_result(pk_election, committee_pks, signer=signer)
        except Exception as e:
            # Re-check finalization state in case the revert was caused by a
            # concurrent submitter crossing the threshold during this call.
            if election.is_dkg_finalized():
                return jsonify({
                    "keyper_id": keyper_meta["id"],
                    "tx_hash": None,
                    "skipped": "dkg_finalized_during_submission",
                    "pk_election": pk_election.hex(),
                    "committee_pks": [p.hex() for p in committee_pks],
                    "dkg_finalized": True,
                })
            return jsonify({"error": f"voteDKGResult failed: {e}"}), 500

        return jsonify({
            "keyper_id": keyper_meta["id"],
            "tx_hash": receipt["transactionHash"].hex(),
            "block_number": int(receipt["blockNumber"]),
            "pk_election": pk_election.hex(),
            "committee_pks": [p.hex() for p in committee_pks],
            "dkg_finalized": election.is_dkg_finalized(),
        })

    @app.route("/decrypt/publish_on_chain", methods=["POST"])
    def publish_decryption_share():
        """Submit ``Election.submitDecryptionShare`` for this keyper.

        Reads the aggregate ciphertext that the tally aggregator published
        to ``Election.publishAggregate``, computes a partial decryption
        share per candidate, and proves correctness with a DLEQ under the
        SDK ``SHUTTER-VOTE-DECRYPT-v1`` transcript so SDK-built auditors
        can verify the bytes directly.

        Idempotent: if this keyper has already submitted, or if the
        aggregate hasn't been published yet, returns a structured response
        without raising.
        """
        if keyper_meta["chain_config"] is None:
            return jsonify({"error": "Keyper not configured with chain credentials"}), 400

        if dkg_state.combined_share is None:
            return jsonify({"error": "DKG not completed; cannot decrypt"}), 400

        data = request.get_json() or {}
        election_address = data.get("election_address")
        if not election_address:
            return jsonify({"error": "Missing election_address"}), 400

        from eth_account import Account
        from eth_client import ElectionClient, EthChain
        cfg = keyper_meta["chain_config"]
        chain = EthChain.connect(cfg["rpc_url"], private_key=cfg["private_key"])
        signer = Account.from_key(cfg["private_key"])
        election = ElectionClient(chain, election_address)

        if not election.is_dkg_finalized():
            return jsonify({"error": "On-chain DKG not finalized"}), 400

        # The contract requires ``block.timestamp >= votingEnd`` and the
        # tally aggregator must have published the aggregate first.
        try:
            aggregate = election.get_aggregate()
        except Exception as e:
            return jsonify({"error": f"Aggregate not yet published: {e}"}), 400

        election_id = election.election_id()
        num_candidates = election.num_candidates()
        ciphertexts = aggregate["aggregates"]
        if len(ciphertexts) != num_candidates:
            return jsonify({"error": f"Aggregate length {len(ciphertexts)} != numCandidates {num_candidates}"}), 500

        msk_k = dkg_state.combined_share
        mpk_k = dkg_state.public_key_share
        keyper_index = keyper_meta["id"]

        # One DLEQ per candidate, all under the SDK transcript shape.
        share_bytes_list: list[bytes] = []
        proofs: list[tuple[int, int]] = []
        for j in range(num_candidates):
            try:
                C1 = g2_from_compressed(ciphertexts[j][0])
                C2 = g2_from_compressed(ciphertexts[j][1])
            except Exception as e:
                return jsonify({"error": f"Aggregate ciphertext {j} invalid: {e}"}), 500

            sigma = point_multiply(C1, msk_k)
            t = sdk_compat.make_onchain_decrypt_transcript(election_id, j)
            e_scalar, z_scalar = sdk_compat.prove_decryption_share(
                t, C1, C2, mpk_k, sigma, msk_k, keyper_index,
            )
            share_bytes_list.append(g2_to_compressed(sigma))
            proofs.append((e_scalar, z_scalar))

        # Submit. If we (or someone with a stale concurrent call) already
        # submitted, the contract reverts with ``AlreadyVoted(address)``.
        # Convention: DKG keyper id k registers as keyperSet member k-1.
        our_member_index = keyper_index - 1
        try:
            receipt = election.submit_decryption_share(share_bytes_list, proofs, signer=signer)
        except Exception as e:
            existing = {s["keyperIndex"] for s in election.get_decryption_shares()}
            if our_member_index in existing:
                return jsonify({
                    "keyper_id": keyper_index,
                    "tx_hash": None,
                    "skipped": "already_submitted",
                    "shares_count": num_candidates,
                })
            return jsonify({"error": f"submitDecryptionShare failed: {e}"}), 500

        return jsonify({
            "keyper_id": keyper_index,
            "tx_hash": receipt["transactionHash"].hex(),
            "block_number": int(receipt["blockNumber"]),
            "shares_count": num_candidates,
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
    parser.add_argument("--rpc-url", default=None,
                        help="Ethereum RPC URL; required to publish DKG results on chain")
    parser.add_argument("--private-key", default=None,
                        help=("Hex private key with 0x prefix used to sign on-chain "
                              "DKG/decryption-share submissions. Prefer KEYPER_PRIVATE_KEY env var."))
    args = parser.parse_args()

    private_key = args.private_key or os.environ.get("KEYPER_PRIVATE_KEY")
    chain_config = None
    if args.rpc_url and private_key:
        chain_config = {"rpc_url": args.rpc_url, "private_key": private_key}

    app = create_keyper_app(args.id, chain_config=chain_config)
    suffix = " [chain enabled]" if chain_config else ""
    print(f"[Keyper {args.id}] Starting on {args.host}:{args.port}{suffix}")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
