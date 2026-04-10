#!/usr/bin/env python3
"""
Election Backend Server — Manages elections, coordinates DKG, receives votes,
performs homomorphic aggregation, and orchestrates threshold decryption.

All cryptographic operations use BLS12-381 G2.

Usage:
    python backend.py --port 5000 --keyper-urls http://127.0.0.1:5001,http://127.0.0.1:5002,http://127.0.0.1:5003

Endpoints:
    POST /election/create           Create a new election
    POST /election/dkg              Run DKG across all registered keypers
    GET  /election/params           Get election public parameters
    POST /election/vote             Submit an encrypted vote with ZK proofs
    POST /election/tally            Aggregate votes and run threshold decryption
    GET  /election/result           Get the final tally
    GET  /election/status           Get current election state
    POST /election/reset            Reset election state
"""

import argparse
import json
import threading
import requests
from flask import Flask, request, jsonify

from crypto.primitives import (
    CURVE_ORDER, G2, Z2,
    point_to_dict, dict_to_point, validate_g2_point,
    point_add, point_eq, is_identity,
)
from crypto.elgamal import aggregate_ciphertexts, threshold_decrypt
from crypto.proofs import verify_range, verify_exact_budget, verify_decryption_share


def create_backend_app(keyper_urls):
    """Create the election backend Flask app."""
    app = Flask("election_backend")

    # Election state (protected by lock for thread safety)
    state = {
        "phase": "idle",  # idle -> setup -> voting -> tallying -> done
        "mpk": None,       # G2 point
        "mpk_shares": {},  # {keyper_id: G2 point}
        "num_candidates": 0,
        "budget": 1,
        "candidate_names": [],
        "n": 0,  # number of keypers
        "t": 0,  # threshold (polynomial degree; need t+1 for decryption)
        "keyper_urls": list(keyper_urls),
        "ballots": [],  # list of validated ballots (per-candidate ciphertexts as G2 point pairs)
        "result": None,
        "lock": threading.Lock(),
    }

    # ------------------------------------------------------------------
    #  POST /election/create
    # ------------------------------------------------------------------
    @app.route("/election/create", methods=["POST"])
    def create_election():
        data = request.get_json()
        n = int(data.get("n", len(state["keyper_urls"])))
        t = int(data.get("t", n // 2))
        num_candidates = int(data.get("num_candidates", 3))
        budget = int(data.get("budget", 1))
        candidate_names = data.get("candidate_names", [f"Candidate_{i}" for i in range(num_candidates)])

        if n < 1:
            return jsonify({"error": "Need at least 1 keyper"}), 400
        if t < 1 or t >= n:
            return jsonify({"error": "Threshold t must satisfy 1 <= t < n"}), 400
        if num_candidates < 1:
            return jsonify({"error": "Need at least 1 candidate"}), 400
        if len(state["keyper_urls"]) < n:
            return jsonify({"error": f"Only {len(state['keyper_urls'])} keyper URLs registered, need {n}"}), 400

        with state["lock"]:
            state.update({
                "phase": "setup",
                "mpk": None,
                "mpk_shares": {},
                "num_candidates": num_candidates,
                "budget": budget,
                "candidate_names": candidate_names[:num_candidates],
                "n": n,
                "t": t,
                "ballots": [],
                "result": None,
            })

        return jsonify({
            "status": "ok",
            "phase": "setup",
            "curve": "BLS12-381",
            "group": "G2",
            "curve_order": str(CURVE_ORDER),
            "n": n,
            "t": t,
            "num_candidates": num_candidates,
            "budget": budget,
            "candidate_names": state["candidate_names"],
        })

    # ------------------------------------------------------------------
    #  POST /election/dkg
    # ------------------------------------------------------------------
    @app.route("/election/dkg", methods=["POST"])
    def run_dkg():
        with state["lock"]:
            if state["phase"] != "setup":
                return jsonify({"error": f"Cannot run DKG in phase '{state['phase']}'"}), 400

        n, t = state["n"], state["t"]
        urls = state["keyper_urls"][:n]

        # --- Round 1: collect commitments and shares from all keypers ---
        round1_data = {}
        for idx, url in enumerate(urls):
            kid = idx + 1
            try:
                resp = requests.post(f"{url}/dkg/round1", json={
                    "n": n, "t": t, "keyper_id": kid,
                }, timeout=30)
                resp.raise_for_status()
                round1_data[kid] = resp.json()
            except Exception as e:
                return jsonify({"error": f"DKG Round 1 failed for keyper {kid}: {e}"}), 500

        # Collect all commitments and validate G2 group membership
        all_commitments_dicts = {}  # raw JSON dicts for forwarding
        all_commitments_points = {}  # parsed G2 points for validation
        for kid, d in round1_data.items():
            comms_dicts = d["commitments"]
            comms_points = []
            for c_dict in comms_dicts:
                try:
                    pt = dict_to_point(c_dict)
                    validate_g2_point(pt)
                    comms_points.append(pt)
                except ValueError as e:
                    return jsonify({"error": f"Invalid DKG commitment from keyper {kid}: {e}"}), 500
            all_commitments_dicts[kid] = comms_dicts
            all_commitments_points[kid] = comms_points

        # --- Round 2: distribute shares and verify ---
        mpk_shares = {}
        for idx, url in enumerate(urls):
            kid = idx + 1
            # Gather shares intended for this keyper from all dealers
            received_shares = {}
            for dealer_id, d in round1_data.items():
                received_shares[str(dealer_id)] = d["shares"][str(kid)]

            try:
                resp = requests.post(f"{url}/dkg/round2", json={
                    "all_commitments": {str(k): v for k, v in all_commitments_dicts.items()},
                    "received_shares": received_shares,
                }, timeout=30)
                resp.raise_for_status()
                r2 = resp.json()
                if not r2.get("verified"):
                    return jsonify({"error": f"Keyper {kid} failed share verification"}), 500
                mpk_shares[kid] = dict_to_point(r2["public_key_share"])
            except Exception as e:
                return jsonify({"error": f"DKG Round 2 failed for keyper {kid}: {e}"}), 500

        # Compute master public key: sum of all γ₀ values (EC point addition)
        mpk = Z2
        for kid in range(1, n + 1):
            gamma_0 = all_commitments_points[kid][0]
            mpk = point_add(mpk, gamma_0)

        with state["lock"]:
            state["mpk"] = mpk
            state["mpk_shares"] = mpk_shares
            state["phase"] = "voting"

        return jsonify({
            "status": "ok",
            "phase": "voting",
            "mpk": point_to_dict(mpk),
            "mpk_shares": {str(k): point_to_dict(v) for k, v in mpk_shares.items()},
        })

    # ------------------------------------------------------------------
    #  GET /election/params
    # ------------------------------------------------------------------
    @app.route("/election/params", methods=["GET"])
    def get_params():
        return jsonify({
            "phase": state["phase"],
            "curve": "BLS12-381",
            "group": "G2",
            "curve_order": str(CURVE_ORDER),
            "mpk": point_to_dict(state["mpk"]) if state["mpk"] else None,
            "num_candidates": state["num_candidates"],
            "budget": state["budget"],
            "candidate_names": state["candidate_names"],
            "n": state["n"],
            "t": state["t"],
        })

    # ------------------------------------------------------------------
    #  POST /election/vote
    # ------------------------------------------------------------------
    @app.route("/election/vote", methods=["POST"])
    def receive_vote():
        with state["lock"]:
            if state["phase"] != "voting":
                return jsonify({"error": f"Not accepting votes in phase '{state['phase']}'"}), 400

        data = request.get_json()
        mpk = state["mpk"]
        B = state["budget"]
        num_cand = state["num_candidates"]

        # Parse ciphertexts (pairs of G2 points)
        cts_raw = data.get("ciphertexts", [])
        if len(cts_raw) != num_cand:
            return jsonify({"error": f"Expected {num_cand} ciphertexts, got {len(cts_raw)}"}), 400

        ciphertexts = []
        for ct in cts_raw:
            try:
                c1 = dict_to_point(ct["c1"])
                c2 = dict_to_point(ct["c2"])
                validate_g2_point(c1)
                validate_g2_point(c2)
            except (ValueError, KeyError) as e:
                return jsonify({"error": f"Invalid ciphertext: {e}"}), 400
            ciphertexts.append((c1, c2))

        # Parse range proofs (list of (e, z) scalar pairs)
        range_proofs_raw = data.get("range_proofs", [])
        if len(range_proofs_raw) != num_cand:
            return jsonify({"error": f"Expected {num_cand} range proofs"}), 400

        range_proofs = []
        for proof_list in range_proofs_raw:
            proof = [(int(branch["e"]), int(branch["z"])) for branch in proof_list]
            range_proofs.append(proof)

        # Parse budget proof (e, z) scalar pair
        bp_raw = data.get("budget_proof", {})
        budget_proof = (int(bp_raw["e"]), int(bp_raw["z"]))

        # --- Verify range proofs ---
        for j in range(num_cand):
            c1, c2 = ciphertexts[j]
            if not verify_range(mpk, c1, c2, range_proofs[j], B):
                return jsonify({"error": f"Range proof for candidate {j} is invalid"}), 400

        # --- Verify budget proof ---
        sum_ct = aggregate_ciphertexts(ciphertexts)
        if not verify_exact_budget(mpk, sum_ct[0], sum_ct[1], B, budget_proof):
            return jsonify({"error": "Budget proof is invalid"}), 400

        # Store validated ballot
        with state["lock"]:
            state["ballots"].append(ciphertexts)

        ballot_num = len(state["ballots"])
        return jsonify({
            "status": "ok",
            "ballot_number": ballot_num,
            "message": f"Vote accepted (ballot #{ballot_num})",
        })

    # ------------------------------------------------------------------
    #  POST /election/tally
    # ------------------------------------------------------------------
    @app.route("/election/tally", methods=["POST"])
    def tally():
        with state["lock"]:
            if state["phase"] != "voting":
                return jsonify({"error": f"Cannot tally in phase '{state['phase']}'"}), 400
            state["phase"] = "tallying"

        mpk = state["mpk"]
        n, t = state["n"], state["t"]
        num_cand = state["num_candidates"]
        B = state["budget"]
        ballots = state["ballots"]
        urls = state["keyper_urls"][:n]

        if len(ballots) == 0:
            with state["lock"]:
                state["phase"] = "voting"
            return jsonify({"error": "No votes to tally"}), 400

        # --- Homomorphic aggregation per candidate ---
        aggregated = []
        for j in range(num_cand):
            candidate_cts = [(ballot[j][0], ballot[j][1]) for ballot in ballots]
            agg = aggregate_ciphertexts(candidate_cts)
            aggregated.append(agg)

        # Serialize aggregated C1 values for keypers
        agg_c1_dicts = [point_to_dict(agg[0]) for agg in aggregated]

        # --- Request decryption shares from all keypers ---
        keyper_responses = []
        for idx, url in enumerate(urls):
            kid = idx + 1
            try:
                resp = requests.post(f"{url}/decrypt", json={
                    "ciphertexts_c1": agg_c1_dicts,
                }, timeout=60)
                resp.raise_for_status()
                keyper_responses.append(resp.json())
            except Exception as e:
                print(f"[Backend] Warning: Keyper {kid} decryption failed: {e}")
                continue

        if len(keyper_responses) < t + 1:
            with state["lock"]:
                state["phase"] = "voting"
            return jsonify({"error": f"Not enough keyper responses: got {len(keyper_responses)}, need {t + 1}"}), 500

        # --- Verify DLEQ proofs and collect shares per candidate ---
        results = {}
        max_val = len(ballots) * B

        for j in range(num_cand):
            c1_j = aggregated[j][0]
            c2_j = aggregated[j][1]

            valid_shares = []
            for kr in keyper_responses:
                kid = int(kr["keyper_id"])
                mpk_k = dict_to_point(kr["public_key_share"])
                share_data = kr["shares"][j]
                sigma = dict_to_point(share_data["sigma"])
                proof_e = int(share_data["proof"]["e"])
                proof_z = int(share_data["proof"]["z"])

                if verify_decryption_share(c1_j, mpk_k, sigma, (proof_e, proof_z)):
                    valid_shares.append((kid, sigma))
                else:
                    print(f"[Backend] Warning: Invalid decryption proof from keyper {kid} for candidate {j}")

                if len(valid_shares) >= t + 1:
                    break

            if len(valid_shares) < t + 1:
                with state["lock"]:
                    state["phase"] = "voting"
                return jsonify({"error": f"Not enough valid decryption shares for candidate {j}"}), 500

            # Use exactly t+1 shares for decryption
            used_shares = valid_shares[:t + 1]
            tally_j = threshold_decrypt(c1_j, c2_j, used_shares, max_val)

            if tally_j is None:
                with state["lock"]:
                    state["phase"] = "voting"
                return jsonify({"error": f"Failed to decrypt tally for candidate {j}"}), 500

            results[j] = tally_j

        # Build result
        named_results = {}
        for j in range(num_cand):
            name = state["candidate_names"][j] if j < len(state["candidate_names"]) else f"Candidate_{j}"
            named_results[name] = results[j]

        with state["lock"]:
            state["result"] = named_results
            state["phase"] = "done"

        return jsonify({
            "status": "ok",
            "phase": "done",
            "total_ballots": len(ballots),
            "results": named_results,
        })

    # ------------------------------------------------------------------
    #  GET /election/result
    # ------------------------------------------------------------------
    @app.route("/election/result", methods=["GET"])
    def get_result():
        if state["result"] is None:
            return jsonify({"error": "No result available yet"}), 404
        return jsonify({
            "phase": state["phase"],
            "total_ballots": len(state["ballots"]),
            "results": state["result"],
        })

    # ------------------------------------------------------------------
    #  GET /election/status
    # ------------------------------------------------------------------
    @app.route("/election/status", methods=["GET"])
    def get_status():
        return jsonify({
            "phase": state["phase"],
            "num_candidates": state["num_candidates"],
            "budget": state["budget"],
            "candidate_names": state["candidate_names"],
            "n": state["n"],
            "t": state["t"],
            "ballots_received": len(state["ballots"]),
            "has_result": state["result"] is not None,
        })

    # ------------------------------------------------------------------
    #  POST /election/reset
    # ------------------------------------------------------------------
    @app.route("/election/reset", methods=["POST"])
    def reset():
        with state["lock"]:
            state.update({
                "phase": "idle",
                "mpk": None, "mpk_shares": {},
                "num_candidates": 0, "budget": 1,
                "candidate_names": [],
                "n": 0, "t": 0,
                "ballots": [],
                "result": None,
            })
        return jsonify({"status": "ok", "message": "Election reset"})

    return app


def main():
    parser = argparse.ArgumentParser(description="Election backend server")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--keyper-urls", required=True,
                        help="Comma-separated list of keyper URLs")
    args = parser.parse_args()

    keyper_urls = [u.strip() for u in args.keyper_urls.split(",")]
    app = create_backend_app(keyper_urls)
    print(f"[Backend] Starting on {args.host}:{args.port}")
    print(f"[Backend] Keyper URLs: {keyper_urls}")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
