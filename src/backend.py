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
import secrets
import threading
import requests
from flask import Flask, request, jsonify

from crypto.primitives import (
    CURVE_ORDER, G2, Z2,
    point_to_dict, dict_to_point, validate_g2_point,
    point_add, point_multiply, point_eq, is_identity,
)
from crypto.elgamal import aggregate_ciphertexts, threshold_decrypt
from crypto.proofs import verify_range, verify_exact_budget, verify_decryption_share


def _parse_scalar(value):
    """Parse an integer from JSON and validate it is in [0, CURVE_ORDER).

    Prevents DoS via astronomically large integers.
    """
    n = int(value)
    if n < 0 or n >= CURVE_ORDER:
        raise ValueError(f"Scalar {n} not in [0, CURVE_ORDER)")
    return n


def create_backend_app(keyper_urls):
    """Create the election backend Flask app."""
    app = Flask("election_backend")

    # Election state (protected by lock for thread safety)
    state = {
        "phase": "idle",  # idle -> setup -> voting -> tallying -> done
        "election_id": "",  # unique identifier bound into ZK proofs
        "mpk": None,       # G2 point
        "mpk_shares": {},  # {keyper_id: G2 point}
        "num_candidates": 0,
        "budget": 1,
        "candidate_names": [],
        "n": 0,  # number of keypers
        "t": 0,  # threshold (polynomial degree; need t+1 for decryption)
        "keyper_urls": list(keyper_urls),
        "active_keypers": [],  # keyper IDs that survived DKG (after complaint exclusion)
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
                "election_id": secrets.token_hex(16),
                "mpk": None,
                "mpk_shares": {},
                "active_keypers": [],
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

        # Track which keyper IDs are still participating
        active_kids = set(range(1, n + 1))
        max_retries = n - t - 1  # maximum dealers we can exclude and still have t+1

        for attempt in range(max_retries + 1):
            active_n = len(active_kids)
            if active_n < t + 1:
                return jsonify({
                    "error": f"DKG failed: only {active_n} honest keypers remain, need at least {t + 1}",
                }), 500

            # Build keyper URL map for active keypers only
            keyper_url_map = {kid: urls[kid - 1] for kid in active_kids}

            # --- Round 1: each keyper generates polynomial + commitments ---
            round1_data = {}
            for kid in sorted(active_kids):
                url = keyper_url_map[kid]
                try:
                    resp = requests.post(f"{url}/dkg/round1", json={
                        "n": active_n, "t": t, "keyper_id": kid,
                    }, timeout=30)
                    resp.raise_for_status()
                    round1_data[kid] = resp.json()
                except Exception as e:
                    return jsonify({"error": f"DKG Round 1 failed for keyper {kid}: {e}"}), 500

            # Collect all commitments and validate G2 group membership
            all_commitments_dicts = {}
            all_commitments_points = {}
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

            # --- Share distribution: keypers send shares P2P ---
            for kid in sorted(active_kids):
                url = keyper_url_map[kid]
                try:
                    resp = requests.post(f"{url}/dkg/distribute_shares", json={
                        "keyper_urls": {str(k): v for k, v in keyper_url_map.items()},
                    }, timeout=60)
                    resp.raise_for_status()
                except Exception as e:
                    return jsonify({"error": f"DKG share distribution failed for keyper {kid}: {e}"}), 500

            # --- Round 2: verify shares, collect complaints ---
            round2_results = {}
            all_complaints = {}  # {complainer_kid: [bad_dealer_ids]}
            for kid in sorted(active_kids):
                url = keyper_url_map[kid]
                try:
                    resp = requests.post(f"{url}/dkg/round2", json={
                        "all_commitments": {str(k): v for k, v in all_commitments_dicts.items()},
                    }, timeout=30)
                    resp.raise_for_status()
                    r2 = resp.json()
                    round2_results[kid] = r2
                    if not r2.get("verified"):
                        complaints = r2.get("complaints", [])
                        if complaints:
                            all_complaints[kid] = complaints
                        else:
                            return jsonify({"error": f"Keyper {kid} failed verification without complaint details"}), 500
                except Exception as e:
                    return jsonify({"error": f"DKG Round 2 failed for keyper {kid}: {e}"}), 500

            if not all_complaints:
                # All keypers verified successfully — DKG complete
                break

            # Identify malicious dealers: any dealer complained about by at least one honest keyper
            bad_dealers = set()
            for complainer, dealers in all_complaints.items():
                for d in dealers:
                    bad_dealers.add(d)

            print(f"[Backend] DKG attempt {attempt + 1}: complaints received against dealers {bad_dealers}, retrying without them")
            active_kids -= bad_dealers

            # If we removed too many, we can't continue
            if len(active_kids) < t + 1:
                return jsonify({
                    "error": f"DKG failed: only {len(active_kids)} honest keypers remain after excluding {bad_dealers}, need {t + 1}",
                    "excluded_keypers": sorted(bad_dealers),
                }), 500
        else:
            # Exhausted retries
            return jsonify({"error": "DKG failed: too many malicious keypers, could not complete"}), 500

        # --- Success path: derive keys from commitments of active keypers ---

        # Derive mpk_shares from public commitments (never trust self-reports):
        #   mpk_j = Σ_k Σ_i (j^i mod q) · γ_i^(k)  for k in active_kids
        mpk_shares = {}
        for j in sorted(active_kids):
            mpk_j = Z2
            for dealer_kid in sorted(active_kids):
                x_power = 1
                for i in range(t + 1):
                    mpk_j = point_add(mpk_j, point_multiply(all_commitments_points[dealer_kid][i], x_power))
                    x_power = (x_power * j) % CURVE_ORDER
            mpk_shares[j] = mpk_j

        # Compute master public key: sum of all γ₀ values (EC point addition)
        mpk = Z2
        for kid in sorted(active_kids):
            gamma_0 = all_commitments_points[kid][0]
            mpk = point_add(mpk, gamma_0)

        # Validate mpk is not identity (colluding keypers could cancel contributions)
        if is_identity(mpk):
            return jsonify({"error": "DKG produced identity master public key — possible collusion"}), 500

        # Validate each mpk_share is not identity
        for j, mpk_j in mpk_shares.items():
            if is_identity(mpk_j):
                return jsonify({"error": f"DKG produced identity public key share for keyper {j}"}), 500

        with state["lock"]:
            state["mpk"] = mpk
            state["mpk_shares"] = mpk_shares
            state["active_keypers"] = sorted(active_kids)
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
            "election_id": state["election_id"],
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
        election_id = state["election_id"]

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
            try:
                proof = [(_parse_scalar(branch["e"]), _parse_scalar(branch["z"])) for branch in proof_list]
            except (ValueError, KeyError) as e:
                return jsonify({"error": f"Invalid proof scalar: {e}"}), 400
            range_proofs.append(proof)

        # Parse budget proof (e, z) scalar pair
        bp_raw = data.get("budget_proof", {})
        try:
            budget_proof = (_parse_scalar(bp_raw["e"]), _parse_scalar(bp_raw["z"]))
        except (ValueError, KeyError) as e:
            return jsonify({"error": f"Invalid budget proof scalar: {e}"}), 400

        # --- Verify range proofs ---
        for j in range(num_cand):
            c1, c2 = ciphertexts[j]
            if not verify_range(mpk, c1, c2, range_proofs[j], B, election_id=election_id):
                return jsonify({"error": f"Range proof for candidate {j} is invalid"}), 400

        # --- Verify budget proof ---
        sum_ct = aggregate_ciphertexts(ciphertexts)
        if not verify_exact_budget(mpk, sum_ct[0], sum_ct[1], B, budget_proof, election_id=election_id):
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
        active_kids = state["active_keypers"]
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

        # --- Request decryption shares from active keypers only ---
        keyper_responses = []
        for kid in active_kids:
            url = urls[kid - 1]
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
            seen_kids = set()
            for kr in keyper_responses:
                kid = int(kr["keyper_id"])
                if kid in seen_kids:
                    continue
                seen_kids.add(kid)
                # Use the MPK share established during DKG, NOT the self-reported one
                mpk_k = state["mpk_shares"][kid]
                share_data = kr["shares"][j]
                sigma = dict_to_point(share_data["sigma"])
                try:
                    proof_e = _parse_scalar(share_data["proof"]["e"])
                    proof_z = _parse_scalar(share_data["proof"]["z"])
                except (ValueError, KeyError) as e:
                    print(f"[Backend] Warning: Invalid proof scalar from keyper {kid}: {e}")
                    continue

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
                "active_keypers": [],
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
