#!/usr/bin/env python3
"""
Vote Proxy — dev-only ballot forwarder.

Receives a ``Ballot`` payload from a voter, packs it into the contract
struct, and submits it on chain via ``Election.submitVote``. The proxy
holds ``VOTE_PROXY_ROLE`` so the contract waives the ``selfSubmitFee``
and accepts ``msg.value == 0``.

This is **not** the production vote proxy. It performs no ballot
validation, no rate-limiting, and no voter authentication. The real
proxy is owned by another team (see PLAN.md §11 and TODO.md). Until then
this stub plus dummy ballot bytes (decision C) lets us exercise the full
on-chain lifecycle end-to-end.

Usage:
    python vote_proxy.py \\
        --rpc-url http://127.0.0.1:8545 \\
        --private-key 0x... \\
        --election 0x... \\
        --port 5400
"""

from __future__ import annotations

import argparse
import os

from eth_account import Account
from flask import Flask, jsonify, request

from eth_client import ElectionClient, EthChain


def _hexbytes(s: str) -> bytes:
    """Parse a 0x-prefixed (or bare) hex string into raw bytes."""
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    return bytes.fromhex(s)


def _parse_ballot(payload: dict) -> dict:
    """Convert the wire JSON into the dict shape ``ElectionClient.submit_vote`` expects."""
    cts_raw = payload.get("ciphertexts", [])
    ciphertexts: list[tuple[bytes, bytes]] = []
    for ct in cts_raw:
        ciphertexts.append((_hexbytes(ct["c1"]), _hexbytes(ct["c2"])))

    return {
        "pseudonym": _hexbytes(payload["pseudonym"]),
        "vk": _hexbytes(payload["vk"]),
        "ciphertexts": ciphertexts,
        "zkProof": _hexbytes(payload["zkProof"]),
        "voterSignature": _hexbytes(payload["voterSignature"]),
        "wrAttestation": _hexbytes(payload["wrAttestation"]),
    }


def create_vote_proxy_app(
    *,
    rpc_url: str,
    private_key: str,
    default_election_address: str | None = None,
) -> Flask:
    """Create the Flask app. ``default_election_address`` may be ``None`` if
    every request supplies its own ``election_address``.
    """
    app = Flask("vote_proxy")
    chain = EthChain.connect(rpc_url, private_key=private_key)
    signer = Account.from_key(private_key)
    app._vote_proxy_state = {
        "chain": chain,
        "signer": signer,
        "default_election": default_election_address,
    }

    @app.route("/status", methods=["GET"])
    def status():
        return jsonify({
            "proxy_address": signer.address,
            "rpc_url": rpc_url,
            "chain_id": chain.chain_id,
            "default_election": default_election_address,
        })

    @app.route("/vote", methods=["POST"])
    def vote():
        body = request.get_json(silent=True) or {}
        election_address = body.get("election_address") or default_election_address
        if not election_address:
            return jsonify({"error": "Missing election_address"}), 400

        ballot_json = body.get("ballot")
        if not ballot_json:
            return jsonify({"error": "Missing ballot"}), 400

        try:
            ballot = _parse_ballot(ballot_json)
        except (KeyError, ValueError) as e:
            return jsonify({"error": f"Malformed ballot: {e}"}), 400

        election = ElectionClient(chain, election_address)
        try:
            receipt = election.submit_vote(ballot, signer=signer, value=0)
        except Exception as e:
            return jsonify({"error": f"submitVote reverted: {e}"}), 502

        # Pull the emitted VoteSubmitted event for the ballot index.
        own_logs = [lg for lg in receipt["logs"]
                    if lg["address"].lower() == election.address.lower()]
        events = election.contract.events.VoteSubmitted().process_receipt({"logs": own_logs})
        ballot_index = int(events[0]["args"]["ballotIndex"]) if events else None

        return jsonify({
            "tx_hash": receipt["transactionHash"].hex(),
            "block_number": int(receipt["blockNumber"]),
            "ballot_index": ballot_index,
            "election_address": election_address,
        })

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--private-key", default=None,
                        help="Hex private key. Prefer VOTE_PROXY_PRIVATE_KEY env var.")
    parser.add_argument("--election", default=None,
                        help="Default Election address; clients may override per-request.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5400)
    args = parser.parse_args()

    private_key = args.private_key or os.environ.get("VOTE_PROXY_PRIVATE_KEY")
    if not private_key:
        parser.error("VOTE_PROXY_PRIVATE_KEY (or --private-key) required")

    app = create_vote_proxy_app(
        rpc_url=args.rpc_url,
        private_key=private_key,
        default_election_address=args.election,
    )
    print(f"[VoteProxy] {Account.from_key(private_key).address} on {args.host}:{args.port} → {args.rpc_url}")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
