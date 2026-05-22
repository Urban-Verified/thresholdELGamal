#!/usr/bin/env python3
"""
Wahlregister-Server (WR) oracle — dev stub for ballot attestations.

The production WR-Server signs an attestation that binds an election ID,
voter pseudonym, and ephemeral verification key (vk = sk · P₁) together,
asserting that the voter who registered ``vk`` is authorised to vote in
``electionId`` under that pseudonym. The on-chain ``Election`` stores
the WR's public key in ``pkWR``; ballot verifiers re-check the
attestation against that public key.

This dev oracle implements the same shape — Schnorr-signed attestation
on G₁ — but uses a single static WR keypair the dev runner controls,
and grants attestations to anyone who asks. **Not for production.** The
real WR-Server enforces voter eligibility, prevents double-attestation,
authenticates the requester (OIDC / Keycloak), and stores audit logs;
this stub does none of that.

Attestation byte layout — matches the binding the high-level concept
spells out in §3.3 verbatim ("Signatur_WR = Sign_WR(ElectionID ∥
Pseudonym ∥ PK_voter)"). The concept doc explicitly defers the
signature *algorithm* to a lower-level spec; we use Schnorr-on-G1
(BLS12-381) with keccak256 as a defensible dev choice — see TODO.md.

    encode_schnorr( schnorr_sign(
        wr_sk, wr_vk,
        keccak256( electionId || pseudonym || vk )
    ) )

Usage:
    python wr_oracle.py --private-key 0x... --port 5300
    GET  /status                   → {wr_vk: hex}
    POST /attest {electionId, pseudonym, vk}  → {attestation: hex}
"""

from __future__ import annotations

import argparse
import os

from eth_utils import keccak
from flask import Flask, jsonify, request

from sdk_compat import (
    encode_schnorr,
    schnorr_keygen,
    schnorr_sign,
)
from crypto.primitives import g1_to_compressed


def wr_attestation_message(election_id: bytes, pseudonym: bytes, vk_bytes: bytes) -> bytes:
    """The exact concatenation the German concept doc §3.3 specifies for
    the WR signature: ``ElectionID ∥ Pseudonym ∥ PK_voter`` — three parts,
    no domain-separation prefix. The signer keccak256's this before
    feeding it to Schnorr.
    """
    if len(election_id) != 32:
        raise ValueError("electionId must be 32 bytes")
    if len(pseudonym) != 32:
        raise ValueError("pseudonym must be 32 bytes")
    if len(vk_bytes) != 48:
        raise ValueError("vk must be 48 bytes")
    return election_id + pseudonym + vk_bytes


def issue_attestation(wr_sk: int, wr_vk, election_id: bytes,
                      pseudonym: bytes, vk_bytes: bytes) -> bytes:
    msg = keccak(wr_attestation_message(election_id, pseudonym, vk_bytes))
    R, s = schnorr_sign(wr_sk, wr_vk, msg)
    return encode_schnorr(R, s)


def create_wr_oracle_app(*, private_key: int) -> Flask:
    sk, vk = schnorr_keygen(private_key)
    app = Flask("wr_oracle")
    app._wr_state = {"sk": sk, "vk": vk}

    @app.route("/status", methods=["GET"])
    def status():
        return jsonify({
            "wr_vk": g1_to_compressed(vk).hex(),
        })

    @app.route("/attest", methods=["POST"])
    def attest():
        body = request.get_json(silent=True) or {}
        try:
            election_id = bytes.fromhex(body["electionId"].removeprefix("0x"))
            pseudonym = bytes.fromhex(body["pseudonym"].removeprefix("0x"))
            vk_bytes = bytes.fromhex(body["vk"].removeprefix("0x"))
        except (KeyError, ValueError) as e:
            return jsonify({"error": f"Bad request: {e}"}), 400

        try:
            attestation = issue_attestation(sk, vk, election_id, pseudonym, vk_bytes)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        return jsonify({
            "attestation": attestation.hex(),
            "wr_vk": g1_to_compressed(vk).hex(),
        })

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key", default=None,
                        help="WR Schnorr private key (hex). Prefer WR_PRIVATE_KEY env var.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5300)
    args = parser.parse_args()

    pk = args.private_key or os.environ.get("WR_PRIVATE_KEY")
    if not pk:
        parser.error("WR_PRIVATE_KEY (or --private-key) required")
    sk = int(pk, 16) if pk.startswith("0x") else int(pk, 16)

    app = create_wr_oracle_app(private_key=sk)
    pub = app._wr_state["vk"]
    print(f"[WR] vk={g1_to_compressed(pub).hex()}  on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
