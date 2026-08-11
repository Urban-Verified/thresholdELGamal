#!/usr/bin/env python3
"""
Keyper Server — Individual threshold committee member.

Each keyper runs as an independent HTTP server and participates in:
  1. Distributed Key Generation (DKG) — generates secret share, verifies others' shares
  2. Partial Decryption — computes decryption shares with DLEQ correctness proofs

All operations use BLS12-381 G2.

Usage:
    KEYPER_PRIVATE_KEY=0x... python keyper.py --port 5001

A keyper's DKG index is resolved by the coordinator from the on-chain KeyperSet
(matching this keyper's own signing address) and adopted at /dkg/round1 time.
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import secrets
import sys
import time
import requests
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify

# Empty string = single-operator dev mode; before_request guard is a no-op.
# Non-empty = multi-operator mode; bearer tokens are minted by dkg-coordinator
# and installed at runtime via POST /auth/bootstrap, never read from an env
# var. See docker/README.md "Auth & bootstrap" (mirrors sx-monorepo's design).
COORDINATOR_ADDRESS = os.environ.get("COORDINATOR_ADDRESS", "")
AUTH_REQUIRED = bool(COORDINATOR_ADDRESS)

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak

from crypto.primitives import (
    point_to_dict, dict_to_point, CURVE_ORDER, G2,
    g2_to_compressed, g2_from_compressed,
    point_multiply,
)
from crypto.dkg import KeyperDKGState, derive_joint_mpk, derive_mpk_share
from keyper_persistence import (
    load_bootstrap_tokens,
    load_dkg_secret,
    load_or_create_encryption_key,
    save_bootstrap_tokens,
    save_dkg_secret,
)
from token_bootstrap import (
    NonceTracker, enc_pubkey_hash, payload_hash, verify_encryption_pubkey,
    x25519_seal, x25519_unseal,
)
import sdk_compat


# ----------------------------------------------------------------------
#  P2P signed-message helpers
#
#  Every keyper-to-keyper DKG message (commitments, shares, share
#  reveals during complaint resolution) is signed with the dealer's
#  Ethereum keyper key. Receivers verify the signature against the
#  member address at the dealer's index in ``KeyperSet`` (passed in via
#  /dkg/round1). Replaces the old anti-equivocation guarantee that the
#  bulletin board provided.
# ----------------------------------------------------------------------

_DST_COMMITMENTS = b"DKG-COMMITMENTS-v1"
_DST_SHARE = b"DKG-SHARE-v1"
_DST_REVEAL = b"DKG-REVEAL-v1"
_DST_ACCUSE = b"DKG-ACCUSE-v1"
# Domain tag prefixed to the *plaintext* inside a sealed share box, so a
# sealed share can never be unsealed and interpreted as some other sealed
# payload (e.g. an /auth/bootstrap envelope, which uses the same X25519 key).
_DST_SHARE_SEAL = b"DKG-SHARE-SEAL-v1"


def seal_share(share: int, recipient_pubkey) -> str:
    """Seal a secret DKG share to a recipient keyper's X25519 public key
    (anonymous sealed box), returning base64 for JSON transport.

    Confidentiality only -- authenticity/binding to (election, dealer,
    recipient) comes from the dealer's separate EIP-191 signature over the
    plaintext share value, exactly as before. The plaintext is domain-tagged
    (``_DST_SHARE_SEAL``) so it cannot be cross-interpreted as another sealed
    payload type that uses the same key.
    """
    plaintext = _DST_SHARE_SEAL + (share % CURVE_ORDER).to_bytes(32, "big")
    return base64.b64encode(x25519_seal(plaintext, recipient_pubkey)).decode()


def unseal_share(sealed_b64: str, recipient_privkey) -> int:
    """Inverse of :func:`seal_share`. Raises on a tampered box (AES-GCM auth
    failure), a wrong recipient key, or a domain-tag / length mismatch."""
    plaintext = x25519_unseal(base64.b64decode(sealed_b64), recipient_privkey)
    if not plaintext.startswith(_DST_SHARE_SEAL):
        raise ValueError("sealed share domain-tag mismatch")
    body = plaintext[len(_DST_SHARE_SEAL):]
    if len(body) != 32:
        raise ValueError("sealed share has unexpected length")
    return int.from_bytes(body, "big")


def _build_share_body(election_id: str, dealer_id: int, recipient_id: int,
                      share: int, signing_key: str, recipient_enc_pubkey) -> dict:
    """Build the ``/dkg/receive_share`` request body for one recipient.

    Always signs the plaintext share value (authenticity/binding, unchanged).
    Seals the value to ``recipient_enc_pubkey`` when it is provided (the
    multi-operator path, so nothing secret is on the wire); falls back to a
    plaintext ``share`` only when it is ``None`` -- single-operator dev mode,
    which is loopback/in-process and has no peer key to seal to.
    """
    signature = _sign(signing_key, _share_payload_hash(election_id, dealer_id, recipient_id, share))
    body = {
        "election_id": election_id,
        "dealer_id": dealer_id,
        "recipient_id": recipient_id,
        "signature": signature,
    }
    if recipient_enc_pubkey is not None:
        body["sealed_share"] = seal_share(share, recipient_enc_pubkey)
    else:
        body["share"] = str(share)
    return body


def _commitments_payload_hash(election_id: str, dealer_id: int, commitments) -> bytes:
    parts = [
        _DST_COMMITMENTS,
        len(election_id).to_bytes(4, "big"),
        election_id.encode("utf-8"),
        dealer_id.to_bytes(8, "big"),
        len(commitments).to_bytes(4, "big"),
    ]
    for c in commitments:
        parts.append(g2_to_compressed(c))
    return keccak(b"".join(parts))


def _share_payload_hash(election_id: str, dealer_id: int, recipient_id: int, share: int) -> bytes:
    parts = [
        _DST_SHARE,
        len(election_id).to_bytes(4, "big"),
        election_id.encode("utf-8"),
        dealer_id.to_bytes(8, "big"),
        recipient_id.to_bytes(8, "big"),
        (share % CURVE_ORDER).to_bytes(32, "big"),
    ]
    return keccak(b"".join(parts))


def _reveal_payload_hash(election_id: str, dealer_id: int, recipient_id: int, share: int) -> bytes:
    parts = [
        _DST_REVEAL,
        len(election_id).to_bytes(4, "big"),
        election_id.encode("utf-8"),
        dealer_id.to_bytes(8, "big"),
        recipient_id.to_bytes(8, "big"),
        (share % CURVE_ORDER).to_bytes(32, "big"),
    ]
    return keccak(b"".join(parts))


def _accusation_payload_hash(election_id: str, accused_dealer_id: int, recipient_id: int) -> bytes:
    """Payload a complaining recipient signs to accuse a dealer of dealing a
    bad share. Bound to the election and to the specific (accused dealer,
    recipient) pair so it can neither be replayed across elections nor
    redirected to unlock a different dealer's share. Carries no share value:
    the accusation only *authorizes* a reveal, it does not disclose one."""
    parts = [
        _DST_ACCUSE,
        len(election_id).to_bytes(4, "big"),
        election_id.encode("utf-8"),
        accused_dealer_id.to_bytes(8, "big"),
        recipient_id.to_bytes(8, "big"),
    ]
    return keccak(b"".join(parts))


def _sign(private_key: str, payload_hash: bytes) -> str:
    """EIP-191 personal-sign over a 32-byte payload hash; returns hex sig."""
    acct = Account.from_key(private_key)
    msg = encode_defunct(primitive=payload_hash)
    signed = acct.sign_message(msg)
    return signed.signature.hex()


def _recover(payload_hash: bytes, signature_hex: str) -> str:
    msg = encode_defunct(primitive=payload_hash)
    return Account.recover_message(msg, signature=bytes.fromhex(signature_hex.removeprefix("0x")))


# ----------------------------------------------------------------------
#  DKG secret / bootstrap-token persistence — see keyper_persistence.py
#
#  Fernet key is derived from this keyper's own signing key so no
#  separate secret needs to be provisioned just for state encryption.
# ----------------------------------------------------------------------

def _derive_fernet(private_key_hex: str) -> Fernet:
    raw = bytes.fromhex(private_key_hex.removeprefix('0x'))
    key = base64.urlsafe_b64encode(hashlib.sha256(b'KEYPER-DKG-STATE-v1' + raw).digest())
    return Fernet(key)


def create_keyper_app(keyper_id=None, *, chain_config=None, signing_key=None):
    """Create a Flask app for a single keyper.

    ``chain_config`` is an optional dict ``{"rpc_url": str, "private_key": str}``
    that enables the on-chain DKG-publication endpoint.

    ``signing_key`` is the Ethereum private key used to sign P2P DKG
    messages (commitments, shares, reveals). If omitted but
    ``chain_config`` is provided, the chain key doubles as the signing
    key. If neither is provided, a deterministic key is derived from
    ``keyper_id`` so off-chain dev runs and tests still work (this path
    requires ``keyper_id`` -- the real deployment path always supplies a
    real signing key instead).

    ``keyper_id`` is optional and, for the real deployment path, normally
    omitted entirely: a keyper's DKG index is not statically configured
    -- it's resolved by the coordinator from the on-chain KeyperSet
    (matching this keyper's own signing address) and adopted the first
    time /dkg/round1 is called, or restored from persisted state on
    restart. Passing an explicit ``keyper_id`` remains supported for
    admin_tui.py's in-process demo and this package's own tests, which
    already know their own index a priori from local, non-chain setup.
    """
    if signing_key is None:
        if chain_config is not None:
            signing_key = chain_config["private_key"]
        elif keyper_id is not None:
            # Deterministic dev fallback so off-chain test runs work
            # without explicit chain config.
            seed = hashlib.sha256(f"keyper-{keyper_id}".encode()).digest()
            signing_key = "0x" + seed.hex()
        else:
            raise ValueError(
                "create_keyper_app requires signing_key, chain_config, or keyper_id "
                "(the last only as a seed for the deterministic dev fallback key)"
            )
    signing_address = Account.from_key(signing_key).address
    # Persisted state is namespaced by this keyper's own signing address,
    # not its (possibly still-unknown) DKG index -- see keyper_persistence.py.
    identity = signing_address
    logger = logging.getLogger(f'keyper.{signing_address[:10]}')

    app = Flask(f"keyper_{signing_address[:10]}")
    start_time = time.time()

    # This keyper's outbound address book -- {kid_str: {"url", "token"}} for
    # every *other* keyper -- both where to reach it and what to authenticate
    # with, from the same trusted source. Delivered by POST /auth/bootstrap
    # (not /dkg/round1 -- DKG endpoints carry no auth material or destination
    # data at all), and persisted to disk alongside this keyper's own tokens
    # so a restart needs no re-bootstrap.
    peers: dict[str, dict[str, str]] = {}

    # This keyper's own required inbound credentials, installed by
    # POST /auth/bootstrap. None until the first successful bootstrap --
    # the guard below must fail closed on None, not skip the check.
    installed: dict[str, str | None] = {"api_token": None, "peer_token": None}
    bootstrap_nonces = NonceTracker()

    # Routes only ever called by other keypers (P2P), never the coordinator
    # or tally-aggregator -- checked against installed["peer_token"].
    PEER_ROUTES = {"/dkg/receive_commitments", "/dkg/receive_share"}
    # Called by the tally-aggregator (holds the same coordinator/API token
    # dkg-coordinator does -- no separate token type for it, see
    # keyper-token-bootstrap.md "Token Scoping") as well as the coordinator
    # itself -- accepts either token.
    DUAL_ROUTES = {"/decrypt/publish_on_chain"}
    # Always reachable regardless of auth state -- /status and /health are
    # health probes, /auth/bootstrap necessarily has to be reachable before
    # any token exists to check against.
    OPEN_ROUTES = {"/status", "/health", "/auth/bootstrap"}

    @app.before_request
    def require_bearer():
        if not AUTH_REQUIRED:
            return  # single-operator dev mode — no auth enforced
        if request.path in OPEN_ROUTES:
            return
        tok = request.headers.get("Authorization", "")
        if not tok.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        presented = tok[7:]

        if request.path in PEER_ROUTES:
            expected = installed["peer_token"]
            ok = expected is not None and secrets.compare_digest(presented, expected)
        elif request.path in DUAL_ROUTES:
            api_tok, peer_tok = installed["api_token"], installed["peer_token"]
            ok = (api_tok is not None and secrets.compare_digest(presented, api_tok)) or \
                 (peer_tok is not None and secrets.compare_digest(presented, peer_tok))
        else:
            expected = installed["api_token"]
            ok = expected is not None and secrets.compare_digest(presented, expected)

        if not ok:
            # Uniform 401 whether the cause is "wrong token" or "no token
            # installed yet" -- don't give a prober an oracle for which.
            return jsonify({"error": "Unauthorized"}), 401

    def _peer_auth_headers(recipient_id_str: str) -> dict:
        """Auth header to attach when calling a peer keyper identified by its id string."""
        tok = peers.get(str(recipient_id_str), {}).get("token", "")
        return {"Authorization": f"Bearer {tok}"} if tok else {}

    fernet = _derive_fernet(signing_key)
    encryption_privkey = load_or_create_encryption_key(fernet, identity, logger)
    encryption_pubkey_bytes = encryption_privkey.public_key().public_bytes_raw()
    encryption_pubkey_hex = "0x" + encryption_pubkey_bytes.hex()
    encryption_pubkey_sig = _sign(signing_key, enc_pubkey_hash(encryption_pubkey_bytes))
    # Restore a prior bootstrap so a restart needs no re-push at all: no
    # rotation happens, tokens are minted once and persisted on both sides.
    _persisted_tokens = load_bootstrap_tokens(fernet, identity, logger)
    if _persisted_tokens:
        installed["api_token"] = _persisted_tokens.get("api_token")
        installed["peer_token"] = _persisted_tokens.get("peer_token")
        peers.update(_persisted_tokens.get("peers") or {})

    dkg_state = KeyperDKGState()
    keyper_meta = {
        # None until adopted from the coordinator's /dkg/round1 call (or
        # restored below from a completed prior ceremony) -- see the
        # module docstring and create_keyper_app's own docstring.
        "id": keyper_id,
        "chain_config": chain_config,
        "signing_key": signing_key,
        "signing_address": signing_address,
    }
    # Per-DKG context: members[i] is the eth address of keyper id i+1 in
    # the KeyperSet, used to verify P2P signatures from that dealer. The
    # election_id scopes the signed payload to a specific DKG instance.
    dkg_meta = {"election_id": None, "members": []}
    # Restore a completed DKG's combined share (and the index it was
    # assigned) so a restart doesn't need a fresh ceremony -- see
    # keyper_persistence.dkg_secret_file. Without restoring keyper_id
    # here too, a restarted keyper would have keyper_meta["id"] = None
    # forever (dkg-runner.sh skips round1 once DKG is already finalized
    # on-chain, so there's no second chance to relearn it from the
    # coordinator) and every subsequent decrypt-share submission would break.
    _persisted_dkg = load_dkg_secret(fernet, identity, logger)
    if _persisted_dkg:
        dkg_state.combined_share = _persisted_dkg["share"]
        dkg_state.public_key_share = point_multiply(G2, _persisted_dkg["share"])
        dkg_meta["election_id"] = _persisted_dkg["election_id"]
        keyper_meta["id"] = _persisted_dkg["keyper_id"]
    # Local share storage (P2P).
    pending_shares = {}            # generated by us in round1, indexed by recipient_id
    received_shares = {}           # received from other keypers, indexed by dealer_id
    received_commitments = {}      # received commitments from peers, indexed by dealer_id
    # Snapshot of the commitments + dealer set used in the most recent
    # round-2 success. Reused by ``/dkg/publish_on_chain`` so the keyper
    # publishes the same DKG result it locally validated.
    last_round2 = {"all_commitments": None, "active_dealers": None}

    def _members_addr(dealer_id: int) -> str | None:
        idx = dealer_id - 1
        if 0 <= idx < len(dkg_meta["members"]):
            return dkg_meta["members"][idx]
        return None

    @app.route("/status", methods=["GET"])
    def status():
        return jsonify({
            "keyper_id": keyper_meta["id"],
            "address": keyper_meta["signing_address"],
            "dkg_completed": dkg_state.combined_share is not None,
            "public_key_share": point_to_dict(dkg_state.public_key_share) if dkg_state.public_key_share else None,
            # Bound to signing_address via encryption_pubkey_sig so the
            # coordinator can trust this key without a separate exchange.
            "encryption_pubkey": encryption_pubkey_hex,
            "encryption_pubkey_sig": encryption_pubkey_sig,
            # Non-sensitive operator-visibility flag.
            "bootstrapped": installed["api_token"] is not None,
        })

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "ok": True,
            "dkg_in_progress": dkg_meta["election_id"] is not None and dkg_state.combined_share is None,
            "uptime_s": int(time.time() - start_time),
        })

    @app.route("/auth/bootstrap", methods=["POST"])
    def auth_bootstrap():
        """Coordinator-pushed token installation.

        Necessarily unauthenticated at the HTTP layer -- this call
        establishes the very credentials every other route checks.
        Authenticity instead comes from the EIP-191 signature embedded in
        the sealed payload, verified against COORDINATOR_ADDRESS -- an
        anonymous sealed box alone proves nothing about the sender, only
        that this keyper's own private key was used to open it.
        """
        if not AUTH_REQUIRED:
            return jsonify({"error": "bootstrap not applicable in single-operator mode"}), 400

        try:
            plaintext = x25519_unseal(request.get_data(), encryption_privkey)
            envelope = json.loads(plaintext)
            payload = envelope["payload"]
            sig = envelope["sig"]
        except Exception:
            return jsonify({"error": "Unauthorized"}), 401

        try:
            recovered = _recover(payload_hash(payload), sig)
        except Exception:
            return jsonify({"error": "Unauthorized"}), 401
        if recovered.lower() != COORDINATOR_ADDRESS.lower():
            return jsonify({"error": "Unauthorized"}), 401
        if str(payload.get("intended_recipient", "")).lower() != keyper_meta["signing_address"].lower():
            return jsonify({"error": "Unauthorized"}), 401
        if not bootstrap_nonces.check_and_record(payload.get("nonce", ""), int(payload.get("timestamp", 0))):
            return jsonify({"error": "Unauthorized"}), 401

        installed["api_token"] = str(payload["api_token"])
        installed["peer_token"] = str(payload["peer_token"])
        peers.clear()
        peers.update({
            str(k): {
                "url": str(v["url"]),
                "token": str(v["token"]),
                # Preserve the peer's X25519 key + binding sig so shares can be
                # sealed to it (verified against its member address at send time).
                **({"enc_pubkey": str(v["enc_pubkey"])} if v.get("enc_pubkey") else {}),
                **({"enc_pubkey_sig": str(v["enc_pubkey_sig"])} if v.get("enc_pubkey_sig") else {}),
            }
            for k, v in (payload.get("peers") or {}).items()
        })
        save_bootstrap_tokens(fernet, identity, installed["api_token"], installed["peer_token"], dict(peers))
        logger.info("op=auth_bootstrap status=ok signer=%s", recovered)
        return jsonify({"status": "ok"})

    @app.route("/dkg/round1", methods=["POST"])
    def dkg_round1():
        """DKG Round 1: generate polynomial, commitments, and shares locally.

        Replaces the bulletin-board-anchored flow: commitments are kept
        locally and fanned out P2P via /dkg/distribute_commitments. The
        request body must include the keyper-set ``members`` (eth
        addresses, in member-index order) so this keyper can verify
        signatures on incoming P2P messages from other dealers.
        """
        data = request.get_json()
        n = int(data["n"])
        t = int(data["t"])
        kid = int(data["keyper_id"])
        election_id = data["election_id"]
        members = data.get("members", [])

        # There is no statically-configured index to check against in the
        # real deployment path (keyper_meta["id"] starts None) -- this
        # keyper simply adopts whatever index the coordinator assigns,
        # since the coordinator resolves it from the on-chain KeyperSet
        # (KeyperSet.getMemberIndex against this keyper's own signing
        # address) rather than from KEYPER_URLS list position. Callers
        # that *do* pass an explicit keyper_id up front (admin_tui.py's
        # in-process demo, this package's own tests) keep a real
        # mismatch check -- a genuine misconfiguration there still fails loudly.
        if keyper_meta["id"] is not None and kid != keyper_meta["id"]:
            return jsonify({"error": f"Keyper ID mismatch: configured as {keyper_meta['id']}, received {kid}"}), 400
        keyper_meta["id"] = kid
        if not isinstance(members, list) or len(members) != n:
            return jsonify({"error": f"members must be a list of {n} addresses, got {len(members)}"}), 400

        # Reset DKG state for this fresh run.
        commitments, shares = dkg_state.round1(kid, n, t)
        pending_shares.clear()
        pending_shares.update(shares)
        received_shares.clear()
        received_commitments.clear()
        # Our own commitments count as received from ourselves.
        received_commitments[kid] = list(commitments)

        # Pin the DKG context so subsequent endpoints can verify
        # signatures and reject messages from other elections.
        dkg_meta["election_id"] = election_id
        # ``members`` are 0x-prefixed mixed-case checksummed strings; the
        # ``Account.recover_message`` return matches that shape, and we
        # compare case-insensitively in the verify path anyway.
        dkg_meta["members"] = list(members)

        return jsonify({
            "keyper_id": kid,
            "status": "ok",
            # Backend gets our commitments via the response so it can build
            # its own off-chain view (used for off-chain mpk derivation and
            # cross-checking what each keyper reports it received).
            "commitments": [point_to_dict(c) for c in commitments],
        })

    @app.route("/dkg/distribute_commitments", methods=["POST"])
    def distribute_commitments():
        """Send our round-1 commitments to every other keyper, signed.

        Each peer's /dkg/receive_commitments verifies the signature
        against ``KeyperSet.getMember(kid - 1)``, replacing the bulletin
        board's anti-equivocation guarantee with a per-message
        unforgeability one. Equivocation across recipients still requires
        the dealer to produce two different signed messages for two
        different views — a real-time receiver-side cross-check (phase 2)
        would catch that locally; for phase 1 the on-chain
        ``voteDKGResult`` threshold-vote does so by failing to finalize.
        """
        data = request.get_json(silent=True) or {}
        kid = keyper_meta["id"]

        if dkg_meta["election_id"] is None:
            return jsonify({"error": "Run /dkg/round1 first"}), 400

        commitments = dkg_state.commitments
        payload_hash = _commitments_payload_hash(dkg_meta["election_id"], kid, commitments)
        signature = _sign(keyper_meta["signing_key"], payload_hash)
        body = {
            "election_id": dkg_meta["election_id"],
            "dealer_id": kid,
            "commitments": [point_to_dict(c) for c in commitments],
            "signature": signature,
        }

        if AUTH_REQUIRED:
            # Fan out to the bootstrap-installed peers map -- never anything
            # the request body supplies, so there's no destination data an
            # attacker holding a leaked coordinator-tier token could redirect.
            targets = {
                rid: {"url": p["url"], "headers": _peer_auth_headers(rid)}
                for rid, p in peers.items()
            }
        else:
            # Single-operator dev mode (e.g. admin_tui.py's in-process demo,
            # no coordinator ever bootstraps a peers map) -- no
            # coordinator-tier token exists to leak, so the caller-supplied
            # address book is safe to trust directly, same as before.
            targets = {
                rid: {"url": url, "headers": {}}
                for rid, url in (data.get("keyper_urls") or {}).items()
                if int(rid) != kid
            }

        for recipient_id_str, target in targets.items():
            recipient_id = int(recipient_id_str)
            try:
                resp = requests.post(f"{target['url']}/dkg/receive_commitments", json=body,
                                      headers=target["headers"], timeout=10)
                resp.raise_for_status()
            except Exception as e:
                return jsonify({
                    "error": f"Failed to send commitments to keyper {recipient_id}: {e}",
                }), 500

        return jsonify({"status": "ok"})

    @app.route("/dkg/receive_commitments", methods=["POST"])
    def receive_commitments():
        """Receive signed commitments from another keyper.

        Append-only: a second post from the same dealer is rejected so a
        real dealer that posted first cannot be overwritten by a later
        forgery (the signature check below already rules out forgeries
        from non-dealer parties).
        """
        data = request.get_json()
        try:
            election_id = data["election_id"]
            dealer_id = int(data["dealer_id"])
            commitments_dicts = data["commitments"]
            sig_hex = data["signature"]
        except (KeyError, ValueError, TypeError) as e:
            return jsonify({"error": f"Bad request: {e}"}), 400

        if election_id != dkg_meta.get("election_id"):
            return jsonify({"error": "Election ID mismatch"}), 400
        if dealer_id in received_commitments:
            return jsonify({"error": "Commitments already received from this dealer"}), 409

        try:
            commitments = [dict_to_point(c) for c in commitments_dicts]
        except Exception as e:
            return jsonify({"error": f"Invalid commitment point: {e}"}), 400

        expected = _members_addr(dealer_id)
        if expected is None:
            return jsonify({"error": f"Unknown dealer_id {dealer_id}"}), 400
        payload_hash = _commitments_payload_hash(election_id, dealer_id, commitments)
        try:
            recovered = _recover(payload_hash, sig_hex)
        except Exception as e:
            return jsonify({"error": f"Signature recover failed: {e}"}), 401
        if recovered.lower() != expected.lower():
            return jsonify({
                "error": f"Bad signature: expected {expected}, recovered {recovered}",
            }), 401

        received_commitments[dealer_id] = commitments
        return jsonify({"status": "ok"})

    @app.route("/dkg/distribute_shares", methods=["POST"])
    def distribute_shares():
        """Send our secret shares directly to each recipient keyper, signed."""
        data = request.get_json(silent=True) or {}
        kid = keyper_meta["id"]

        if dkg_meta["election_id"] is None:
            return jsonify({"error": "Run /dkg/round1 first"}), 400

        # Our own share never leaves the process -- store it directly.
        received_shares[kid] = pending_shares[kid]

        if AUTH_REQUIRED:
            # Fan out to the bootstrap-installed peers map -- never anything
            # the request body supplies, so there's no destination data an
            # attacker holding a leaked coordinator-tier token could redirect.
            # Each share is sealed to the recipient's X25519 key (C-1 Leg A) so
            # nothing secret is on the wire. The key rides in the peers map, but
            # we verify it against the recipient's *on-chain* member address
            # before sealing -- so even a lying coordinator can at most cause a
            # DoS (share sealed to the real key, sent to a wrong URL, unopenable
            # there), never redirect the plaintext to itself.
            targets = {}
            for rid, p in peers.items():
                recipient_id = int(rid)
                member_addr = _members_addr(recipient_id)
                enc_hex, enc_sig = p.get("enc_pubkey"), p.get("enc_pubkey_sig")
                if member_addr is None or not enc_hex or not enc_sig:
                    return jsonify({
                        "error": f"No verified encryption key for keyper {recipient_id}; re-bootstrap",
                    }), 500
                try:
                    enc_pub = verify_encryption_pubkey(member_addr, enc_hex, enc_sig)
                except Exception as e:
                    return jsonify({
                        "error": f"Peer {recipient_id} encryption key failed verification: {e}",
                    }), 500
                targets[rid] = {"url": p["url"], "headers": _peer_auth_headers(rid), "enc_pub": enc_pub}
        else:
            # Single-operator dev mode (e.g. admin_tui.py's in-process demo,
            # no coordinator ever bootstraps a peers map) -- loopback/in-process,
            # no peer key to seal to, so shares go plaintext (enc_pub=None).
            targets = {
                rid: {"url": url, "headers": {}, "enc_pub": None}
                for rid, url in (data.get("keyper_urls") or {}).items()
                if int(rid) != kid
            }

        for recipient_id_str, target in targets.items():
            recipient_id = int(recipient_id_str)
            share_val = pending_shares[recipient_id]
            body = _build_share_body(
                dkg_meta["election_id"], kid, recipient_id, share_val,
                keyper_meta["signing_key"], target["enc_pub"],
            )
            try:
                resp = requests.post(f"{target['url']}/dkg/receive_share", json=body,
                                     headers=target["headers"], timeout=10)
                resp.raise_for_status()
            except Exception as e:
                return jsonify({"error": f"Failed to send share to keyper {recipient_id}: {e}"}), 500

        return jsonify({"status": "ok"})

    @app.route("/dkg/receive_share", methods=["POST"])
    def receive_share():
        """Receive a signed secret share from another keyper.

        The share value travels sealed to this keyper's X25519 key
        (``sealed_share``) so a passive network observer sees only ciphertext
        (audit finding C-1, Leg A). Plaintext ``share`` is accepted only in
        single-operator dev mode; when auth is on, a bare plaintext share is
        rejected so there is no silent downgrade off the sealed path.

        Confidentiality (sealing) and authenticity (the dealer's signature over
        the recovered value) are independent: the signature check below is
        unchanged and runs against the unsealed scalar. Append-only per dealer;
        signature is checked against the dealer's keyper-set member address.
        """
        data = request.get_json()
        try:
            election_id = data["election_id"]
            dealer_id = int(data["dealer_id"])
            recipient_id = int(data["recipient_id"])
            sig_hex = data["signature"]
            if "sealed_share" in data:
                share = unseal_share(data["sealed_share"], encryption_privkey)
            elif AUTH_REQUIRED:
                # No downgrade to plaintext once auth (multi-operator) is on.
                return jsonify({"error": "sealed_share required"}), 400
            else:
                share = int(data["share"])
        except (KeyError, ValueError, TypeError) as e:
            return jsonify({"error": f"Bad request: {e}"}), 400

        if election_id != dkg_meta.get("election_id"):
            return jsonify({"error": "Election ID mismatch"}), 400
        if recipient_id != keyper_meta["id"]:
            return jsonify({"error": f"Recipient mismatch: this is keyper {keyper_meta['id']}"}), 400
        if share < 0 or share >= CURVE_ORDER:
            return jsonify({"error": "Share value out of scalar field range"}), 400
        if dealer_id in received_shares:
            return jsonify({"error": "Share already received from this dealer"}), 409

        expected = _members_addr(dealer_id)
        if expected is None:
            return jsonify({"error": f"Unknown dealer_id {dealer_id}"}), 400
        payload_hash = _share_payload_hash(election_id, dealer_id, recipient_id, share)
        try:
            recovered = _recover(payload_hash, sig_hex)
        except Exception as e:
            return jsonify({"error": f"Signature recover failed: {e}"}), 401
        if recovered.lower() != expected.lower():
            return jsonify({
                "error": f"Bad signature: expected {expected}, recovered {recovered}",
            }), 401

        received_shares[dealer_id] = share
        return jsonify({"status": "ok"})

    @app.route("/dkg/reveal_share", methods=["POST"])
    def reveal_share():
        """Signed Feldman-VSS rebuttal, gated on a recipient-signed accusation.

        This dealer reveals the share it dealt to recipient ``j`` *only* when
        presented a valid ``DKG-ACCUSE-v1`` accusation signed by ``j`` against
        *this* dealer for the pinned election. Without that evidence the
        endpoint discloses nothing -- the bearer token controls who may reach
        the endpoint (coordinator-mediated ``api_token``); the accusation
        controls which specific share may be released. The gate lives here in
        the handler, not in ``before_request``, so it is enforced in every
        mode -- including single-operator dev mode where no token is required
        -- closing the H-1 disclosure oracle unconditionally.

        The endpoint is a *pure gated reveal*: it does not itself check
        ``share · P₂ == Σⱼ recipient^j · γⱼ`` or decide who lied. That
        adjudication (and dealer exclusion / re-run) is the resolver's job --
        see dkg-complaint-resolution.md (scope B). The returned ``signature``
        is the dealer's own ``DKG-REVEAL-v1`` statement, bound to the same
        payload the recipient would have received in /dkg/receive_share;
        together with the accusation signature it is two-sided signed evidence
        the resolver can adjudicate.

        Failures return a uniform 401 so a prober cannot learn which check
        failed (e.g. whether a share exists for that recipient).
        """
        data = request.get_json(silent=True) or {}
        acc = data.get("accusation")
        if not isinstance(acc, dict):
            return jsonify({"error": "Missing accusation"}), 400
        try:
            acc_election_id = acc["election_id"]
            accused_dealer_id = int(acc["accused_dealer_id"])
            recipient_id = int(acc["recipient_id"])
            acc_sig = acc["signature"]
        except (KeyError, ValueError, TypeError) as e:
            return jsonify({"error": f"Bad accusation: {e}"}), 400

        # (1) The accusation must be scoped to this dealer's pinned election.
        if dkg_meta["election_id"] is None or acc_election_id != dkg_meta["election_id"]:
            return jsonify({"error": "Unauthorized"}), 401
        # (2) It must name *this* keyper as the accused dealer, so one
        #     accusation unlocks exactly one (dealer, recipient) share and
        #     cannot be redirected to harvest a different dealer's share.
        if accused_dealer_id != keyper_meta["id"]:
            return jsonify({"error": "Unauthorized"}), 401
        # (3) We must actually have dealt a share to this recipient.
        if recipient_id not in pending_shares:
            return jsonify({"error": "Unauthorized"}), 401
        # (4) The accusation must be signed by the recipient themselves --
        #     recipient j can therefore only ever unlock f_i(j), its own
        #     share, which it is already entitled to.
        expected = _members_addr(recipient_id)
        if expected is None:
            return jsonify({"error": "Unauthorized"}), 401
        try:
            recovered = _recover(
                _accusation_payload_hash(acc_election_id, accused_dealer_id, recipient_id),
                acc_sig,
            )
        except Exception:
            return jsonify({"error": "Unauthorized"}), 401
        if recovered.lower() != expected.lower():
            return jsonify({"error": "Unauthorized"}), 401

        kid = keyper_meta["id"]
        share = pending_shares[recipient_id]
        payload_hash = _reveal_payload_hash(
            dkg_meta["election_id"], kid, recipient_id, share,
        )
        signature = _sign(keyper_meta["signing_key"], payload_hash)

        return jsonify({
            "dealer_id": kid,
            "recipient_id": recipient_id,
            "election_id": dkg_meta["election_id"],
            "share": str(share),
            "signature": signature,
            "signing_address": keyper_meta["signing_address"],
        })

    @app.route("/dkg/round2", methods=["POST"])
    def dkg_round2():
        """DKG Round 2: verify received shares and compute combined secret share.

        All commitments come from local state populated by
        /dkg/receive_commitments — the bulletin board is gone.
        """
        data = request.get_json() or {}
        # ``data`` may carry an election_id for cross-checking; not strictly
        # required since round 1 already pinned it.
        if data.get("election_id") and data["election_id"] != dkg_meta.get("election_id"):
            return jsonify({"error": "Election ID mismatch"}), 400

        all_commitments = dict(received_commitments)

        try:
            combined_share, public_key_share = dkg_state.round2(all_commitments, received_shares)
        except ValueError as e:
            # Use structured bad_dealers attribute from DKG (no regex parsing)
            bad_dealers = getattr(e, "bad_dealers", [])
            # Sign one accusation per bad dealer. This is the recipient-signed
            # evidence that the accused dealer's gated /dkg/reveal_share
            # requires before disclosing a share, and that the coordinator
            # surfaces on halt -- see dkg-complaint-resolution.md (scope A).
            # We are the complaining recipient (my_kid); the accusation names
            # the accused dealer and is bound to the pinned election.
            my_kid = keyper_meta["id"]
            accusations = [
                {
                    "election_id": dkg_meta["election_id"],
                    "accused_dealer_id": int(bad),
                    "recipient_id": my_kid,
                    "signature": _sign(
                        keyper_meta["signing_key"],
                        _accusation_payload_hash(dkg_meta["election_id"], int(bad), my_kid),
                    ),
                }
                for bad in bad_dealers
            ]
            return jsonify({
                "keyper_id": my_kid,
                "verified": False,
                "complaints": bad_dealers,
                "accusations": accusations,
                "error": str(e),
            }), 200  # 200 so backend can parse the complaint

        # Snapshot what we just consumed so a subsequent on-chain publish
        # uses the identical commitment set.
        last_round2["all_commitments"] = dict(all_commitments)
        last_round2["active_dealers"] = sorted(received_shares.keys())

        # Persist so a restart doesn't need a fresh DKG ceremony.
        save_dkg_secret(fernet, identity, dkg_meta["election_id"], combined_share, keyper_meta["id"])
        logger.info("op=dkg_round2 election_id=%s status=verified", dkg_meta.get("election_id"))

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

    # NOTE: there is deliberately no off-chain ``POST /decrypt`` oracle. Partial
    # decryption happens only through ``/decrypt/publish_on_chain`` above, which
    # decrypts the aggregate read *from the contract* (caller cannot choose the
    # ciphertext) and is gated on DKG finalization + votingEnd + a published
    # aggregate. A raw endpoint that returned a partial decryption of any
    # caller-supplied ciphertext would be a decryption oracle (audit finding
    # H-2); it was removed. The tally is decrypted on-chain: keypers submit
    # shares via ``submitDecryptionShare`` and ``tally_aggregator.finalize``
    # Lagrange-combines them. See dkg-complaint-resolution.md / audit-report.md.

    return app


def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S',
    )
    parser = argparse.ArgumentParser(description="Keyper server for threshold ElGamal voting")
    parser.add_argument("--port", type=int, required=True, help="Port to listen on")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--rpc-url", default=None,
                        help="Ethereum RPC URL; required to publish DKG results on chain")
    parser.add_argument("--private-key", default=None,
                        help=("Hex private key with 0x prefix used to sign on-chain "
                              "DKG/decryption-share submissions. Prefer KEYPER_PRIVATE_KEY env var."))
    args = parser.parse_args()

    private_key = args.private_key or os.environ.get("KEYPER_PRIVATE_KEY")
    if not private_key:
        sys.exit(
            "Error: KEYPER_PRIVATE_KEY is required (or --private-key)."
        )
    chain_config = None
    if args.rpc_url:
        chain_config = {"rpc_url": args.rpc_url, "private_key": private_key}

    # Same key signs both the chain transactions and the P2P DKG messages
    # so the recovered address matches the KeyperSet member entry.
    app = create_keyper_app(chain_config=chain_config, signing_key=private_key)
    signing_address = Account.from_key(private_key).address
    suffix = " [chain enabled]" if chain_config else ""
    print(f"[Keyper {signing_address}] Starting on {args.host}:{args.port}{suffix}")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
