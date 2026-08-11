"""Shared crypto helpers for the automated keyper bearer-token bootstrap.

Used by both ``keyper.py`` (unseal + verify + install) and
``dkg_coordinator.py`` (verify keyper encryption keys, mint + seal + sign +
push tokens).

Two independent properties, neither substituting for the other:
  - confidentiality: ``x25519_seal``/``x25519_unseal`` (anonymous sealed
    box -- anyone can seal *to* a public key, so this alone proves nothing
    about the sender)
  - authenticity: an EIP-191 signature over the plaintext payload, computed
    with ``payload_hash``/``enc_pubkey_hash`` and verified by the caller
    against a known address (``COORDINATOR_ADDRESS`` or a keyper's own
    signing address)
"""
from __future__ import annotations

import json
import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak

BOOTSTRAP_DST = b"KEYPER-TOKEN-BOOTSTRAP-v1"
ENC_PUBKEY_DST = b"KEYPER-ENC-PUBKEY-v1"
_HKDF_INFO = b"keyper-token-bootstrap-v1"

# Bootstrap payload timestamps must fall within this window of "now" on the
# verifying side; also the nonce-tracker's retention window.
NONCE_WINDOW_S = 300


def canonical_payload_bytes(payload: dict) -> bytes:
    """Deterministic JSON encoding so both sides hash/sign identical bytes."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def payload_hash(payload: dict) -> bytes:
    return keccak(BOOTSTRAP_DST + canonical_payload_bytes(payload))


def enc_pubkey_hash(pubkey_bytes: bytes) -> bytes:
    return keccak(ENC_PUBKEY_DST + pubkey_bytes)


def verify_encryption_pubkey(address: str, pubkey_hex: str, sig_hex: str) -> X25519PublicKey:
    """Verify a keyper's self-published ``encryption_pubkey`` is bound to the
    given (already-trusted, e.g. on-chain member) signing address, and return
    the parsed X25519 public key.

    Used both by the coordinator (to trust a keyper's key before sealing its
    bootstrap envelope) and by a dealer (to trust a peer's key before sealing a
    share to it -- so a key delivered via the coordinator's peers map can't be
    substituted). Raises ``ValueError`` on any mismatch; callers must treat that
    as "not usable", never seal to an unverified key.
    """
    pubkey_bytes = bytes.fromhex(pubkey_hex.removeprefix("0x"))
    msg = encode_defunct(primitive=enc_pubkey_hash(pubkey_bytes))
    recovered = Account.recover_message(msg, signature=bytes.fromhex(sig_hex.removeprefix("0x")))
    if recovered.lower() != address.lower():
        raise ValueError(f"encryption_pubkey signature mismatch for {address}: recovered {recovered}")
    return X25519PublicKey.from_public_bytes(pubkey_bytes)


def x25519_seal(plaintext: bytes, recipient_pubkey: X25519PublicKey) -> bytes:
    """Anonymous sealed box: fresh ephemeral keypair per message, ECDH + HKDF + AES-GCM.

    Anyone can produce a sealed envelope to a public key -- this gives
    confidentiality only. Do not mistake "unseals successfully" for "came
    from the expected sender"; that must be checked separately via a
    signature embedded in ``plaintext``.
    """
    eph_priv = X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes_raw()
    recipient_pub_bytes = recipient_pubkey.public_bytes_raw()
    shared = eph_priv.exchange(recipient_pubkey)
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=_HKDF_INFO + eph_pub_bytes + recipient_pub_bytes,
    ).derive(shared)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return eph_pub_bytes + nonce + ct


def x25519_unseal(sealed: bytes, recipient_privkey: X25519PrivateKey) -> bytes:
    if len(sealed) < 32 + 12:
        raise ValueError("sealed envelope too short")
    eph_pub_bytes, nonce, ct = sealed[:32], sealed[32:44], sealed[44:]
    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
    recipient_pub_bytes = recipient_privkey.public_key().public_bytes_raw()
    shared = recipient_privkey.exchange(eph_pub)
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=_HKDF_INFO + eph_pub_bytes + recipient_pub_bytes,
    ).derive(shared)
    return AESGCM(key).decrypt(nonce, ct, None)


class NonceTracker:
    """Bounded, TTL-based replay guard for bootstrap payload nonces.

    Rejects a (nonce, timestamp) pair if the timestamp is outside the
    freshness window or the nonce has already been seen within it. Entries
    older than the window are pruned on every check, so memory stays
    bounded regardless of how long the process runs.
    """

    def __init__(self, window_s: float = NONCE_WINDOW_S):
        self._window_s = window_s
        self._seen: dict[str, float] = {}

    def check_and_record(self, nonce: str, timestamp: int) -> bool:
        now = time.time()
        self._prune(now)
        if not nonce or abs(now - timestamp) > self._window_s:
            return False
        if nonce in self._seen:
            return False
        self._seen[nonce] = now
        return True

    def _prune(self, now: float) -> None:
        expired = [n for n, seen_at in self._seen.items() if now - seen_at > self._window_s]
        for n in expired:
            del self._seen[n]
