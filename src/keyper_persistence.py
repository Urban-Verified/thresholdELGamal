"""Encrypted on-disk persistence for a keyper's durable state.

Three separate files under KEYPER_STATE_DIR/keyper-<identity>/, all
Fernet-encrypted with a key derived from the keyper's own signing key,
none sharing a file with another:
  - dkg_secret.enc         this keyper's combined DKG share (+ the DKG index
                           it was assigned) for the (single) election it
                           serves, so a restart doesn't need a fresh DKG
                           ceremony. Unlike a multi-tenant keyper fleet
                           serving many concurrent proposals, this repo runs
                           one election per keyper process, so there is
                           exactly one entry and no retention/pruning need.
  - encryption_key.enc     the X25519 keypair used to decrypt /auth/bootstrap
                           payloads -- persisted so the coordinator's cached
                           encryption_pubkey for this keyper never goes stale
  - bootstrap_tokens.enc   the installed api_token/peer_token/peers map
                           ({kid: {url, token}} for every other keyper),
                           so a restart needs no re-bootstrap at all

Scoped per keyper *identity* (its own signing address) rather than a
keyper_id integer -- keypers no longer have a statically-configured index
(see keyper.py; the DKG index is resolved by the coordinator via
KeyperSet.getMemberIndex and adopted at round1 time). The signing address
is stable from the moment the process starts, so it's available even
before any DKG index is known, and it still uniquely separates multiple
keypers sharing one process (admin_tui.py's in-process demo, this
package's own test suite) without either needing a preassigned index. In
Docker, where each keyper is its own container with its own volume mount,
this just adds one harmless subdirectory level.
"""

from __future__ import annotations

import json
import logging
import os
import pathlib

from cryptography.fernet import Fernet, InvalidToken

# Relative to this file (src/keyper_persistence.py) rather than a bare
# absolute path: create_keyper_app() runs both inside Docker (WORKDIR
# /app/src -> default /app/keyper-state, matching the volume mount in
# docker-compose.keyper.yml) and directly on the host (admin_tui.py's
# in-process demo, this package's own test suite) -- a hardcoded
# "/keyper-state" would try to mkdir at the filesystem root on the host
# and fail on a read-only root filesystem.
_DEFAULT_STATE_DIR = str(pathlib.Path(__file__).resolve().parent.parent / "keyper-state")


def state_dir(identity: str) -> pathlib.Path:
    base = pathlib.Path(os.environ.get("KEYPER_STATE_DIR", _DEFAULT_STATE_DIR))
    d = base / f"keyper-{identity.lower()}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def dkg_secret_file(identity: str) -> pathlib.Path:
    return state_dir(identity) / "dkg_secret.enc"


def save_dkg_secret(fernet: Fernet, identity: str, election_id: str, combined_share: int, keyper_id: int) -> None:
    data = {"election_id": election_id, "share": hex(combined_share), "keyper_id": keyper_id}
    encrypted = fernet.encrypt(json.dumps(data).encode())
    path = dkg_secret_file(identity)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(encrypted)
    os.replace(tmp, path)


def load_dkg_secret(fernet: Fernet, identity: str, logger: logging.Logger) -> dict | None:
    """Returns {"election_id", "share" (int), "keyper_id" (int)} if a prior
    DKG ceremony's result was persisted, else None."""
    path = dkg_secret_file(identity)
    if not path.exists():
        return None
    try:
        data = json.loads(fernet.decrypt(path.read_bytes()))
        logger.info("op=load_dkg_secret status=ok election_id=%s keyper_id=%s",
                    data.get("election_id"), data.get("keyper_id"))
        return {
            "election_id": data["election_id"],
            "share": int(data["share"], 16),
            "keyper_id": data["keyper_id"],
        }
    except InvalidToken:
        logger.error(
            "op=load_dkg_secret status=error reason=decryption_failed "
            "(wrong KEYPER_PRIVATE_KEY or tampered file — starting with empty state)"
        )
        return None
    except Exception as err:
        logger.error("op=load_dkg_secret status=error err=%s", err)
        return None


def encryption_key_file(identity: str) -> pathlib.Path:
    return state_dir(identity) / "encryption_key.enc"


def load_or_create_encryption_key(fernet: Fernet, identity: str, logger: logging.Logger):
    """Load this keyper's X25519 bootstrap-encryption private key, generating
    and persisting one on first run. Persisted (not regenerated per restart)
    so the coordinator's cached ``encryption_pubkey`` for this keyper stays
    valid across restarts."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    path = encryption_key_file(identity)
    if path.exists():
        try:
            raw = fernet.decrypt(path.read_bytes())
            logger.info("op=load_encryption_key status=ok")
            return X25519PrivateKey.from_private_bytes(raw)
        except InvalidToken:
            logger.error(
                "op=load_encryption_key status=error reason=decryption_failed "
                "(wrong KEYPER_PRIVATE_KEY or tampered file -- regenerating)"
            )

    key = X25519PrivateKey.generate()
    encrypted = fernet.encrypt(key.private_bytes_raw())
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(encrypted)
    os.replace(tmp, path)
    logger.info("op=create_encryption_key status=ok")
    return key


def bootstrap_tokens_file(identity: str) -> pathlib.Path:
    return state_dir(identity) / "bootstrap_tokens.enc"


def save_bootstrap_tokens(
    fernet: Fernet, identity: str, api_token: str, peer_token: str, peers: dict[str, dict[str, str]],
) -> None:
    """Persist this keyper's own api_token/peer_token and its outbound
    peers map ({kid: {"url", "token"}} -- both what it needs to reach a
    peer and what to authenticate with, from the same trusted source) --
    a separate encrypted file from dkg_secret.enc, so a keyper restart
    never needs a fresh /auth/bootstrap call to resume being called *or*
    calling others. Overwritten wholesale on every successful bootstrap."""
    data = {
        "api_token": api_token,
        "peer_token": peer_token,
        "peers": peers,
    }
    encrypted = fernet.encrypt(json.dumps(data).encode())
    path = bootstrap_tokens_file(identity)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(encrypted)
    os.replace(tmp, path)


def load_bootstrap_tokens(fernet: Fernet, identity: str, logger: logging.Logger) -> dict | None:
    """Returns {"api_token", "peer_token", "peers"} if a prior bootstrap
    was persisted, else None (never bootstrapped yet -- the keyper stays
    in the fail-closed pre-bootstrap state)."""
    path = bootstrap_tokens_file(identity)
    if not path.exists():
        return None
    try:
        data = json.loads(fernet.decrypt(path.read_bytes()))
        logger.info("op=load_bootstrap_tokens status=ok")
        return data
    except InvalidToken:
        logger.error(
            "op=load_bootstrap_tokens status=error reason=decryption_failed "
            "(wrong KEYPER_PRIVATE_KEY or tampered file -- starting unbootstrapped)"
        )
        return None
    except Exception as err:
        logger.error("op=load_bootstrap_tokens status=error err=%s", err)
        return None
