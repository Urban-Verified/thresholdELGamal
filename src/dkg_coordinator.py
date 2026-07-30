#!/usr/bin/env python3
"""
DKG coordinator — orchestrates the keyper HTTP APIs for Feldman VSS DKG.

Flow (matches RUNNING.md):
  round1 → distribute_commitments → distribute_shares → round2 → publish_on_chain
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import sys
import time
from dataclasses import dataclass
from typing import Any, Optional

import requests
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from eth_account import Account
from eth_account.messages import encode_defunct

import coordinator_state
from token_bootstrap import enc_pubkey_hash, payload_hash, x25519_seal

log = logging.getLogger('dkg')

# HTTP timeout for a single /auth/bootstrap push.
_BOOTSTRAP_TIMEOUT_S = 20.0


def _eth_sign(payload_dict: dict, private_key: str) -> str:
    msg = encode_defunct(primitive=payload_hash(payload_dict))
    return Account.from_key(private_key).sign_message(msg).signature.hex()


class DKGCoordinatorError(RuntimeError):
    pass


@dataclass(frozen=True)
class Keyper:
    kid: int
    url: str


def _resolve_kids_onchain(urls: list[str], rpc_url: str, election_address: str,
                           *, timeout: float = 10.0) -> dict[str, int]:
    """Resolve each keyper URL's real DKG index from the on-chain KeyperSet,
    by asking it for the index of the address that URL's own /status
    reports -- instead of trusting KEYPER_URLS list position. Returns
    {url: kid} (1-indexed, matching KeyperSet.getMemberIndex()+1).
    """
    from eth_client import ElectionClient, EthChain, KeyperSetClient

    chain = EthChain.connect(rpc_url)
    keyper_set_addr = ElectionClient(chain, election_address).keyper_set_address()
    ks = KeyperSetClient(chain, keyper_set_addr)

    result: dict[str, int] = {}
    for url in urls:
        u = url.rstrip("/")
        r = requests.get(f"{u}/status", timeout=timeout)
        r.raise_for_status()
        addr = r.json().get("address")
        if not isinstance(addr, str) or not addr.startswith("0x"):
            raise DKGCoordinatorError(f"{u}/status missing/invalid address")
        try:
            result[u] = ks.get_member_index(addr) + 1
        except Exception as e:
            raise DKGCoordinatorError(f"{u} (address {addr}) is not a KeyperSet member: {e}") from e
    return result


def _keypers_from_urls(urls: list[str], *, rpc_url: str | None = None,
                        election_address: str | None = None) -> list[Keyper]:
    """Assign each URL its DKG index.

    Falls back to position (1-indexed, matching the historical KEYPER_URLS
    ordering requirement) when no chain connection is given -- used by
    admin_tui.py's in-process demo, whose committee is already correctly
    ordered by construction. When rpc_url + election_address are both
    given (the real CLI path), each keyper's real on-chain member index is
    resolved instead, so KEYPER_URLS' order no longer matters.

    Always returns the list sorted by kid -- callers (fetch_members_from_status
    and anything that zips this list against another kid-ordered one) rely
    on that invariant, which position-based assignment satisfied for free
    but on-chain resolution doesn't automatically guarantee.
    """
    if rpc_url and election_address:
        kids_by_url = _resolve_kids_onchain(urls, rpc_url, election_address)
        keypers = [Keyper(kid=kids_by_url[u.rstrip("/")], url=u.rstrip("/")) for u in urls]
    else:
        keypers = [Keyper(kid=i + 1, url=u.rstrip("/")) for i, u in enumerate(urls)]
    return sorted(keypers, key=lambda kp: kp.kid)


def fetch_members_from_status(keypers: list[Keyper], *, timeout: float = 5.0) -> list[str]:
    """
    Fetch the expected DKG `members` list from each keyper `/status`.
    We take the first successful set (and sanity-check that all match).
    """
    members_by_kid: dict[int, str] = {}
    for kp in keypers:
        r = requests.get(f"{kp.url}/status", timeout=timeout)
        r.raise_for_status()
        j = r.json()
        addr = j.get("address")
        if not isinstance(addr, str) or not addr.startswith("0x"):
            raise DKGCoordinatorError(f"{kp.url}/status missing/invalid address")
        members_by_kid[kp.kid] = addr

    return [members_by_kid[i] for i in range(1, len(keypers) + 1)]


def build_keyper_urls_map(keypers: list[Keyper]) -> dict[str, str]:
    # Keyper APIs expect a dict keyed by string keyper_id.
    return {str(kp.kid): kp.url for kp in keypers}


# ----------------------------------------------------------------------
#  Keyper bearer-token bootstrap
#
#  Mirrors sx-monorepo's auto_dkg.py: mint api_token/peer_token pairs,
#  seal + sign them per keyper via /auth/bootstrap, and hand the api_token
#  side off to tally-aggregator (a separate, later-running process) via
#  coordinator_state's plaintext shared file -- see keyper-token-bootstrap
#  design notes in docker/README.md.
# ----------------------------------------------------------------------

def _verify_encryption_pubkey(address: str, pubkey_hex: str, sig_hex: str) -> X25519PublicKey:
    """Verify a keyper's self-published encryption_pubkey is bound to its
    already-trusted signing address, then return the parsed public key.

    Raises on any failure -- callers must treat that keyper as not
    bootstrappable this round rather than silently skipping verification.
    """
    pubkey_bytes = bytes.fromhex(pubkey_hex.removeprefix("0x"))
    msg = encode_defunct(primitive=enc_pubkey_hash(pubkey_bytes))
    recovered = Account.recover_message(msg, signature=bytes.fromhex(sig_hex.removeprefix("0x")))
    if recovered.lower() != address.lower():
        raise DKGCoordinatorError(
            f"encryption_pubkey signature mismatch for {address}: recovered {recovered}"
        )
    return X25519PublicKey.from_public_bytes(pubkey_bytes)


def fetch_encryption_pubkeys(
    keypers: list[Keyper], member_addrs: list[str], *, timeout: float = 5.0,
) -> dict[int, X25519PublicKey]:
    """Fetch and verify each keyper's bootstrap encryption_pubkey from /status.

    A keyper that's unreachable or fails verification is simply omitted --
    the caller should skip bootstrapping it this pass, not crash the whole
    thing.
    """
    pubkeys: dict[int, X25519PublicKey] = {}
    for kp, addr in zip(keypers, member_addrs):
        try:
            r = requests.get(f"{kp.url}/status", timeout=timeout)
            r.raise_for_status()
            j = r.json()
            pubkeys[kp.kid] = _verify_encryption_pubkey(
                addr, j["encryption_pubkey"], j["encryption_pubkey_sig"],
            )
        except Exception as e:
            log.warning("op=fetch_encryption_pubkey keyper=%d status=error err=%s", kp.kid, e)
    return pubkeys


def fetch_bootstrapped_status(keypers: list[Keyper], *, timeout: float = 5.0) -> dict[int, bool]:
    """Read each keyper's live /status.bootstrapped flag.

    Tells "lost its persisted token file" (row present on our side,
    bootstrapped=False on theirs -- needs a targeted same-value re-push)
    apart from "already fine" (no push needed). An unreachable keyper is
    reported as bootstrapped=True -- pushing to a host we can't reach would
    just fail anyway, so there's no point forcing the attempt.
    """
    result: dict[int, bool] = {}
    for kp in keypers:
        try:
            r = requests.get(f"{kp.url}/status", timeout=timeout)
            r.raise_for_status()
            result[kp.kid] = bool(r.json().get("bootstrapped", False))
        except Exception as e:
            log.warning("op=fetch_bootstrapped_status keyper=%d status=error err=%s", kp.kid, e)
            result[kp.kid] = True
    return result


def push_bootstrap(
    kp: Keyper,
    intended_recipient: str,
    api_token: str,
    peer_token: str,
    peers: dict[str, dict[str, str]],
    encryption_pubkey: X25519PublicKey,
    coordinator_signing_key: str,
    *,
    timeout: float = _BOOTSTRAP_TIMEOUT_S,
) -> bool:
    """Seal+sign a bootstrap envelope for one keyper and POST it.

    Carries everything a keyper needs: its own api_token/peer_token, plus
    peers ({kid: {"url", "token"}} for every *other* keyper -- both where
    to reach it and what to authenticate with, from this one trusted
    source). DKG endpoints (round1, distribute_* etc.) carry no auth
    material or destination data at all -- everything flows through this
    one channel.

    Returns True on success; logs and returns False on any failure so a
    single unreachable keyper doesn't abort the whole pass.
    """
    payload = {
        "intended_recipient": intended_recipient,
        "api_token": api_token,
        "peer_token": peer_token,
        "peers": peers,
        "nonce": secrets.token_hex(16),
        "timestamp": int(time.time()),
    }
    sig = _eth_sign(payload, coordinator_signing_key)
    sealed = x25519_seal(
        json.dumps({"payload": payload, "sig": sig}).encode(),
        encryption_pubkey,
    )
    try:
        r = requests.post(f"{kp.url}/auth/bootstrap", data=sealed, timeout=timeout,
                           headers={"Content-Type": "application/octet-stream"})
        r.raise_for_status()
        log.info("op=auth_bootstrap keyper=%d status=ok", kp.kid)
        return True
    except Exception as e:
        log.warning("op=auth_bootstrap keyper=%d status=error err=%s", kp.kid, e)
        return False


def bootstrap_keypers(keyper_urls: list[str], coordinator_signing_key: str, *,
                       rpc_url: str | None = None, election_address: str | None = None) -> dict[str, str]:
    """One-shot token mint + push, reconciled against the persisted shared
    state file. Safe to call on every dkg-runner invocation regardless of
    whether the DKG ceremony itself has already run: a keyper that lost its
    persisted token (redeployed, volume wiped) gets a targeted re-push of
    its unchanged value; a brand-new keyper URL gets a fresh mint, which
    ripples a full re-push to every keyper since each one's peers map
    depends on the complete set.

    No rotation otherwise -- tokens are minted once and persisted on both
    sides (this file, and each keyper's own encrypted volume).

    ``rpc_url``/``election_address``: when both given, each keyper's index
    is resolved from the on-chain KeyperSet instead of KEYPER_URLS list
    position -- see ``_keypers_from_urls``.

    Returns {url: api_token} for immediate use by this same process's DKG
    ceremony. Returns {} (and does nothing else) if
    ``coordinator_signing_key`` is empty -- single-operator dev mode,
    matching keyper.py's own ``AUTH_REQUIRED = bool(COORDINATOR_ADDRESS)``.
    """
    if not coordinator_signing_key:
        return {}

    keypers = _keypers_from_urls(keyper_urls, rpc_url=rpc_url, election_address=election_address)
    member_addrs = fetch_members_from_status(keypers)
    existing = coordinator_state.load_tokens()

    urls = [kp.url.rstrip("/") for kp in keypers]
    missing_urls = [u for u in urls if u not in existing]

    tokens_by_url = dict(existing)
    for url in missing_urls:
        tokens_by_url[url] = {
            "api_token": secrets.token_hex(32),
            "peer_token": secrets.token_hex(32),
        }

    if missing_urls:
        # A value changed -- every keyper's peers map depends on the full
        # set, so re-push to everyone.
        target_kids = {kp.kid for kp in keypers}
    else:
        bootstrapped = fetch_bootstrapped_status(keypers)
        target_kids = {kp.kid for kp in keypers if not bootstrapped.get(kp.kid, True)}

    if target_kids:
        enc_pubkeys = fetch_encryption_pubkeys(keypers, member_addrs)
        pushed = 0
        for kp, addr in zip(keypers, member_addrs):
            if kp.kid not in target_kids:
                continue
            enc_pubkey = enc_pubkeys.get(kp.kid)
            if enc_pubkey is None:
                continue
            url = kp.url.rstrip("/")
            own = tokens_by_url[url]
            # {kid: {"url", "token"}} for every *other* keyper -- both where
            # to reach it and what to authenticate with, so DKG endpoints
            # never need keyper_urls in their own request body at all.
            peers = {
                str(other.kid): {
                    "url": other.url,
                    "token": tokens_by_url[other.url.rstrip("/")]["peer_token"],
                }
                for other in keypers if other.kid != kp.kid
            }
            if push_bootstrap(kp, addr, own["api_token"], own["peer_token"],
                               peers, enc_pubkey, coordinator_signing_key):
                pushed += 1
        log.info("op=bootstrap_keypers status=ok pushed=%d/%d new=%d",
                  pushed, len(target_kids), len(missing_urls))
    else:
        log.info("op=bootstrap_keypers status=ok action=none")

    if missing_urls:
        coordinator_state.save_tokens(tokens_by_url)

    return {url: toks["api_token"] for url, toks in tokens_by_url.items()}


def _post(url: str, path: str, payload: dict[str, Any], *, timeout: float,
          headers: dict | None = None) -> dict[str, Any]:
    r = requests.post(f"{url}{path}", json=payload, headers=headers, timeout=timeout)
    if r.status_code >= 400:
        # Try to surface server error shape if present.
        try:
            body = r.json()
        except Exception:
            body = {"text": r.text}
        raise DKGCoordinatorError(f"POST {path} failed on {url}: {r.status_code} {body}")
    try:
        return r.json()
    except Exception:
        return {}


def run_dkg(
    *,
    keyper_urls: list[str],
    election_id: str,
    election_address: str,
    n: int,
    t: int,
    members: Optional[list[str]] = None,
    api_tokens: Optional[dict[str, str]] = None,
    rpc_url: Optional[str] = None,
    timeout: float = 60.0,
    sleep_between: float = 0.0,
    verbose: bool = True,
) -> None:
    """
    Orchestrate DKG across keypers and publish the DKG result on-chain.

    ``api_tokens`` maps each keyper's base URL to the coordinator-tier
    bearer token that keyper expects on round1/round2/distribute_*/
    publish_on_chain -- the coordinator authenticates its own calls with
    it. Peer tokens (for P2P calls between keypers) are delivered
    separately via /auth/bootstrap, not through this function. Omit (or
    pass None/{}) for single-operator dev mode (e.g. admin_tui.py), which
    also switches distribute_commitments/distribute_shares back to sending
    ``keyper_urls`` in the body -- see keyper.py's AUTH_REQUIRED fallback.

    ``rpc_url``: when given (alongside the always-required
    ``election_address``), each keyper's DKG index is resolved from the
    on-chain KeyperSet instead of ``keyper_urls`` list position -- see
    ``_keypers_from_urls``. Omitted by admin_tui.py, whose committee is
    already correctly ordered by construction.
    """
    keypers = _keypers_from_urls(keyper_urls, rpc_url=rpc_url, election_address=election_address)
    if len(keypers) != n:
        raise DKGCoordinatorError(f"n={n} but got {len(keypers)} keyper URLs")
    if members is None:
        members = fetch_members_from_status(keypers, timeout=min(timeout, 10.0))
    if len(members) != n:
        raise DKGCoordinatorError(f"members length {len(members)} != n {n}")

    keyper_urls_map = build_keyper_urls_map(keypers)

    def _auth(kp: Keyper) -> dict | None:
        """Bearer header for coordinator → keyper calls using that keyper's own api_token."""
        if not api_tokens:
            return None
        tok = api_tokens.get(kp.url.rstrip("/"), "")
        return {"Authorization": f"Bearer {tok}"} if tok else None

    if verbose:
        print(json.dumps(
            {
                "step": "config",
                "n": n,
                "t": t,
                "election_id": election_id,
                "election_address": election_address,
                "keypers": [{"kid": kp.kid, "url": kp.url} for kp in keypers],
                "members": members,
                "authenticated": bool(api_tokens),
            },
            indent=2,
        ))

    # round1
    for kp in keypers:
        if verbose:
            print(f"[dkg] round1: keyper {kp.kid}")
        _post(
            kp.url,
            "/dkg/round1",
            {"n": n, "t": t, "keyper_id": kp.kid, "election_id": election_id, "members": members},
            timeout=timeout,
            headers=_auth(kp),
        )
        if sleep_between:
            time.sleep(sleep_between)

    # distribute commitments -- with a coordinator-tier token in play, each
    # keyper fans out to its own bootstrap-installed peers map instead
    # (see keyper.py); keyper_urls is only meaningful in unauthenticated
    # single-operator dev mode, so omit it once real auth is configured.
    for kp in keypers:
        if verbose:
            print(f"[dkg] distribute_commitments: keyper {kp.kid}")
        body = {} if api_tokens else {"keyper_urls": keyper_urls_map}
        _post(kp.url, "/dkg/distribute_commitments", body, timeout=timeout, headers=_auth(kp))
        if sleep_between:
            time.sleep(sleep_between)

    # distribute shares -- same as above.
    for kp in keypers:
        if verbose:
            print(f"[dkg] distribute_shares: keyper {kp.kid}")
        body = {} if api_tokens else {"keyper_urls": keyper_urls_map}
        _post(kp.url, "/dkg/distribute_shares", body, timeout=timeout, headers=_auth(kp))
        if sleep_between:
            time.sleep(sleep_between)

    # round2
    for kp in keypers:
        if verbose:
            print(f"[dkg] round2: keyper {kp.kid}")
        _post(kp.url, "/dkg/round2", {"election_id": election_id}, timeout=timeout, headers=_auth(kp))
        if sleep_between:
            time.sleep(sleep_between)

    # publish on chain
    for kp in keypers:
        if verbose:
            print(f"[dkg] publish_on_chain: keyper {kp.kid}")
        _post(
            kp.url,
            "/dkg/publish_on_chain",
            {"election_address": election_address, "n": n},
            timeout=timeout,
            headers=_auth(kp),
        )
        if sleep_between:
            time.sleep(sleep_between)

    if verbose:
        print("[dkg] done")


def _require(value: str | None, flag: str, env: str) -> str:
    if not value:
        raise SystemExit(f"error: {flag} required: pass {flag} or set ${env}")
    return value


def _cmd_bootstrap(args) -> int:
    keyper_urls = [u.strip() for u in args.keyper_urls.split(",") if u.strip()]
    if not args.coordinator_signing_key:
        print("[bootstrap] coordinator-signing-key empty -- single-operator dev mode, nothing to do")
        return 0
    rpc_url = _require(args.rpc_url, "--rpc-url", "RPC_URL")
    election_address = _require(args.election_address, "--election-address", "ELECTION_ADDRESS")
    tokens = bootstrap_keypers(keyper_urls, args.coordinator_signing_key,
                                rpc_url=rpc_url, election_address=election_address)
    print(f"[bootstrap] done -- {len(tokens)} keyper(s) have a token on record "
          f"at {coordinator_state.bootstrap_tokens_file()}")
    return 0


def _cmd_run(args) -> int:
    keyper_urls = [u.strip() for u in args.keyper_urls.split(",") if u.strip()]
    rpc_url = _require(args.rpc_url, "--rpc-url", "RPC_URL")
    persisted = coordinator_state.load_tokens()
    api_tokens = {url: toks["api_token"] for url, toks in persisted.items()} if persisted else None
    run_dkg(
        keyper_urls=keyper_urls,
        election_id=args.election_id,
        election_address=args.election_address,
        n=args.n,
        t=args.t,
        api_tokens=api_tokens,
        rpc_url=rpc_url,
        timeout=args.timeout,
        sleep_between=args.sleep_between,
        verbose=not args.quiet,
    )
    return 0


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S',
    )
    p = argparse.ArgumentParser(description="DKG coordinator (keyper HTTP orchestrator)")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_boot = sub.add_parser("bootstrap", help="Mint/push keyper bearer tokens, write the shared state file")
    p_boot.add_argument("--keyper-urls", required=True, help="Comma-separated keyper base URLs")
    p_boot.add_argument("--rpc-url", default=os.environ.get("RPC_URL"),
                         help="Ethereum RPC URL -- resolves each keyper's real DKG index via the "
                              "on-chain KeyperSet instead of trusting --keyper-urls order.")
    p_boot.add_argument("--election-address", default=os.environ.get("ELECTION_ADDRESS"),
                         help="Election contract address (0x...) -- its configured KeyperSet is "
                              "the source of truth for each keyper's index.")
    p_boot.add_argument("--coordinator-signing-key", default=os.environ.get("COORDINATOR_SIGNING_KEY", ""),
                         help="This coordinator's own EIP-191 signing key. Empty = single-operator dev mode.")
    p_boot.set_defaults(func=_cmd_bootstrap)

    p_run = sub.add_parser("run", help="Orchestrate the DKG ceremony across keypers and publish on chain")
    p_run.add_argument("--keyper-urls", required=True, help="Comma-separated keyper base URLs")
    p_run.add_argument("--rpc-url", default=os.environ.get("RPC_URL"),
                        help="Ethereum RPC URL -- resolves each keyper's real DKG index via the "
                             "on-chain KeyperSet instead of trusting --keyper-urls order.")
    p_run.add_argument("--election-id", required=True, help="Opaque election id string for keypers (e.g. demo-election)")
    p_run.add_argument("--election-address", required=True, help="Election contract address (0x...)")
    p_run.add_argument("--n", type=int, required=True, help="Number of keypers")
    p_run.add_argument("--t", type=int, required=True, help="Threshold degree (need t+1 shares)")
    p_run.add_argument("--timeout", type=float, default=60.0, help="Per-request timeout seconds (default 60)")
    p_run.add_argument("--sleep-between", type=float, default=0.0, help="Sleep seconds between requests (default 0)")
    p_run.add_argument("--quiet", action="store_true", help="Less output")
    p_run.set_defaults(func=_cmd_run)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    try:
        main()
    except DKGCoordinatorError as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(2)
