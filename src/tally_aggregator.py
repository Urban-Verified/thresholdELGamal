#!/usr/bin/env python3
"""
Standalone Tally Aggregator — pure on-chain reader/writer for the post-vote
phase of an election.

The Tally Aggregator holds ``TALLY_AGGREGATOR_ROLE`` on the target
``Election`` contract. After ``votingEnd``, it:

  * **aggregate** — reads every ballot from the chain, runs full SDK-shape
    verification (range OR + exact-budget DLEQ + Schnorr signature + WR
    attestation against ``Election.pkWR``), homomorphically sums the
    surviving ciphertexts, and calls ``Election.publishAggregate``.

  * **finalize** — reads the on-chain decryption shares and the DKG
    committee, re-verifies each share's DLEQ under the SDK
    ``SHUTTER-VOTE-DECRYPT-v1`` transcript, picks the first ``thresholdT``
    valid shares per candidate, Lagrange-combines on G₂, recovers the
    integer per-candidate totals via BSGS, and calls
    ``Election.publishResult``.

Both operations are stateless given ``(chain, election_address, signer)``;
no Flask, no off-chain state, no bulletin-board access. See ``PLAN.md``
decision E.

Library usage:

    from eth_account import Account
    from eth_client import EthChain
    from tally_aggregator import aggregate, finalize

    chain = EthChain.connect(rpc_url)
    signer = Account.from_key(private_key)        # has TALLY_AGGREGATOR_ROLE
    aggregate(chain, election_addr, signer)
    finalize(chain, election_addr, signer)

CLI usage:

    python tally_aggregator.py aggregate --election 0x... --rpc-url ...
    python tally_aggregator.py finalize  --election 0x... --rpc-url ...
    python tally_aggregator.py daemon    --election 0x... --rpc-url ...

The signer's private key is read from ``--private-key`` or, preferably,
the ``TALLY_AGGREGATOR_PRIVATE_KEY`` environment variable.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Optional

import requests
from eth_account import Account
from eth_account.signers.local import LocalAccount

import coordinator_state
import sdk_compat
from crypto.elgamal import threshold_decrypt
from crypto.primitives import (
    Z2,
    g2_from_compressed,
    g2_to_compressed,
    point_add,
)
from eth_client import BallotProofError, ElectionClient, EthChain


# ---------------------------------------------------------------------------
#  Errors
# ---------------------------------------------------------------------------

class TallyAggregatorError(RuntimeError):
    """Raised when the on-chain aggregator can't proceed.

    ``data`` carries any structured detail (e.g. per-ballot rejection
    reasons) the caller might want to surface.
    """

    def __init__(self, message: str, *, data: Optional[dict] = None):
        super().__init__(message)
        self.data = data or {}


# ---------------------------------------------------------------------------
#  Result types
# ---------------------------------------------------------------------------

@dataclass
class AggregateResult:
    tx_hash: str
    block_number: int
    ballots_total: int
    ballots_admitted: int
    ballots_rejected: int
    rejections: list[dict]
    ballots_superseded: int
    superseded: list[dict]
    voters_counted: int
    candidates: int

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class FinalizeResult:
    tx_hash: str
    block_number: int
    totals: list[int]
    keyper_indices: list[int]

    def as_dict(self) -> dict:
        return self.__dict__.copy()


# ---------------------------------------------------------------------------
#  aggregate
# ---------------------------------------------------------------------------

def aggregate(
    chain: EthChain,
    election_address: str,
    signer: LocalAccount,
) -> AggregateResult:
    """Read ballots from chain → SDK-verify each → sum admitted ones →
    ``publishAggregate``.

    Bad ballots are dropped with a structured ``reason`` and the
    aggregate proceeds on the survivors. Raises
    :class:`TallyAggregatorError` if no ballots can be admitted, the
    election's ``pkWR`` isn't set, or the ``publishAggregate`` tx itself
    reverts.
    """
    election = ElectionClient(chain, election_address)
    if not election.is_dkg_finalized():
        raise TallyAggregatorError("On-chain DKG not finalized")

    info = election.get_election()
    cfg_view = info["config"]
    num_cand = cfg_view["numCandidates"]
    budget = cfg_view["budget"]
    election_id_int = cfg_view["electionId"]
    election_id_bytes = sdk_compat.election_id_to_bytes32(election_id_int)
    mpk = g2_from_compressed(info["dkg"]["pkElection"])

    pk_wr = bytes(cfg_view["pkWR"])
    if len(pk_wr) != 48:
        raise TallyAggregatorError(
            f"Election pkWR length {len(pk_wr)} != 48 — election was "
            f"published without a WR public key; cannot verify attestations",
        )
    verify_wr = sdk_compat.make_wr_attestation_verifier(pk_wr)

    n_ballots = election.get_num_ballots()
    if n_ballots == 0:
        raise TallyAggregatorError("No ballots on chain")

    # Ballot rows come from storage; the zkProof for each comes from its
    # VoteSubmitted log and is checked against the on-chain commitment. A
    # missing or mismatched proof aborts the run -- it is never downgraded to
    # a per-ballot rejection, which would silently drop a valid vote and
    # publish a wrong tally.
    from_block = int(os.environ.get(DEPLOY_BLOCK_ENV, "0") or 0)
    try:
        ballots = election.get_all_ballots_with_proofs(from_block=from_block)
    except BallotProofError as e:
        raise TallyAggregatorError(
            f"Could not recover ballot proofs from logs: {e}",
            data={"from_block": from_block, "hint": f"set {DEPLOY_BLOCK_ENV} to the election's deploy block"},
        ) from e
    c1_acc = [Z2] * num_cand
    c2_acc = [Z2] * num_cand
    rejections: list[dict] = []
    superseded: list[dict] = []

    def _verify(idx: int) -> tuple[bool, str | None]:
        b = ballots[idx]
        return sdk_compat.verify_ballot(
            mpk=mpk,
            election_id=election_id_bytes,
            pseudonym=bytes(b["pseudonym"]),
            vk_bytes=bytes(b["vk"]),
            ciphertext_bytes=[(bytes(ct[0]), bytes(ct[1])) for ct in b["ciphertexts"]],
            zk_proof=bytes(b["zkProof"]),
            voter_signature=bytes(b["voterSignature"]),
            wr_attestation=bytes(b["wrAttestation"]),
            num_candidates=num_cand,
            budget=budget,
            verify_wr=verify_wr,
        )

    # ------------------------------------------------------------------
    #  Re-vote selection: LATEST VALID per pseudonym.
    #
    #  The contract appends a ballot record per submission and points
    #  ballotIndexPlusOneByPseudonym at the newest, so one pseudonym can own
    #  several ballots. Counting them all would count that voter twice.
    #
    #  The rule, which MUST match voting-dashboard's generated
    #  verify-aggregate.js byte for byte -- otherwise an auditor selects a
    #  different ballot and computes a different aggregate:
    #
    #    for each pseudonym, walk its ballots newest -> oldest and count the
    #    first that verifies; if none verify, that voter contributes nothing.
    #
    #  Ballots older than the selected one are never verified: they are
    #  superseded regardless of validity. Ballots newer than it were tried and
    #  failed, so they appear in `rejections` as well as `superseded`.
    # ------------------------------------------------------------------
    by_pseudonym: dict[bytes, list[int]] = {}
    for idx, b in enumerate(ballots):
        by_pseudonym.setdefault(bytes(b["pseudonym"]), []).append(idx)

    selected: list[int] = []
    for pseudonym, idxs in by_pseudonym.items():
        chosen: int | None = None
        for idx in sorted(idxs, reverse=True):
            ok, reason = _verify(idx)
            if ok:
                chosen = idx
                break
            rejections.append({"ballot_index": idx, "reason": reason})
        if chosen is None:
            continue
        selected.append(chosen)
        # Only ballots OLDER than the counted one are superseded: they were
        # never verified, because a newer ballot already won. Newer ballots
        # were tried and failed, so they are rejections -- categorising them
        # as both would double-count and the three categories would not sum
        # to the ballot total.
        for idx in idxs:
            if idx < chosen:
                superseded.append({
                    "ballot_index": idx,
                    "superseded_by": chosen,
                    "pseudonym": pseudonym.hex(),
                })

    for idx in sorted(selected):
        b = ballots[idx]
        for j in range(num_cand):
            c1 = g2_from_compressed(b["ciphertexts"][j][0])
            c2 = g2_from_compressed(b["ciphertexts"][j][1])
            c1_acc[j] = point_add(c1_acc[j], c1)
            c2_acc[j] = point_add(c2_acc[j], c2)
    admitted = len(selected)

    if admitted == 0:
        raise TallyAggregatorError(
            "No countable ballots: every voter's ballots failed verification",
            data={"rejections": rejections, "superseded": superseded},
        )

    aggregate_bytes = [
        (g2_to_compressed(c1_acc[j]), g2_to_compressed(c2_acc[j]))
        for j in range(num_cand)
    ]
    try:
        receipt = election.publish_aggregate(aggregate_bytes, signer=signer)
    except Exception as e:
        raise TallyAggregatorError(f"publishAggregate reverted: {e}") from e

    return AggregateResult(
        tx_hash=receipt["transactionHash"].hex(),
        block_number=int(receipt["blockNumber"]),
        ballots_total=n_ballots,
        ballots_admitted=admitted,
        ballots_rejected=len(rejections),
        rejections=rejections,
        ballots_superseded=len(superseded),
        superseded=superseded,
        voters_counted=len(selected),
        candidates=num_cand,
    )


# ---------------------------------------------------------------------------
#  finalize
# ---------------------------------------------------------------------------

def finalize(
    chain: EthChain,
    election_address: str,
    signer: LocalAccount,
) -> FinalizeResult:
    """Read shares + committee + aggregate → DLEQ-verify → Lagrange + BSGS →
    ``publishResult``.

    Picks the first ``thresholdT`` verified shares per candidate. Raises
    :class:`TallyAggregatorError` if not enough shares verify, BSGS fails
    (suggests an upper-bound mismatch), or the ``publishResult`` tx reverts.
    """
    election = ElectionClient(chain, election_address)
    if not election.is_dkg_finalized():
        raise TallyAggregatorError("On-chain DKG not finalized")
    if election.is_result_finalized():
        raise TallyAggregatorError("Result already finalized")

    info = election.get_election()
    eid = info["config"]["electionId"]
    num_cand = info["config"]["numCandidates"]
    threshold = info["config"]["thresholdT"]
    committee_pks = [g2_from_compressed(p) for p in info["dkg"]["committeePKs"]]

    try:
        agg = election.get_aggregate()
    except Exception as e:
        raise TallyAggregatorError(f"Aggregate not yet published: {e}") from e
    agg_pts = [
        (g2_from_compressed(c[0]), g2_from_compressed(c[1])) for c in agg["aggregates"]
    ]
    if len(agg_pts) != num_cand:
        raise TallyAggregatorError(
            f"Aggregate length {len(agg_pts)} != numCandidates {num_cand}",
        )

    on_chain_shares = election.get_decryption_shares()
    if len(on_chain_shares) < threshold:
        raise TallyAggregatorError(
            f"Only {len(on_chain_shares)} keypers submitted shares; need {threshold}",
        )

    n_ballots = election.get_num_ballots()
    budget = info["config"]["budget"]
    max_val = n_ballots * budget

    totals: list[int] = []
    used_keyper_indices: list[int] = []
    for j in range(num_cand):
        verified: list[tuple[int, object, int]] = []  # (dkg_id, sigma, member_idx)
        for s in on_chain_shares:
            k_member = s["keyperIndex"]
            k_dkg = k_member + 1
            if k_member >= len(committee_pks):
                continue
            mpk_k = committee_pks[k_member]
            try:
                sigma = g2_from_compressed(s["shares"][j])
            except Exception:
                continue
            e_scalar, z_scalar = s["proofs"][j]
            t_v = sdk_compat.make_onchain_decrypt_transcript(eid, j)
            if not sdk_compat.verify_decryption_share(
                t_v, agg_pts[j][0], agg_pts[j][1],
                mpk_k, sigma, e_scalar, z_scalar, keyper_index=k_dkg,
            ):
                continue
            verified.append((k_dkg, sigma, k_member))
            if len(verified) >= threshold:
                break

        if len(verified) < threshold:
            raise TallyAggregatorError(
                f"Candidate {j}: only {len(verified)} verified shares (need {threshold})",
            )

        shares_for_decrypt = [(kid, sigma) for (kid, sigma, _km) in verified]
        m = threshold_decrypt(agg_pts[j][0], agg_pts[j][1], shares_for_decrypt, max_val)
        if m is None:
            raise TallyAggregatorError(
                f"BSGS failed for candidate {j} (max_val={max_val})",
            )
        totals.append(int(m))

        if not used_keyper_indices:
            used_keyper_indices = [km for (_kid, _s, km) in verified]

    try:
        receipt = election.publish_result(totals, used_keyper_indices, signer=signer)
    except Exception as e:
        raise TallyAggregatorError(f"publishResult reverted: {e}") from e

    return FinalizeResult(
        tx_hash=receipt["transactionHash"].hex(),
        block_number=int(receipt["blockNumber"]),
        totals=totals,
        keyper_indices=used_keyper_indices,
    )

def _now_ts(chain: EthChain) -> int:
    return int(chain.w3.eth.get_block("latest")["timestamp"])


def _aggregate_published(election: ElectionClient) -> bool:
    try:
        election.get_aggregate()
        return True
    except Exception:
        return False


def _keyper_urls_from_env() -> list[str]:
    raw = os.environ.get("KEYPER_URLS", "")
    return [u.strip().rstrip("/") for u in raw.split(",") if u.strip()]


def _trigger_keyper_decrypts(election_address: str, *, quiet: bool = False) -> None:
    """Best-effort trigger of each keyper's /decrypt/publish_on_chain.

    Reads the coordinator-tier bearer tokens lazily, right here at the
    point of use -- never at daemon startup. dkg-coordinator's one-shot
    bootstrap pass writes the shared token file early in the election, but
    there's no explicit start-order dependency between the two containers,
    so this process must not assume the file exists yet when it boots. By
    the time votingEnd has passed and the aggregate is published, the file
    will have long since been written in virtually every real run; if it's
    still missing (or a keyper has no entry in it -- single-operator dev
    mode, where bootstrapping never runs at all), the request is simply
    sent with no Authorization header, which keyper.py accepts as long as
    it isn't itself configured to require auth. A failed or unauthorized
    call here is not fatal -- daemon()'s own poll loop is the retry
    mechanism, since this is only ever called while still waiting for the
    share threshold.

    Idempotent on the keyper side (a keyper that already submitted returns
    a structured "skipped" response, not an error), so re-triggering every
    poll cycle is safe and self-heals a keyper that was briefly down.
    """
    keyper_urls = _keyper_urls_from_env()
    if not keyper_urls:
        if not quiet:
            print("[daemon] KEYPER_URLS not set -- cannot trigger keyper decrypt", file=sys.stderr)
        return

    tokens = coordinator_state.load_tokens()
    for url in keyper_urls:
        api_token = tokens.get(url, {}).get("api_token", "")
        headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}
        try:
            r = requests.post(f"{url}/decrypt/publish_on_chain",
                               json={"election_address": election_address},
                               headers=headers, timeout=30)
            r.raise_for_status()
            if not quiet:
                print(f"[daemon] triggered decrypt at {url}: {r.json()}")
        except Exception as e:
            if not quiet:
                print(f"[daemon] decrypt trigger failed at {url}: {e}", file=sys.stderr)


def daemon(
    chain: EthChain,
    election_address: str,
    signer: LocalAccount,
    *,
    poll: float = 10.0,
    quiet: bool = False,
) -> int:
    """Long-running poll-and-act loop.

    - Wait until voting has ended (on-chain), then publishAggregate if missing.
    - Wait until thresholdT decryption shares are present, then publishResult.
    - Exit after result is finalized.

    This is intentionally idempotent: it re-checks on-chain state before
    attempting writes and tolerates being restarted mid-election.
    """
    election = ElectionClient(chain, election_address)

    while True:
        try:
            if election.is_result_finalized():
                if not quiet:
                    print("[daemon] result already finalized")
                return 0

            if not election.is_dkg_finalized():
                if not quiet:
                    print("[daemon] waiting: DKG not finalized yet")
                time.sleep(poll)
                continue

            phase = int(election.get_phase())
            # Election.getPhase(): >=4 implies votingEnd has passed.
            if phase < 4:
                if not quiet:
                    info = election.get_election()
                    ve = int(info["config"]["votingEnd"])
                    now = _now_ts(chain)
                    left = ve - now
                    print(f"[daemon] waiting: voting still open (phase={phase}, votingEnd-now={left}s)")
                time.sleep(poll)
                continue

            if not _aggregate_published(election):
                if not quiet:
                    print("[daemon] publishing aggregate…")
                agg = aggregate(chain, election_address, signer)
                if not quiet:
                    print(json.dumps(agg.as_dict(), indent=2, default=str))
                time.sleep(poll)
                continue

            info = election.get_election()
            threshold = int(info["config"]["thresholdT"])
            shares = election.get_decryption_shares()
            if len(shares) < threshold:
                _trigger_keyper_decrypts(election_address, quiet=quiet)
                if not quiet:
                    print(f"[daemon] waiting: shares on chain {len(shares)}/{threshold}")
                time.sleep(poll)
                continue

            if not quiet:
                print("[daemon] finalizing result…")
            fin = finalize(chain, election_address, signer)
            if not quiet:
                print(json.dumps(fin.as_dict(), indent=2, default=str))
            return 0

        except TallyAggregatorError as e:
            # Expected transient failures (e.g. not enough shares, pkWR unset)
            # should not crash the daemon. Surface the error and keep polling.
            if not quiet:
                print(f"[daemon] error: {e}", file=sys.stderr)
                if e.data:
                    print(json.dumps(e.data, indent=2), file=sys.stderr)
            time.sleep(poll)
        except KeyboardInterrupt:
            print("\n[daemon] interrupted", file=sys.stderr)
            return 130
        except Exception as e:
            # Unknown error: surface and keep trying. Operators can kill if needed.
            if not quiet:
                print(f"[daemon] unexpected error: {e}", file=sys.stderr)
            time.sleep(poll)


# ---------------------------------------------------------------------------
#  CLI
# ---------------------------------------------------------------------------

PRIVATE_KEY_ENV = "TALLY_AGGREGATOR_PRIVATE_KEY"
RPC_URL_ENV = "RPC_URL"
ELECTION_ADDRESS_ENV = "ELECTION_ADDRESS"
POLL_SECONDS_ENV = "TALLY_POLL_SECONDS"
# Block to start the VoteSubmitted log scan from. Proofs live in logs, not
# storage, so recovering them means an eth_getLogs range. On a public chain,
# scanning from 0 will be refused or time out -- set this to the election's
# deployment block. Default 0 is fine for a local devnet.
DEPLOY_BLOCK_ENV = "ELECTION_DEPLOY_BLOCK"


def _resolve_signer(args) -> LocalAccount:
    pk = args.private_key or os.environ.get(PRIVATE_KEY_ENV)
    if not pk:
        raise SystemExit(
            f"private key required: pass --private-key or set ${PRIVATE_KEY_ENV}",
        )
    return Account.from_key(pk)


def _resolve_rpc_url(args) -> str:
    rpc_url = args.rpc_url or os.environ.get(RPC_URL_ENV)
    if not rpc_url:
        raise SystemExit(f"RPC URL required: pass --rpc-url or set ${RPC_URL_ENV}")
    return rpc_url


def _resolve_election(args) -> str:
    election = args.election or os.environ.get(ELECTION_ADDRESS_ENV)
    if not election:
        raise SystemExit(f"election address required: pass --election or set ${ELECTION_ADDRESS_ENV}")
    return election


def _add_common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--rpc-url", default=None,
                   help=f"Ethereum RPC URL. Prefer ${RPC_URL_ENV}.")
    p.add_argument("--election", default=None,
                   help=f"Election contract address. Prefer ${ELECTION_ADDRESS_ENV}.")
    p.add_argument("--private-key", default=None,
                   help=f"Hex private key (TALLY_AGGREGATOR_ROLE). "
                        f"Prefer ${PRIVATE_KEY_ENV}.")


def _print_result(result_obj) -> None:
    print(json.dumps(result_obj.as_dict(), indent=2, default=str))


def _cmd_aggregate(args) -> int:
    signer = _resolve_signer(args)
    rpc_url = _resolve_rpc_url(args)
    election = _resolve_election(args)
    chain = EthChain.connect(rpc_url, private_key=args.private_key
                             or os.environ.get(PRIVATE_KEY_ENV))
    try:
        res = aggregate(chain, election, signer)
    except TallyAggregatorError as e:
        print(f"aggregate failed: {e}", file=sys.stderr)
        if e.data:
            print(json.dumps(e.data, indent=2), file=sys.stderr)
        return 1
    _print_result(res)
    return 0


def _cmd_finalize(args) -> int:
    signer = _resolve_signer(args)
    rpc_url = _resolve_rpc_url(args)
    election = _resolve_election(args)
    chain = EthChain.connect(rpc_url, private_key=args.private_key
                             or os.environ.get(PRIVATE_KEY_ENV))
    try:
        res = finalize(chain, election, signer)
    except TallyAggregatorError as e:
        print(f"finalize failed: {e}", file=sys.stderr)
        if e.data:
            print(json.dumps(e.data, indent=2), file=sys.stderr)
        return 1
    _print_result(res)
    return 0


def _cmd_daemon(args) -> int:
    signer = _resolve_signer(args)
    rpc_url = _resolve_rpc_url(args)
    election = _resolve_election(args)
    poll = args.poll if args.poll is not None else float(os.environ.get(POLL_SECONDS_ENV, "10"))
    chain = EthChain.connect(rpc_url, private_key=args.private_key
                             or os.environ.get(PRIVATE_KEY_ENV))
    return daemon(
        chain,
        election,
        signer,
        poll=poll,
        quiet=args.quiet,
    )


def main():
    parser = argparse.ArgumentParser(
        description="Standalone Tally Aggregator (PLAN.md decision E)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_agg = sub.add_parser("aggregate", help="Read ballots, verify, publishAggregate")
    _add_common_args(p_agg)
    p_agg.set_defaults(func=_cmd_aggregate)

    p_fin = sub.add_parser("finalize", help="Read shares, Lagrange + BSGS, publishResult")
    _add_common_args(p_fin)
    p_fin.set_defaults(func=_cmd_finalize)

    p_daemon = sub.add_parser("daemon", help="Watch chain and finalize automatically")
    _add_common_args(p_daemon)
    p_daemon.add_argument("--poll", type=float, default=None,
                          help=f"Seconds between polls (default 10). Prefer ${POLL_SECONDS_ENV}.")
    p_daemon.add_argument("--quiet", action="store_true",
                          help="Reduce log output (errors still printed)")
    p_daemon.set_defaults(func=_cmd_daemon)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
