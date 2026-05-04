"""
web3.py wrappers around the production voting contracts.

ABIs are loaded from the vendored ``abis/`` folder at the repo root — see
``PLAN.md`` §7 and ``abis/README.md`` for refresh instructions.

Three contract wrappers are exposed:

  * ``KeyperSetClient``     — read-only views over the keyper committee.
  * ``RegistryClient``      — read + admin ``publishElection``.
  * ``ElectionClient``      — full per-election lifecycle (DKG vote,
                              ballot submit, decryption share submit,
                              aggregate / result publish, all reads).

A single ``EthChain`` helper owns the ``Web3`` instance and a default
signer; per-role signers are passed explicitly to write methods.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.contract import Contract


# ----------------------------------------------------------------------
#  ABI loading
# ----------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
_ABI_DIR = _REPO_ROOT / "abis"


def _load_abi(name: str) -> list:
    path = _ABI_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(
            f"ABI {name}.json not found at {path}. See abis/README.md to refresh."
        )
    with path.open() as f:
        return json.load(f)


# ----------------------------------------------------------------------
#  Chain / signer container
# ----------------------------------------------------------------------

@dataclass
class EthChain:
    """Holds a ``Web3`` instance plus a default signing account."""

    w3: Web3
    chain_id: int
    default_account: LocalAccount | None = None

    @classmethod
    def connect(
        cls,
        rpc_url: str,
        private_key: str | None = None,
    ) -> "EthChain":
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
        if not w3.is_connected():
            raise ConnectionError(f"Could not connect to {rpc_url}")
        chain_id = w3.eth.chain_id
        acct = Account.from_key(private_key) if private_key else None
        return cls(w3=w3, chain_id=chain_id, default_account=acct)

    # --- transaction helpers ---

    def send(
        self,
        fn,
        *,
        signer: LocalAccount | None = None,
        value: int = 0,
        gas: int | None = None,
    ) -> dict:
        """Build, sign, send a transaction; wait for receipt and return it.

        ``fn`` is a bound contract function, e.g.
        ``election.functions.submitVote(ballot)``.
        """
        acct = signer or self.default_account
        if acct is None:
            raise ValueError("No signer configured (pass signer= or set default_account)")

        tx = fn.build_transaction({
            "from": acct.address,
            "nonce": self.w3.eth.get_transaction_count(acct.address),
            "chainId": self.chain_id,
            "value": value,
            **({"gas": gas} if gas is not None else {}),
        })
        signed = acct.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        if receipt.status != 1:
            raise RuntimeError(f"Transaction failed: {tx_hash.hex()}")
        return dict(receipt)


# ----------------------------------------------------------------------
#  Contract clients
# ----------------------------------------------------------------------

class _BaseClient:
    abi_name: str = ""  # override

    def __init__(self, chain: EthChain, address: str):
        self.chain = chain
        self.address = Web3.to_checksum_address(address)
        abi = _load_abi(self.abi_name)
        self.contract: Contract = chain.w3.eth.contract(address=self.address, abi=abi)


class KeyperSetClient(_BaseClient):
    """Production ``KeyperSet`` is immutable on construction — there is no
    ``isFinalized``, no owner, no setters. Members and threshold are baked
    in at deploy time.
    """

    abi_name = "KeyperSet"

    # --- views ---

    def get_num_members(self) -> int:
        return int(self.contract.functions.getNumMembers().call())

    def get_member(self, index: int) -> str:
        return self.contract.functions.getMember(index).call()

    def get_members(self) -> list[str]:
        return list(self.contract.functions.getMembers().call())

    def get_member_index(self, account: str) -> int:
        return int(self.contract.functions.getMemberIndex(
            Web3.to_checksum_address(account)
        ).call())

    def get_threshold(self) -> int:
        return int(self.contract.functions.getThreshold().call())

    def is_member(self, account: str) -> bool:
        return self.contract.functions.isMember(
            Web3.to_checksum_address(account)
        ).call()


class RegistryClient(_BaseClient):
    abi_name = "ElectionRegistry"

    # --- views ---

    def election_count(self) -> int:
        return int(self.contract.functions.electionCount().call())

    def elections(self, election_id: int) -> str:
        return self.contract.functions.elections(election_id).call()

    def get_elections(self, start: int, count: int) -> list[str]:
        return list(self.contract.functions.getElections(start, count).call())

    # --- writes ---

    def publish_election(
        self,
        keyper_set: str,
        params: dict,
        *,
        signer: LocalAccount | None = None,
    ) -> tuple[str, dict]:
        """Deploy a new ``Election`` via the registry.

        ``params`` is a dict matching ``VotingTypes.ElectionParams``:
            {
              "votingStart":     uint64,
              "votingEnd":       uint64,
              "selfSubmitFee":   uint256,
              "numCandidates":   uint32,
              "budget":          uint32,
              "pkWR":            bytes,
              "tallyAggregator": address,
              "voteProxy":       address,
            }

        Returns ``(election_address, receipt)``.
        """
        tuple_params = (
            int(params["votingStart"]),
            int(params["votingEnd"]),
            int(params["selfSubmitFee"]),
            int(params["numCandidates"]),
            int(params["budget"]),
            params["pkWR"],
            Web3.to_checksum_address(params["tallyAggregator"]),
            Web3.to_checksum_address(params["voteProxy"]),
        )
        fn = self.contract.functions.publishElection(
            Web3.to_checksum_address(keyper_set),
            tuple_params,
        )
        receipt = self.chain.send(fn, signer=signer)

        # Extract the ElectionCreated event. ``receipt['logs']`` includes
        # logs from the freshly deployed Election (RoleGranted, etc.) that
        # don't match this contract's ABI, so we filter to logs emitted by
        # the registry itself before parsing.
        own_logs = [lg for lg in receipt["logs"] if lg["address"].lower() == self.address.lower()]
        events = self.contract.events.ElectionCreated().process_receipt({"logs": own_logs})
        if not events:
            raise RuntimeError("publishElection succeeded but no ElectionCreated event found")
        return events[0]["args"]["election"], receipt


class ElectionClient(_BaseClient):
    abi_name = "Election"

    # --- config views ---

    def election_id(self) -> int:
        return int(self.contract.functions.electionId().call())

    def voting_start(self) -> int:
        return int(self.contract.functions.votingStart().call())

    def voting_end(self) -> int:
        return int(self.contract.functions.votingEnd().call())

    def num_candidates(self) -> int:
        return int(self.contract.functions.numCandidates().call())

    def budget(self) -> int:
        return int(self.contract.functions.budget().call())

    def self_submit_fee(self) -> int:
        return int(self.contract.functions.selfSubmitFee().call())

    def keyper_set_address(self) -> str:
        return self.contract.functions.keyperSet().call()

    def get_phase(self) -> int:
        return int(self.contract.functions.getPhase().call())

    def get_election(self) -> dict:
        """Return ``(ElectionConfigView, DKGResult)`` as nested dicts."""
        config, dkg = self.contract.functions.getElection().call()
        return {
            "config": {
                "electionId": int(config[0]),
                "votingStart": int(config[1]),
                "votingEnd": int(config[2]),
                "selfSubmitFee": int(config[3]),
                "numCandidates": int(config[4]),
                "budget": int(config[5]),
                "thresholdN": int(config[6]),
                "thresholdT": int(config[7]),
                "keyperAddresses": list(config[8]),
                "pkWR": bytes(config[9]),
            },
            "dkg": {
                "pkElection": bytes(dkg[0]),
                "committeePKs": [bytes(p) for p in dkg[1]],
            },
        }

    # --- DKG ---

    def is_dkg_finalized(self) -> bool:
        return self.contract.functions.isDKGFinalized().call()

    def vote_dkg_result(
        self,
        pk_election: bytes,
        committee_pks: Iterable[bytes],
        *,
        signer: LocalAccount | None = None,
    ) -> dict:
        fn = self.contract.functions.voteDKGResult(
            bytes(pk_election),
            [bytes(p) for p in committee_pks],
        )
        return self.chain.send(fn, signer=signer)

    # --- ballots ---

    def submit_vote(
        self,
        ballot: dict,
        *,
        signer: LocalAccount | None = None,
        value: int = 0,
    ) -> dict:
        """Submit a ballot. ``ballot`` matches ``VotingTypes.Ballot``:
            {
              "pseudonym":      bytes32,
              "vk":             bytes (48),
              "ciphertexts":    [(c1: bytes96, c2: bytes96), ...],
              "zkProof":        bytes,
              "voterSignature": bytes,
              "wrAttestation":  bytes,
            }
        """
        tuple_ballot = (
            bytes(ballot["pseudonym"]),
            bytes(ballot["vk"]),
            [(bytes(ct[0]), bytes(ct[1])) for ct in ballot["ciphertexts"]],
            bytes(ballot["zkProof"]),
            bytes(ballot["voterSignature"]),
            bytes(ballot["wrAttestation"]),
        )
        fn = self.contract.functions.submitVote(tuple_ballot)
        return self.chain.send(fn, signer=signer, value=value)

    def get_num_ballots(self) -> int:
        return int(self.contract.functions.getNumBallots().call())

    def get_ballots(self, start: int, count: int) -> list[dict]:
        raw = self.contract.functions.getBallots(start, count).call()
        return [_decode_ballot(b) for b in raw]

    def get_ballot(self, pseudonym: bytes) -> dict:
        raw = self.contract.functions.getBallot(bytes(pseudonym)).call()
        return _decode_ballot(raw)

    # --- decryption shares ---

    def submit_decryption_share(
        self,
        shares: Iterable[bytes],
        proofs: Iterable[tuple[int, int]],
        *,
        signer: LocalAccount | None = None,
    ) -> dict:
        fn = self.contract.functions.submitDecryptionShare(
            [bytes(s) for s in shares],
            [(int(e), int(z)) for (e, z) in proofs],
        )
        return self.chain.send(fn, signer=signer)

    def get_decryption_shares(self) -> list[dict]:
        raw = self.contract.functions.getDecryptionShares().call()
        return [
            {
                "keyperIndex": int(s[0]),
                "submittedAt": int(s[1]),
                "shares": [bytes(b) for b in s[2]],
                "proofs": [(int(p[0]), int(p[1])) for p in s[3]],
            }
            for s in raw
        ]

    # --- aggregate / result ---

    def publish_aggregate(
        self,
        aggregates: Iterable[tuple[bytes, bytes]],
        proof: bytes,
        *,
        signer: LocalAccount | None = None,
    ) -> dict:
        tally = (
            [(bytes(c[0]), bytes(c[1])) for c in aggregates],
            bytes(proof),
        )
        fn = self.contract.functions.publishAggregate(tally)
        return self.chain.send(fn, signer=signer)

    def get_aggregate(self) -> dict:
        aggregates, proof = self.contract.functions.getAggregate().call()
        return {
            "aggregates": [(bytes(c[0]), bytes(c[1])) for c in aggregates],
            "proof": bytes(proof),
        }

    def publish_result(
        self,
        totals: Iterable[int],
        keyper_indices: Iterable[int],
        *,
        signer: LocalAccount | None = None,
    ) -> dict:
        fn = self.contract.functions.publishResult(
            [int(t) for t in totals],
            [int(i) for i in keyper_indices],
        )
        return self.chain.send(fn, signer=signer)

    def is_result_finalized(self) -> bool:
        return self.contract.functions.isResultFinalized().call()

    def get_result(self) -> dict:
        totals, indices = self.contract.functions.getResult().call()
        return {"tally": [int(t) for t in totals], "keyperIndices": [int(i) for i in indices]}


# ----------------------------------------------------------------------
#  Helpers
# ----------------------------------------------------------------------

def _decode_ballot(raw: tuple) -> dict:
    return {
        "pseudonym": bytes(raw[0]),
        "vk": bytes(raw[1]),
        "ciphertexts": [(bytes(c[0]), bytes(c[1])) for c in raw[2]],
        "zkProof": bytes(raw[3]),
        "voterSignature": bytes(raw[4]),
        "wrAttestation": bytes(raw[5]),
    }
