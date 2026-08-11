# Threshold ElGamal Voting System

A threshold ElGamal encryption-based voting system over **BLS12-381** with homomorphic vote aggregation, distributed key generation, and zero-knowledge proofs.

Individual votes are encrypted client-side — the backend never sees plaintext. Votes are aggregated homomorphically, and only the final tally is decrypted by a threshold committee of keypers.


![Recording2026-04-13125741-ezgif com-speed](https://github.com/user-attachments/assets/12b670af-a213-44d6-a213-17170a72672c)


## Architecture

```
┌──────────┐   attest(electionId,pseudonym,vk)    ┌────────────┐
│  Voter    │ ───────────────────────────────────► │  WR oracle  │
│   CLI     │ ◄─────────────────────────────────── │   (dev)     │
└─────┬─────┘            wrAttestation             └────────────┘
      │
      │ contract-shaped ballot (ciphertexts + proofs + signatures + attestation)
      ▼
┌────────────┐        submitVote()        ┌─────────────────┐
│ Vote proxy  │ ─────────────────────────► │ Election contract│
│   (dev)     │                           │ (source of truth)│
└────────────┘                           └────────┬────────┘
                                                  │
                                                  │ publishAggregate / publishResult
                                                  ▼
                                           ┌────────────────┐
                                           │ Tally aggregator│
                                           │  (library/CLI)  │
                                           └────────────────┘

Keypers (committee):
  - signed P2P DKG between keypers (commitments + shares)
  - publish DKG result + decryption shares on-chain
```

**Voter CLI** — Encrypts votes locally, generates ZK proofs, fetches a WR attestation, and submits to the vote proxy.
**Vote Proxy (dev)** — Holds `VOTE_PROXY_ROLE` and forwards `submitVote` calls to the on-chain `Election` contract.
**Election contract** — Source of truth for election config, ballots, aggregate, decryption shares, and final result.
**Keyper Servers** — Threshold committee members. Participate in DKG (round-1 Feldman commitments and round-2 shares are exchanged directly between keypers over signed HTTP — see "Anti-equivocation" below) and provide decryption shares on chain.
**Anti-equivocation (signed P2P)** — Each DKG message is signed with the dealer's keyper key (recovered against its registered ``KeyperSet`` member address). A dealer that sends inconsistent commitments to different recipients is caught either by Feldman VSS verification at round 2 or, in the on-chain pipeline, by the ``voteDKGResult`` threshold vote failing to finalize.

## Cryptographic Primitives

| Component | Implementation |
|---|---|
| Curve | BLS12-381 G2 (Type-3 pairing curve, 255-bit scalar field, 128-bit security) |
| Encryption | ElGamal in the exponent over G2: C = (r·P₂, r·mpk + m·P₂) |
| Homomorphism | Component-wise EC point addition: Enc(a) + Enc(b) = Enc(a+b) |
| DKG | Feldman VSS (2-round protocol; round-1 commitments + round-2 shares delivered keyper-to-keyper over signed HTTP) |
| Range proofs | (B+1)-branch OR-composition of DLEQ proofs (Fiat-Shamir) |
| Budget proofs | DLEQ proof that Σvⱼ = B on aggregated ciphertext |
| Decryption proofs | DLEQ proof: dlog_{P₂}(mpkₖ) = dlog_{C₁}(σₖ) |
| DLog recovery | Baby-step giant-step on EC for small plaintexts |
| RNG | `secrets` module (CSPRNG) for all key material and proof randomness |
| Fiat-Shamir hash | SHA-256 with length-prefixed serialization and domain separation |
| Subgroup check | Cofactor-clearing verification on all deserialized G2 points |

## Election Lifecycle

1. **Create** — Admin publishes an on-chain election via `ElectionRegistry.publishElection`.
2. **DKG** — Keypers run 2-round Feldman VSS (commitments + shares delivered keyper-to-keyper over signed HTTP) then publish the DKG result on chain via `voteDKGResult`. Each keyper verifies the dealer's signature recovers to the expected member address before storing. Equivocation is caught either by Feldman VSS verification at round 2 (raising a complaint that the dkg coordinator resolves via signed share-reveal), or — in the on-chain pipeline — by the on-chain `voteDKGResult` threshold vote failing to finalize. The joint public key mpk is published.
3. **Voting** — Each voter encrypts their ballot client-side, generates range proofs (each vote in {0, …, B}) and a budget proof (sum = B), and submits a contract-shaped ballot via the vote proxy. The vote proxy validates all proofs before accepting.
4. **Tally** — The tally aggregator verifies all ballots (SDK-compatible), publishes the aggregate on chain, keypers publish decryption shares on chain, then the tally aggregator finalizes the result.

## Quick Start

```bash
cd src
pip install -r requirements.txt
```

### Run an election manually

```bash
# See RUNNING.md for the full on-chain pipeline (anvil + keypers + WR oracle + vote proxy + tally aggregator).
```

For the full on-chain end-to-end runbook, see `RUNNING.md` §3.

### Multi-operator deployment

For a real deployment — independently-operated keypers, each holding only
their own key, talking over a network with bearer-token auth and
encrypted persisted state — see `docker/README.md` and `RUNNING.md` §3c.
`docker-compose.keyper.yml` runs one keyper; `docker-compose.coordinator.yml`
runs `dkg-coordinator` (bootstraps tokens, drives DKG) and `tally-aggregator`
(publishes the aggregate, triggers keyper decryption, finalizes the result).

### Interactive TUI (recommended)

The admin TUI can launch all servers, create elections, run DKG, monitor ballots, and tally — all from one terminal:

```bash
cd src

# Launch with 3 keypers (default)
python admin_tui.py

# Or customize
python admin_tui.py --num-keypers 5

# Or point to existing servers
python admin_tui.py --keyper-urls http://127.0.0.1:5001,http://127.0.0.1:5002,http://127.0.0.1:5003
```

From the admin menu, use the on-chain flow (`1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9`),
then `q` to quit.

### Run tests

```bash
cd src

# Pure crypto unit + integration tests (no chain, no Flask)
python -m pytest tests/test_comprehensive.py -v

# On-chain e2e tests (anvil + forge required) -- full HTTP lifecycle
# with signed P2P keyper DKG, on real Election/KeyperSet contracts
python -m pytest tests/test_e2e_onchain.py -v

# Keyper P2P/DKG security regression tests
python tests/test_security_fixes.py

# Stress test (100 votes, 10 candidates, budget 10; on-chain)
python -u tests/test_stress.py

# Tally performance test (10,000 ballots; on-chain)
python -u tests/test_tally_perf.py

# Full test suite
pytest
```

Covers:
- **Unit tests** — BLS12-381 curve constants, G2 point arithmetic, serialization/deserialization with subgroup checks, ElGamal encryption/decryption, homomorphic addition, BSGS discrete log, Lagrange coefficients, DKG (various n/t, Feldman verification, bad share rejection), range/budget/decryption ZK proofs (completeness, soundness, tampering, domain separation, election binding).
- **Integration tests** — Full crypto pipeline (DKG → encrypt → prove → aggregate → threshold decrypt) without servers, including any-subset threshold property and decryption share proof verification.
- **On-chain e2e tests** — Full HTTP lifecycle with signed P2P keyper DKG against real contracts: single-choice elections, budget elections, late-keyper skip path, SDK transcript interop.
- **Security regression tests** — audit-driven checks on keyper P2P/DKG behavior.
- **Stress tests** — 100 concurrent votes with 10 candidates and budget 10; 10,000-ballot tally performance benchmarks.

## Project Structure

```
src/
├── crypto/
│   ├── primitives.py      # BLS12-381 G2 constants, point ops, Fiat-Shamir hash, serialization
│   ├── elgamal.py         # EC ElGamal encryption, homomorphic ops, BSGS, threshold decryption
│   ├── dkg.py             # Feldman VSS distributed key generation over G2
│   └── proofs.py          # ZK range, budget, and decryption share proofs (DLEQ)
├── tests/
│   ├── test_comprehensive.py  # Pure crypto + SDK-compat tests
│   ├── test_e2e_onchain.py    # On-chain end-to-end tests
│   ├── test_security_fixes.py # Keyper P2P/DKG security regression tests
│   ├── test_compressed_codecs.py # G1/G2 compressed point codec tests
│   ├── test_sdk_compat.py     # SDK transcript + codec fixtures + interop tests
│   ├── test_stress.py         # On-chain stress smoke tests
│   └── test_tally_perf.py     # On-chain perf smoke tests
├── keyper.py              # Keyper server (Flask) with signed P2P DKG (commitments + shares)
├── keyper_persistence.py  # Fernet-encrypted DKG secret / bootstrap-token persistence
├── token_bootstrap.py     # X25519 seal/unseal + EIP-191 payload hashing for /auth/bootstrap
├── coordinator_state.py   # Plaintext bootstrap_tokens.json hand-off (dkg-coordinator -> tally-aggregator)
├── voter.py               # Voter CLI
├── admin_tui.py           # Admin TUI with server management (rich)
├── dkg_coordinator.py     # Orchestrates keyper DKG HTTP APIs + publishes on-chain
├── tally_aggregator.py    # On-chain tally aggregator (library + CLI, no Flask)
├── vote_proxy.py          # Dev-only ballot forwarder
├── wr_oracle.py           # Dev Wahlregister-Server stub (Schnorr on G1)
├── chain_setup.py         # anvil + forge create + publishElection helpers
├── eth_client.py          # web3.py wrappers for KeyperSet / Registry / Election
├── sdk_compat.py          # Python port of the shutter-voting-sdk subset we need
└── requirements.txt

docker-compose.keyper.yml         # Multi-operator: one independently-run keyper
docker-compose.coordinator.yml    # Multi-operator: dkg-coordinator + tally-aggregator
```

## API Reference

### Keyper endpoints

Every endpoint below requires a bearer token once the keyper is started
with `COORDINATOR_ADDRESS` set (multi-operator mode — see "Multi-operator
deployment" below) — except `/status`, `/health`, and `/auth/bootstrap`,
which must stay reachable before any token exists to check against.

| Endpoint | Method | Description |
|---|---|---|
| `/status` | GET | Identity, encryption pubkey (+ signature), `bootstrapped`/`dkg_completed` flags |
| `/health` | GET | Liveness probe (uptime, DKG-in-progress flag) |
| `/auth/bootstrap` | POST | Coordinator-pushed bearer-token install (X25519 sealed box + EIP-191 signed) |
| `/dkg/round1` | POST | Generate polynomial + commitments + shares; pin election context |
| `/dkg/distribute_commitments` | POST | Fan out signed commitments to other keypers |
| `/dkg/receive_commitments` | POST | Append-only, signature-verified intake from a peer |
| `/dkg/distribute_shares` | POST | Fan out signed secret shares to other keypers |
| `/dkg/receive_share` | POST | Append-only, signature-verified intake from a peer |
| `/dkg/reveal_share` | POST | Accusation-gated signed share reveal for Feldman VSS complaint resolution — requires a recipient-signed `DKG-ACCUSE-v1` accusation naming this dealer (body: `{"accusation": {...}}`); reveals only the accuser's own share |
| `/dkg/round2` | POST | Verify received shares against received commitments |
| `/dkg/publish_on_chain` | POST | Submit `voteDKGResult` (chain mode only) |
| `/decrypt/publish_on_chain` | POST | Submit `submitDecryptionShare` (chain mode only) |

## Security Properties

**Implemented:**
- Ballot confidentiality (DDH assumption in G2, under SXDH — 128-bit security)
- Threshold decryption (t+1-of-n — no single keyper can decrypt)
- Vote validity (ZK range proofs: each vote in {0, …, B})
- Budget enforcement (ZK budget proof: Σvⱼ = B)
- Decryption correctness (DLEQ proofs on partial decryption shares, verified against DKG-established keys)
- Feldman VSS verification (detects dishonest keypers during DKG)
- Peer-to-peer DKG share distribution (a dealer never sends shares to a central service)
- Anti-equivocation via signed P2P DKG (EIP-191 over `(electionId, dealerId, recipientId, share)` / `(electionId, dealerId, commitments)`; receivers verify signature recovers to dealer's KeyperSet member address; appen-only per dealer)
- G2 subgroup membership validation on all deserialized points (cofactor attack protection)
- Ciphertext and commitment group membership validation
- CSPRNG for all secret material (`secrets` module)
- Fiat-Shamir hash with length-prefixed serialization (no concatenation collisions)
- Domain separation across proof types
- Budget proof Fiat-Shamir transcript binds P₂ and mpk per protocol spec
- Optional election ID binding in proofs
- Multi-operator keyper authentication (two-tier bearer tokens minted and
  pushed by `dkg-coordinator` over an X25519 sealed box, EIP-191 signed
  against a keyper's own configured `COORDINATOR_ADDRESS`; no unauthenticated
  route accepts caller-supplied peer addresses)
- Encrypted-at-rest keyper state (DKG secret, bootstrap tokens, bootstrap
  encryption keypair — Fernet, key derived from the keyper's own signing
  key) so a restart never needs a fresh DKG ceremony or re-bootstrap

**Not implemented (requires deployment context):**
- Voter authentication (OIDC / Keycloak)
- Ballot signatures and replay protection
- Transport encryption (HTTPS / TLS for P2P keyper channels)
- Phase-2 equivocation diagnostics (a digest-echo round between keypers so a misbehaving dealer is named locally instead of "DKG didn't reach threshold on chain"). Phase 1 — signed P2P + on-chain threshold vote — is shipped.
- Voter pseudonymization

## Dependencies

- **py_arkworks_bls12381** — BLS12-381 elliptic curve operations via Rust/arkworks bindings (50–730× faster than py_ecc)
- **Flask** — HTTP servers for keypers, vote proxy, and WR oracle
- **requests** — HTTP client for voter CLI, tally aggregator (chain reads), and keyper↔keyper signed P2P (commitments, shares, reveals)
- **eth-account / eth-utils** — EIP-191 personal_sign / recover used to authenticate every keyper-to-keyper DKG message
- **web3.py** — chain interactions against the production bulletin-board contracts
- **rich** — Terminal UI rendering (panels, tables, progress bars, live displays)

---

## Licence

Copyright (C) 2026 Brainbot GmbH

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License, version 3 only, as published
by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along
with this program. If not, see <https://www.gnu.org/licenses/>.

SPDX-License-Identifier: AGPL-3.0-only
