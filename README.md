# Urban Verified: Private and Verifiable Online Voting

The system lets people vote online in a way that:

- **keeps every vote secret.** Nobody, not even the people running the election, can see who voted for whom.
- **lets anyone check the result.** Every encrypted ballot and every step of the count is published, so anyone can confirm that the result is correct.

This README starts with the big picture, then explains each part of the system, then goes into the technical design and the technology used, and ends with how to run the code in this repository.

## Contents

1. [How it works (high level)](#1-how-it-works-high-level)
2. [Overview of the components](#2-overview-of-the-components)
3. [Technical architecture](#3-technical-architecture)
4. [Cryptography and Technology](#4-cryptography-and-technology)
5. [thresholdELGamal: working with this repository](#5-thresholdelgamal-working-with-this-repository)
6. [Licence](#licence)

---

## 1. How it works (high level)

### The idea in plain words

Think of a ballot box with a lock that needs several keys to open.

- The key to **lock** the box (the encryption key) is public. Every voter uses it to lock their own vote.
- The key to **unlock** the box is never held by one person. It is split between several independent guardians called **keypers**. A minimum number of them (for example 2 out of 3) must work together to unlock anything.
- The locked votes are **added up while they are still locked**. This is possible because of the kind of encryption we use (threshold ElGamal): adding locked votes gives a locked total.
- The keypers only ever unlock **the total**. Single ballots are never unlocked, so no single vote is ever revealed.

All of this happens on a public blockchain, which acts as a bulletin board that nobody can secretly change.

### The election, step by step

```
 1. Election is registered        An election is published on the blockchain
          │                       (candidates, voting window, keypers).
          ▼
 2. Keypers create the keys       The keypers run a joint key ceremony (DKG).
          │                       Result: one public encryption key. The
          │                       matching decryption key never exists in
          │                       one place; each keyper only holds a piece.
          ▼
 3. Voting opens
          │
          ▼
 4. Voters cast ballots           Each voter logs in, is checked for
          │                       eligibility, and their vote is encrypted
          │                       on their own device before it is sent.
          ▼
 5. Voting closes
          │
          ▼
 6. Ballots are added up          All valid ballots are added together while
          │                       still encrypted. The encrypted total is
          │                       published on the blockchain.
          ▼
 7. Keypers publish shares        Each keyper uses its key piece on the
          │                       encrypted total only, and publishes a
          │                       "decryption share" with a proof that it
          │                       did this honestly.
          ▼
 8. Shares are combined           Enough shares together unlock the total.
          │
          ▼
 9. Result is published           The final count per candidate is
                                  published on the blockchain.
```

At every step, anyone can open the [Voting Dashboard](https://github.com/Urban-Verified/voting-dashboard) to follow the election and check the cryptography in their own browser.

### High-level architecture

```
  ┌───────────────────────┐                 ┌───────────────────────┐
  │         Voter         │    1. log in    │  Login & eligibility  │
  │   (browser or app)    │  ───────────>   │                       │
  │                       │                 │ Voter Registry Oracle │
  │  Builds an encrypted  │   <───────────  │                       │
  │  ballot with the      │   2. "you may   │  checks eligibility,  │
  │  Shutter Voting SDK   │       vote"     │  issues a pseudonym   │
  └───────────────────────┘                 └───────────────────────┘
              │
              │  3. encrypted ballot + proofs
              v
  ┌───────────────────────┐
  │      Vote proxy       │
  │                       │
  │  submits the ballot   │
  │  to the blockchain    │
  └───────────────────────┘
              │
              │  4. ballot stored on chain
              v
  ┌─────────────────────────────────────────────────────────────────┐
  │           Blockchain bulletin board (smart contracts)           │
  │                                                                 │
  │   election config, public key, ballots, encrypted total,        │
  │   decryption shares, final result                               │
  └─────────────────────────────────────────────────────────────────┘
           ^                  │            ^                │
           │  public key,     │  read      │  encrypted     │  reads
           │  decryption      │  ballots   │  total, final  │  everything
           │  shares          v            │  result        v
  ┌──────────────────┐     ┌───────────────────┐    ┌───────────────────┐
  │     Keypers      │     │ Tally aggregator  │    │ Voting Dashboard  │
  │                  │ <── │                   │    │                   │
  │   independent    │     │ adds up ballots,  │    │ read-only, for    │
  │   operators      │     │ asks keypers to   │    │ everyone          │
  │                  │     │ decrypt, then     │    │                   │
  │                  │     │ publishes result  │    │                   │
  └──────────────────┘     └───────────────────┘    └───────────────────┘
           ^
           │  runs the key ceremony
           │
  ┌──────────────────┐
  │ DKG coordinator  │
  └──────────────────┘
```

---

## 2. Overview of the components

The system is split across four repositories, plus the login service and the Voter Registry Oracle.

| Component | What it does | Where |
|---|---|---|
| **Keypers, DKG coordinator, tally aggregator** | The backend services that create the election key, add up the encrypted ballots, and decrypt only the total. | This repository: [`thresholdELGamal`](https://github.com/Urban-Verified/thresholdELGamal) |
| **Bulletin board (smart contracts)** | The public, tamper-proof record of the election. An election registry publishes each new election. Each election contract stores the public key, all ballots, the encrypted total, the decryption shares and the result. | [`bulletin-board`](https://github.com/Urban-Verified/bulletin-board) |
| **Shutter Voting SDK (Urban Verified Crypto)** | A TypeScript library that encrypts votes and creates the proofs that a ballot is valid. It is used by the voting app to build ballots and by the dashboard to verify them. Published on npm as [`@shutter-network/urban-verified-crypto`](https://www.npmjs.com/package/@shutter-network/urban-verified-crypto). The stack uses version **0.1.2** (`^0.1.2`); later versions change the ballot format. | [`shutter-voting-sdk`](https://github.com/Urban-Verified/shutter-voting-sdk) |
| **Voting Dashboard** | A read-only website that follows each election through its phases. It shows the keys, ballots, encrypted total, decryption shares and result, and re-checks all the cryptography in the browser. Voters can also use "Find my vote" to confirm their ballot was recorded. | [`voting-dashboard`](https://github.com/Urban-Verified/voting-dashboard) |
| **Login and Voter Registry Oracle** | Voters log in through a **Keycloak** server. The **Voter Registry Oracle** (an eligibility service based on the electoral register, *Wahlregister*) checks that the person may vote, gives them a pseudonym, and signs a statement that this pseudonym is allowed to vote. Ballots without this signature are not counted. | Not part of these repositories |

---

## 3. Technical architecture

### 3.1 Roles and trust

| Role | Holds | Can do | Cannot do |
|---|---|---|---|
| **Election admin** | Admin key for `ElectionRegistry` | Publish elections, choose the keyper set | Decrypt anything |
| **Keyper** (N of them) | One secret key share | Publish a DKG result vote and a decryption share | Decrypt alone. At least T keypers (the threshold) must cooperate |
| **DKG coordinator** | Bearer tokens for keyper APIs | Trigger the steps of the key ceremony | See secret shares (they are sealed between keypers) |
| **Tally aggregator** | `TALLY_AGGREGATOR_ROLE` on the election | Publish the encrypted total and the final result | Change the result: anyone can recompute both from on-chain data |
| **Vote proxy** | `VOTE_PROXY_ROLE` on the election | Submit ballots on behalf of voters without paying the submission fee | Read or change a ballot (it is encrypted and signed by the voter) |
| **Voter Registry Oracle** | The `pkWR` signing key | Sign "this pseudonym may vote in this election" | Link a ballot to a vote choice |
| **Anyone** | Nothing | Read and verify every step | |

The main privacy assumption: **fewer than T keypers collude.** If T or more keypers worked together, they could decrypt individual ballots. This is why keypers should be run by independent organisations.

### 3.2 On-chain contracts

The contracts live in [`bulletin-board`](https://github.com/Urban-Verified/bulletin-board). Their ABIs are copied into [`abis/`](abis/README.md).

- **`KeyperSet`**: the fixed list of keyper addresses and the threshold T.
- **`ElectionRegistry`**: creates and indexes elections (`publishElection`). Election IDs start at 1.
- **`Election`**: one contract per election. It stores the configuration (voting window, number of candidates, budget, keyper set, `pkWR`) and everything published during the election.

`Election.getPhase()` returns:

| Value | Meaning |
|---|---|
| `0` | Registered, waiting for the key ceremony |
| `2` | Key ceremony done, waiting for voting to open |
| `3` | Voting open |
| `4` | Voting closed (tally can start) |

### 3.3 Key ceremony (DKG)

The keypers create the election key together using **Feldman verifiable secret sharing** in two rounds. No party ever holds the full secret key.

1. **Round 1, commitments.** Each keyper picks a random secret polynomial of degree T−1 and sends public commitments to it to every other keyper.
2. **Round 2, shares.** Each keyper sends every other keyper a private share of its polynomial. Each share is **sealed** (X25519 sealed box) to the receiver's key, so only that receiver can read it.
3. **Verify.** Each keyper checks every share it received against the sender's commitments. If a share is wrong, the receiver can file a signed accusation. The accused keyper must then reveal that one share so everyone can check who is lying.
4. **Publish.** Each keyper computes the joint public key `mpk` and the per-keyper public keys, and votes for this result on chain with `voteDKGResult`. Once T keypers vote for the same result, it is final and voting can begin.

Every keyper-to-keyper message is signed with the sender's Ethereum key and checked against its `KeyperSet` address. A keyper that sends different data to different peers is caught either by the share check in step 3 or because the on-chain vote never reaches the threshold.

The **DKG coordinator** only triggers these steps over HTTP (`round1 → distribute_commitments → distribute_shares → round2 → publish_on_chain`). Shares travel directly between keypers.

### 3.4 Casting a ballot

1. The voter logs in through **Keycloak**. The **Voter Registry Oracle** checks the electoral register, assigns a **pseudonym**, and signs an attestation over `electionId ∥ pseudonym ∥ vk`, where `vk` is a fresh signing key the voter's device generated for this ballot.
2. In the browser, the voting app uses the **Shutter Voting SDK** to:
   - encrypt one value per candidate under the election key `mpk`,
   - prove that each value is between `0` and the budget `B` (range proof),
   - prove that all values add up to exactly `B` (budget proof),
   - sign the ballot with the voter's key `vk` (Schnorr signature).
3. The ballot is sent to the **vote proxy**, which calls `Election.submitVote`.
4. The contract stores the pseudonym, `vk`, ciphertexts, signature, attestation and a hash of the proof. The full proof is emitted in the `VoteSubmitted` event log, which keeps the gas cost low enough for large ballots.

**Re-voting is allowed.** A voter can submit again with the same pseudonym. When counting, for each pseudonym the **newest ballot that passes all checks** is counted. Older ballots from that voter are ignored. The dashboard applies the same rule when it shows which ballots count, so anyone can reproduce the count.

### 3.5 Counting and decryption

Once voting closes, the **tally aggregator** (`daemon` mode does all of this automatically):

1. Reads every ballot from the contract and its proof from the event logs. It checks that each proof matches the hash stored on chain.
2. Checks every ballot: range proofs, budget proof, voter signature, and the Voter Registry Oracle's attestation against `pkWR`. Invalid ballots are skipped and reported.
3. Picks the newest valid ballot per pseudonym and adds the ciphertexts together per candidate.
4. Publishes the encrypted total with `publishAggregate`.
5. Calls each keyper's `/decrypt/publish_on_chain`. Each keyper computes its decryption share for the encrypted total only, with a proof that it used its real key share (DLEQ proof), and submits it with `submitDecryptionShare`.
6. When at least T shares are on chain, it checks each share's proof, combines T valid shares (Lagrange interpolation), recovers the number of votes per candidate, and publishes it with `publishResult`.

All of these steps can be repeated by anyone from public data. The Voting Dashboard checks the ballots and shares in the browser and provides scripts to repeat the rest.

### 3.6 Security properties

**In place:**

- **Ballot secrecy.** Votes are encrypted on the voter's device. Only the sum is ever decrypted, and only with T keypers.
- **Ballot validity.** Zero-knowledge proofs show each vote is in range and the total matches the budget, without revealing the vote.
- **Eligibility.** Only ballots with a valid attestation from the Voter Registry Oracle are counted.
- **One counted ballot per voter.** Re-votes replace earlier ballots (newest valid wins).
- **Honest decryption.** Every decryption share comes with a proof that is checked before use.
- **Honest key ceremony.** Feldman share checks, signed keyper messages, sealed shares between operators, and an on-chain threshold vote on the result. A bad share stops the ceremony; resolving it is a manual step.
- **Verifiability.** Every ballot, the encrypted total, every decryption share and the result are public on chain, together with their proofs. Anyone can recompute the count and check every proof without trusting the people running the election. The Voting Dashboard does the ballot and share checks in the browser.

---

## 4. Cryptography and Technology

This section lists the technology and the cryptographic building blocks used across the whole system. Section 3 explains when each one is used; here we only say what it is.

### 4.1 Technology stack

| Component | Language and main libraries |
|---|---|
| Bulletin board | Solidity 0.8, Foundry, OpenZeppelin access control. Runs on any EVM chain |
| Keyper, DKG coordinator, tally aggregator | Python 3.11+, Flask, `py_arkworks_bls12381` (Rust arkworks bindings), `web3.py`, `cryptography`. Packaged with Docker Compose |
| Urban Verified Crypto SDK | TypeScript, BLST compiled to WebAssembly, `viem` (keccak256). Version 0.1.2 |
| Voting Dashboard | React, Vite, `ethers` (chain reads), the SDK (ballot and share checks in the browser), i18next, ECharts |
| Voter login and eligibility | Keycloak (OpenID Connect) for login. The Voter Registry Oracle signs eligibility attestations (Schnorr on BLS12-381 G1) |

### 4.2 Elliptic curve: BLS12-381

All election cryptography runs on the pairing-friendly curve **BLS12-381** (about 128-bit security). It has two groups, and we use them for different jobs:

| Group | Point size (compressed) | Used for |
|---|---|---|
| **G1** | 48 bytes | Voter signing keys and signatures, Voter Registry Oracle key `pkWR` and attestations |
| **G2** | 96 bytes | Election public key `mpk`, keyper public keys, ciphertexts, decryption shares |

`P₁` and `P₂` are the standard generators of G1 and G2. Every point read from outside is checked to be in the correct prime-order subgroup before use. Note that we use the BLS12-381 curve, but not BLS signatures: all signatures on this curve are Schnorr signatures (see 4.5).

### 4.3 Encryption: threshold ElGamal in the exponent

A vote `m` (a small number) is encrypted under the election key `mpk` with fresh randomness `r`:

```
C = (C₁, C₂) = (r·P₂,  r·mpk + m·P₂)
```

- **Homomorphic addition.** Adding two ciphertexts point by point gives an encryption of the sum: `Enc(a) + Enc(b) = Enc(a + b)`.
- **Threshold decryption.** The secret key `sk` (with `mpk = sk·P₂`) is shared so that each keyper `k` holds `skₖ`. Keyper `k` publishes `σₖ = skₖ·C₁`. Any T shares are combined with Lagrange coefficients `λₖ` into `sk·C₁ = Σ λₖ·σₖ`, and then `m·P₂ = C₂ − sk·C₁`.
- **Recovering the number.** `m` is found from `m·P₂` with **baby-step giant-step**. This works because vote totals are small (at most the number of voters times the budget).

### 4.4 Distributed key generation: Feldman VSS

Each keyper `i` picks a random polynomial `fᵢ(x) = aᵢ₀ + aᵢ₁x + … + aᵢ,T−1 x^(T−1)`.

- **Commitments:** `Aᵢⱼ = aᵢⱼ·P₂` for each coefficient. Exactly T commitments are accepted per keyper.
- **Shares:** keyper `i` gives keyper `k` the value `fᵢ(k)`.
- **Share check:** keyper `k` accepts the share if `fᵢ(k)·P₂ = Σⱼ kʲ·Aᵢⱼ`.
- **Result:** keyper `k`'s secret share is `skₖ = Σᵢ fᵢ(k)`. The election key is `mpk = Σᵢ Aᵢ₀`, and each keyper public key `pkₖ = skₖ·P₂` can be computed by anyone from the commitments.

### 4.5 Signatures

| Signature | Scheme | Signs |
|---|---|---|
| Voter signature | Schnorr over G1, per-ballot key `vk = sk·P₁` | keccak256 of the canonical ballot message |
| Voter Registry Oracle attestation | Schnorr over G1, key `pkWR` | keccak256 of `electionId ∥ pseudonym ∥ vk` |
| Keyper P2P messages | Ethereum `personal_sign` (EIP-191, secp256k1) | DKG commitments, shares, accusations and reveals |
| Coordinator bootstrap | Ethereum `personal_sign` (EIP-191, secp256k1) | Bearer tokens pushed to keypers |
| On-chain transactions | Ethereum transactions (secp256k1) | Contract calls by keypers, aggregator, proxy and admin |

### 4.6 Zero-knowledge proofs

All proofs are non-interactive Sigma protocols (made non-interactive with Fiat-Shamir).

| Proof | Construction | Shows |
|---|---|---|
| **Range proof** (per candidate) | OR-composition of B+1 Chaum-Pedersen (DLEQ) branches | The ciphertext encrypts a value in `{0, 1, …, B}` |
| **Budget proof** (per ballot) | One Chaum-Pedersen (DLEQ) proof on the sum of the ballot's ciphertexts | The ballot's votes add up to exactly `B` |
| **Decryption share proof** (per keyper, per candidate) | Chaum-Pedersen (DLEQ) proof | `dlog_P₂(pkₖ) = dlog_C₁(σₖ)`, so the share was made with the keyper's real key |

The range proofs and the budget proof are packed into one ballot validity proof. Only its keccak256 hash is kept in contract storage; the full bytes are in the `VoteSubmitted` event.

### 4.7 Fiat-Shamir transcript and hashing

- Challenges come from a **transcript**: every public input is added with a label and a length prefix, and each challenge is fed back into the transcript.
- Transcripts use domain labels (ballot proofs, decryption shares and signatures each have their own; range and budget steps are separated by tags inside the ballot transcript) and are bound to the election ID, so a proof cannot be reused in another context.
- On-chain proofs and signatures use **keccak256**. Hash-to-scalar uses two keccak256 calls with different prefixes, reduced modulo the curve order.
- The TypeScript SDK and the Python services produce byte-identical transcripts. This is checked with shared test fixtures.

### 4.8 Transport and storage security

| Need | Technique |
|---|---|
| DKG shares between keypers | X25519 sealed box: one-time X25519 key exchange, HKDF, AES-GCM |
| Bearer tokens from coordinator to keyper | Same sealed box, plus an EIP-191 signature from the coordinator address |
| Keyper secrets at rest | Fernet (AES-CBC + HMAC), key derived from the keyper's own signing key |
| Randomness | Operating-system CSPRNG (Python `secrets`, Web Crypto in the browser) |

---

## 5. thresholdELGamal: working with this repository

This repository contains the keyper, the DKG coordinator and the tally aggregator, plus development stand-ins so a full election can run on one machine.

### 5.1 Services in this repository

| Service | Run by | Job |
|---|---|---|
| **Keyper** | Each keyper operator, on their own machine | Holds one piece of the decryption key. Takes part in the key ceremony and later publishes its decryption share for the encrypted total. |
| **DKG coordinator** | The election administrator | Sets up secure access to every keyper, then drives the key ceremony step by step. It never sees any secret key piece. |
| **Tally aggregator** | The election administrator | After voting closes: checks every ballot, adds up the valid ones, publishes the encrypted total, asks the keypers to decrypt, combines their shares and publishes the result. |

### 5.2 Project structure

```
src/
├── crypto/
│   ├── primitives.py         # BLS12-381 point ops, serialization
│   ├── elgamal.py            # ElGamal, homomorphic addition, BSGS, threshold decryption
│   ├── dkg.py                # Feldman VSS key ceremony
│   └── proofs.py             # Older SHA-256 proofs, used only by tests
├── keyper.py                 # Keyper server (Flask)
├── keyper_persistence.py     # Encrypted-at-rest keyper state
├── token_bootstrap.py        # Sealed + signed token hand-off from coordinator to keypers
├── dkg_coordinator.py        # Drives the key ceremony over the keyper APIs
├── coordinator_state.py      # Token hand-off file between coordinator and tally aggregator
├── tally_aggregator.py       # Aggregate, finalize, or run both as a daemon
├── eth_client.py             # web3.py wrappers for KeyperSet, ElectionRegistry, Election
├── sdk_compat.py             # Python port of the SDK: on-chain ballot and share proofs
├── chain_setup.py            # Local chain helpers (anvil + forge deploys)
├── admin_tui.py              # Terminal UI that runs a whole local election
├── voter.py                  # Dev voter CLI
├── vote_proxy.py             # Dev vote proxy (no validation; not for production)
├── wr_oracle.py              # Dev Voter Registry Oracle stub (signs for anyone; not for production)
├── tests/
└── requirements.txt

abis/                            # Contract ABIs copied from bulletin-board
docker/                          # Shared image build and coordinator entry point
docker-compose.keyper.yml        # One keyper, run by each keyper operator
docker-compose.coordinator.yml   # dkg-coordinator + tally-aggregator, run by the admin
```

`voter.py`, `vote_proxy.py` and `wr_oracle.py` are **development stand-ins** for the real voting app, vote proxy and Voter Registry Oracle, so the full flow can run locally.

`sdk_compat.py` is a Python port of the SDK parts the backend needs (ballot verification, decryption-share proofs, codecs). Shared test fixtures make sure it accepts exactly the same bytes as the TypeScript SDK.

### 5.3 Quick start (local demo)

Requirements: Python 3.11+, [Foundry](https://book.getfoundry.sh/getting-started/installation) (`anvil`, `forge`), and a clone of [`bulletin-board`](https://github.com/Urban-Verified/bulletin-board) next to this repository (built with `forge build`).

```bash
cd src
pip install -r requirements.txt

# Start a local chain, 3 keypers and all dev services, then drive
# the election from a menu
python admin_tui.py

# Or with a different committee size
python admin_tui.py --num-keypers 5
```

### 5.4 Further guides

| Guide | For |
|---|---|
| [`RUNNING.md`](RUNNING.md) | Full local run: TUI (§3a), each process by hand (§3b), Docker multi-operator (§3c), and tests |
| [`KEYPER_SETUP.md`](KEYPER_SETUP.md) | Keyper operators running their own keyper |
| [`docker/README.md`](docker/README.md) | Multi-operator Docker deployment, auth and bootstrap details |
| [`abis/README.md`](abis/README.md) | Refreshing the contract ABIs |

### 5.5 Tests

The tests use pytest, which is not in `requirements.txt`. Install it first with `pip install pytest`.

```bash
cd src

# Pure crypto unit + integration tests (no chain needed)
python -m pytest tests/test_comprehensive.py -v

# Python <-> TypeScript SDK compatibility
python -m pytest tests/test_sdk_compat.py tests/test_compressed_codecs.py -v

# On-chain e2e tests (anvil + forge required) -- full HTTP lifecycle
# with signed P2P keyper DKG, on real Election/KeyperSet contracts
python -m pytest tests/test_e2e_onchain.py -v

# Production-size election (10 candidates, budget 10) and re-vote rule
python -m pytest tests/test_production_shape.py tests/test_revote_dedup.py -v

# Keyper security regressions and the sealed multi-operator DKG
python tests/test_security_fixes.py
python tests/test_prod_sealed_dkg.py

# Load and performance (on-chain)
python -u tests/test_stress.py
python -u tests/test_tally_perf.py
```

### 5.6 Keyper API

Every endpoint below requires a bearer token once the keyper is started
with `COORDINATOR_ADDRESS` set; except `/status`, `/health`, and `/auth/bootstrap`,
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

### 5.7 Dependencies

- **py_arkworks_bls12381**: fast BLS12-381 operations (Rust arkworks bindings)
- **cryptography**: X25519 sealing and Fernet encryption at rest
- **Flask**: keyper server and dev services
- **requests**: HTTP between coordinator, aggregator and keypers
- **web3.py** (brings in `eth-account`): contract calls and message signing
- **rich**: terminal UI

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
