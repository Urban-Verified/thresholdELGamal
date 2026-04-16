# Threshold ElGamal Voting System

A threshold ElGamal encryption-based voting system over **BLS12-381** with homomorphic vote aggregation, distributed key generation, and zero-knowledge proofs.

Individual votes are encrypted client-side — the backend never sees plaintext. Votes are aggregated homomorphically, and only the final tally is decrypted by a threshold committee of keypers.


![Recording2026-04-13125741-ezgif com-speed](https://github.com/user-attachments/assets/12b670af-a213-44d6-a213-17170a72672c)


## Architecture

```
┌────────┐     encrypted vote + ZK proofs     ┌─────────┐     partial decryption     ┌──────────┐
│ Voter  │ ──────────────────────────────────► │ Backend │ ◄──────────────────────── │ Keyper 1 │
│  CLI   │                                     │ Server  │                            └──────────┘
└────────┘                                     │         │ ◄──────────────────────── ┌──────────┐
                                               │         │                            │ Keyper 2 │
                                               │         │                            └──────────┘
                                               │         │ ◄──────────────────────── ┌──────────┐
                                               │         │                            │ Keyper 3 │
                                               └─────────┘                            └──────────┘
                                                    │                                      │
                                                    │         ┌────────────────┐           │
                                                    └────────►│  Bulletin      │◄──────────┘
                                                              │  Board         │  commitments
                                                              │  (append-only) │  (anti-equivocation)
                                                              └────────────────┘
```

**Voter CLI** — Encrypts votes locally, generates ZK proofs, submits to backend.
**Backend Server** — Manages election lifecycle, validates proofs, aggregates ciphertexts, orchestrates decryption.
**Keyper Servers** — Threshold committee members. Participate in DKG and provide partial decryption shares.
**Bulletin Board** — Neutral append-only log. Keypers post DKG commitments here instead of relaying through the backend, preventing equivocation (no party can show different commitments to different recipients). Topics are freezable with SHA-256 digests for cross-verification.

## Cryptographic Primitives

| Component | Implementation |
|---|---|
| Curve | BLS12-381 G2 (Type-3 pairing curve, 255-bit scalar field, 128-bit security) |
| Encryption | ElGamal in the exponent over G2: C = (r·P₂, r·mpk + m·P₂) |
| Homomorphism | Component-wise EC point addition: Enc(a) + Enc(b) = Enc(a+b) |
| DKG | Feldman VSS (2-round protocol, peer-to-peer share delivery, bulletin board commitments) |
| Range proofs | (B+1)-branch OR-composition of DLEQ proofs (Fiat-Shamir) |
| Budget proofs | DLEQ proof that Σvⱼ = B on aggregated ciphertext |
| Decryption proofs | DLEQ proof: dlog_{P₂}(mpkₖ) = dlog_{C₁}(σₖ) |
| DLog recovery | Baby-step giant-step on EC for small plaintexts |
| RNG | `secrets` module (CSPRNG) for all key material and proof randomness |
| Fiat-Shamir hash | SHA-256 with length-prefixed serialization and domain separation |
| Subgroup check | Cofactor-clearing verification on all deserialized G2 points |

## Election Lifecycle

1. **Create** — Backend initializes election parameters for BLS12-381 G2 (no prime generation needed — curve parameters are fixed constants).
2. **DKG** — Backend coordinates 2-round Feldman VSS. Keypers post commitments to a neutral **bulletin board** (append-only, freezable); secret shares are distributed peer-to-peer between keypers (backend never sees them). All participants read identical commitments from the board and verify a SHA-256 digest, preventing equivocation. The joint public key mpk is published.
3. **Voting** — Each voter encrypts their ballot client-side, generates range proofs (each vote in {0, …, B}) and a budget proof (sum = B), and submits to the backend. The backend validates all proofs before accepting.
4. **Tally** — Backend homomorphically aggregates all ballots per candidate via EC point addition, then requests partial decryption shares (with DLEQ correctness proofs) from keypers. Only t+1 of n keypers are needed. Lagrange interpolation on EC points recovers m·P₂, then BSGS recovers m.

## Quick Start

```bash
cd src
pip install -r requirements.txt
```

### Run an election manually

```bash
# Start bulletin board
python bulletin_board.py --port 5500 &

# Start 3 keypers
python keyper.py --id 1 --port 5001 &
python keyper.py --id 2 --port 5002 &
python keyper.py --id 3 --port 5003 &

# Start backend
python backend.py --port 5000 --bb-url http://127.0.0.1:5500 \
  --keyper-urls http://127.0.0.1:5001,http://127.0.0.1:5002,http://127.0.0.1:5003
```

Then in another terminal:

```bash
# Check status
python voter.py status --backend http://127.0.0.1:5000

# Create election: 3 keypers, threshold t=1, 3 candidates, budget 1 (single-choice)
curl -X POST http://127.0.0.1:5000/election/create \
  -H "Content-Type: application/json" \
  -d '{"n": 3, "t": 1, "num_candidates": 3, "budget": 1,
       "candidate_names": ["Alice", "Bob", "Charlie"]}'

# Run DKG
curl -X POST http://127.0.0.1:5000/election/dkg

# Cast votes
python voter.py vote --backend http://127.0.0.1:5000 --choice 0   # vote for Alice
python voter.py vote --backend http://127.0.0.1:5000 --choice 1   # vote for Bob
python voter.py vote --backend http://127.0.0.1:5000 --votes 0,0,1 # vote for Charlie

# Tally
curl -X POST http://127.0.0.1:5000/election/tally

# View result
python voter.py result --backend http://127.0.0.1:5000
```

### Interactive TUI (recommended)

The admin TUI can launch all servers, create elections, run DKG, monitor ballots, and tally — all from one terminal:

```bash
cd src

# Launch with 3 keypers (default)
python admin_tui.py

# Or customize
python admin_tui.py --num-keypers 5 --backend-port 5000 --keyper-base-port 5001 --bb-port 5500

# Or point to existing servers
python admin_tui.py --keyper-urls http://127.0.0.1:5001,http://127.0.0.1:5002,http://127.0.0.1:5003
```

From the admin menu, press `0` to spin up the backend + all keypers as background threads, then walk through the election lifecycle.

The voter TUI provides an interactive voting experience with live encryption/proof visualization:

```bash
python voter_tui.py --backend http://127.0.0.1:5000
```

Features:
- **Admin TUI** — Server management, election creation wizard, DKG visualization, live ballot monitor, tally with protocol tree, bar chart results
- **Voter TUI** — Interactive candidate selection, live progress bars for encryption & ZK proof generation, ciphertext fingerprints, styled results display

### Run tests

```bash
cd src

# Full test suite (78 unit/integration/e2e tests)
python -m pytest tests/test_comprehensive.py -v

# Standalone E2E tests (4 HTTP lifecycle tests)
python -m pytest tests/test_e2e.py -v

# Stress test (100 votes, 10 candidates, budget 10)
python -u tests/test_stress.py

# Tally performance test (10,000 ballots)
python -u tests/test_tally_perf.py
```

78+ tests covering:
- **Unit tests** — BLS12-381 curve constants, G2 point arithmetic, serialization/deserialization with subgroup checks, ElGamal encryption/decryption, homomorphic addition, BSGS discrete log, Lagrange coefficients, DKG (various n/t, Feldman verification, bad share rejection), range/budget/decryption ZK proofs (completeness, soundness, tampering, domain separation, election binding).
- **Integration tests** — Full crypto pipeline (DKG → encrypt → prove → aggregate → threshold decrypt) without servers, including any-subset threshold property and decryption share proof verification.
- **E2E tests** — Full HTTP lifecycle with bulletin board, peer-to-peer DKG: single-choice elections, budget elections, 5-keyper elections, invalid vote rejection.
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
│   ├── test_comprehensive.py  # Full test suite (78 tests)
│   ├── test_e2e.py            # HTTP lifecycle E2E tests (4 tests)
│   ├── test_stress.py         # Stress test (100 votes, 10 candidates)
│   └── test_tally_perf.py     # Tally performance benchmark (10k ballots)
├── backend.py             # Election backend server (Flask)
├── bulletin_board.py      # Neutral append-only bulletin board (Flask)
├── keyper.py              # Keyper server (Flask) with P2P share delivery
├── voter.py               # Voter CLI
├── voter_tui.py           # Interactive voter TUI (rich)
├── admin_tui.py           # Admin TUI with server management (rich)
└── requirements.txt
```

## API Reference

### Backend

| Endpoint | Method | Description |
|---|---|---|
| `/election/create` | POST | Create election (n, t, candidates, budget) |
| `/election/dkg` | POST | Run distributed key generation (via bulletin board + P2P) |
| `/election/params` | GET | Get public parameters (curve, mpk, B, candidates, n, t) |
| `/election/vote` | POST | Submit encrypted vote with ZK proofs |
| `/election/tally` | POST | Aggregate and threshold-decrypt |
| `/election/result` | GET | Get final tally |
| `/election/status` | GET | Get election phase and metadata |
| `/election/reset` | POST | Reset election state |

### Bulletin Board

| Endpoint | Method | Description |
|---|---|---|
| `/bb/post` | POST | Post entry `{topic, sender_id, data}` (append-only, no overwrites) |
| `/bb/read/<topic>` | GET | Read all entries for a topic |
| `/bb/entry/<topic>/<id>` | GET | Read a single entry |
| `/bb/freeze` | POST | Freeze topic `{topic}` — returns SHA-256 digest |
| `/bb/digest/<topic>` | GET | Current topic digest |
| `/bb/status` | GET | Health check |

## Security Properties

**Implemented:**
- Ballot confidentiality (DDH assumption in G2, under SXDH — 128-bit security)
- Threshold decryption (t+1-of-n — no single keyper can decrypt)
- Vote validity (ZK range proofs: each vote in {0, …, B})
- Budget enforcement (ZK budget proof: Σvⱼ = B)
- Decryption correctness (DLEQ proofs on partial decryption shares, verified against DKG-established keys)
- Feldman VSS verification (detects dishonest keypers during DKG)
- Peer-to-peer DKG share distribution (backend never sees secret shares)
- Anti-equivocation bulletin board (append-only commitments, freezable topics, SHA-256 digest cross-verification)
- G2 subgroup membership validation on all deserialized points (cofactor attack protection)
- Ciphertext and commitment group membership validation
- CSPRNG for all secret material (`secrets` module)
- Fiat-Shamir hash with length-prefixed serialization (no concatenation collisions)
- Domain separation across proof types
- Budget proof Fiat-Shamir transcript binds P₂ and mpk per protocol spec
- Optional election ID binding in proofs

**Not implemented (requires deployment context):**
- Voter authentication (OIDC / Keycloak)
- Ballot signatures and replay protection
- Transport encryption (HTTPS / TLS for P2P keyper channels)
- Replicated / blockchain-backed bulletin board (current implementation is centralized in-memory)
- Voter pseudonymization

## Dependencies

- **py_arkworks_bls12381** — BLS12-381 elliptic curve operations via Rust/arkworks bindings (50–730× faster than py_ecc)
- **Flask** — HTTP servers for backend, keypers, and bulletin board
- **requests** — HTTP client for voter CLI, backend↔keyper coordination, keyper↔keyper P2P share delivery, and bulletin board access
- **rich** — Terminal UI rendering (panels, tables, progress bars, live displays)
