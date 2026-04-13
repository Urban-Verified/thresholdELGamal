# Threshold ElGamal Voting System

A threshold ElGamal encryption-based voting system over **BLS12-381** with homomorphic vote aggregation, distributed key generation, and zero-knowledge proofs.

Individual votes are encrypted client-side — the backend never sees plaintext. Votes are aggregated homomorphically, and only the final tally is decrypted by a threshold committee of keypers.

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
```

**Voter CLI** — Encrypts votes locally, generates ZK proofs, submits to backend.
**Backend Server** — Manages election lifecycle, validates proofs, aggregates ciphertexts, orchestrates decryption.
**Keyper Servers** — Threshold committee members. Participate in DKG and provide partial decryption shares.

## Cryptographic Primitives

| Component | Implementation |
|---|---|
| Curve | BLS12-381 G2 (Type-3 pairing curve, 255-bit scalar field, 128-bit security) |
| Encryption | ElGamal in the exponent over G2: C = (r·P₂, r·mpk + m·P₂) |
| Homomorphism | Component-wise EC point addition: Enc(a) + Enc(b) = Enc(a+b) |
| DKG | Feldman VSS (2-round protocol, peer-to-peer share delivery) |
| Range proofs | (B+1)-branch OR-composition of DLEQ proofs (Fiat-Shamir) |
| Budget proofs | DLEQ proof that Σvⱼ = B on aggregated ciphertext |
| Decryption proofs | DLEQ proof: dlog_{P₂}(mpkₖ) = dlog_{C₁}(σₖ) |
| DLog recovery | Baby-step giant-step on EC for small plaintexts |
| RNG | `secrets` module (CSPRNG) for all key material and proof randomness |
| Fiat-Shamir hash | SHA-256 with length-prefixed serialization and domain separation |
| Subgroup check | Cofactor-clearing verification on all deserialized G2 points |

## Election Lifecycle

1. **Create** — Backend initializes election parameters for BLS12-381 G2 (no prime generation needed — curve parameters are fixed constants).
2. **DKG** — Backend coordinates 2-round Feldman VSS. Commitments (public) flow through the backend; secret shares are distributed peer-to-peer between keypers (backend never sees them). The joint public key mpk is published.
3. **Voting** — Each voter encrypts their ballot client-side, generates range proofs (each vote in {0, …, B}) and a budget proof (sum = B), and submits to the backend. The backend validates all proofs before accepting.
4. **Tally** — Backend homomorphically aggregates all ballots per candidate via EC point addition, then requests partial decryption shares (with DLEQ correctness proofs) from keypers. Only t+1 of n keypers are needed. Lagrange interpolation on EC points recovers m·P₂, then BSGS recovers m.

## Quick Start

```bash
cd src
pip install -r requirements.txt
```

### Run an election manually

```bash
# Start 3 keypers
python keyper.py --id 1 --port 5001 &
python keyper.py --id 2 --port 5002 &
python keyper.py --id 3 --port 5003 &

# Start backend
python backend.py --port 5000 \
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

### Run tests

```bash
cd src
python -m unittest test_comprehensive -v
```

78 tests covering:
- **Unit tests** — BLS12-381 curve constants, G2 point arithmetic, serialization/deserialization with subgroup checks, ElGamal encryption/decryption, homomorphic addition, BSGS discrete log, Lagrange coefficients, DKG (various n/t, Feldman verification, bad share rejection), range/budget/decryption ZK proofs (completeness, soundness, tampering, domain separation, election binding).
- **Integration tests** — Full crypto pipeline (DKG → encrypt → prove → aggregate → threshold decrypt) without servers, including any-subset threshold property and decryption share proof verification.
- **E2E tests** — Full HTTP lifecycle with peer-to-peer DKG: single-choice elections, budget elections, invalid vote rejection.

## Project Structure

```
src/
├── crypto/
│   ├── primitives.py    # BLS12-381 G2 constants, point ops, Fiat-Shamir hash, serialization
│   ├── elgamal.py       # EC ElGamal encryption, homomorphic ops, BSGS, threshold decryption
│   ├── dkg.py           # Feldman VSS distributed key generation over G2
│   └── proofs.py        # ZK range, budget, and decryption share proofs (DLEQ)
├── backend.py           # Election backend server (Flask)
├── keyper.py            # Keyper server (Flask) with P2P share delivery
├── voter.py             # Voter CLI
├── test_e2e.py          # Standalone E2E tests (4 tests)
├── test_comprehensive.py # Full test suite (78 tests)
└── requirements.txt
```

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/election/create` | POST | Create election (n, t, candidates, budget) |
| `/election/dkg` | POST | Run distributed key generation (P2P share delivery) |
| `/election/params` | GET | Get public parameters (curve, mpk, B, candidates, n, t) |
| `/election/vote` | POST | Submit encrypted vote with ZK proofs |
| `/election/tally` | POST | Aggregate and threshold-decrypt |
| `/election/result` | GET | Get final tally |
| `/election/status` | GET | Get election phase and metadata |
| `/election/reset` | POST | Reset election state |

## Security Properties

**Implemented:**
- Ballot confidentiality (DDH assumption in G2, under SXDH — 128-bit security)
- Threshold decryption (t+1-of-n — no single keyper can decrypt)
- Vote validity (ZK range proofs: each vote in {0, …, B})
- Budget enforcement (ZK budget proof: Σvⱼ = B)
- Decryption correctness (DLEQ proofs on partial decryption shares, verified against DKG-established keys)
- Feldman VSS verification (detects dishonest keypers during DKG)
- Peer-to-peer DKG share distribution (backend never sees secret shares)
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
- Persistent storage / bulletin board
- Voter pseudonymization

## Dependencies

- **py_ecc** — BLS12-381 elliptic curve operations (optimized G2)
- **Flask** — HTTP servers for backend and keypers
- **requests** — HTTP client for voter CLI, backend↔keyper coordination, and keyper↔keyper P2P share delivery
