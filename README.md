# Threshold ElGamal Voting System

A threshold ElGamal encryption-based voting system with homomorphic vote aggregation, distributed key generation, and zero-knowledge proofs.

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
| Group | Safe prime p = 2q + 1, order-q subgroup of Z_p* |
| Encryption | ElGamal in the exponent: C = (g^r, pk^r · g^m) |
| Homomorphism | Component-wise multiplication: Enc(a) · Enc(b) = Enc(a+b) |
| DKG | Feldman Verifiable Secret Sharing (2-round protocol) |
| Range proofs | (B+1)-branch OR-composition of DLEQ proofs (Fiat-Shamir) |
| Budget proofs | DLEQ proof that sum(v_j) = B on aggregated ciphertext |
| Decryption proofs | DLEQ proof: log_g(mpk_k) = log_C1(sigma_k) |
| DLog recovery | Baby-step giant-step for small plaintexts |
| RNG | `secrets` module (CSPRNG) for all key material and proof randomness |
| Fiat-Shamir hash | SHA-256 with length-prefixed serialization and domain separation |

## Election Lifecycle

1. **Create** — Backend generates safe prime group parameters.
2. **DKG** — Backend coordinates 2-round Feldman VSS across all keypers. Each keyper gets a secret share; the joint public key mpk is published.
3. **Voting** — Each voter encrypts their ballot client-side, generates range proofs (each vote in [0, B]) and a budget proof (sum = B), and submits to the backend. The backend validates all proofs before accepting.
4. **Tally** — Backend homomorphically aggregates all ballots per candidate, then requests partial decryption shares (with DLEQ correctness proofs) from keypers. Only t+1 of n keypers are needed. Lagrange interpolation in the exponent recovers g^m, then BSGS recovers m.

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

96 tests covering:
- **Unit tests** — Group parameters, ElGamal encryption, homomorphic properties, BSGS, DKG (various n/t, Feldman verification, subset reconstruction), range/budget/decryption ZK proofs (completeness, soundness, tampering, domain separation, election binding), hash collision resistance, group membership validation.
- **Integration tests** — Full crypto pipeline (DKG → encrypt → prove → aggregate → threshold decrypt) without servers.
- **E2E tests** — Full HTTP lifecycle: single-choice elections, budget elections, invalid vote rejection, phase enforcement, election reset, 20-voter stress test, backend input validation.

## Project Structure

```
src/
├── crypto/
│   ├── primitives.py    # Group params, Fiat-Shamir hash, group element validation
│   ├── elgamal.py       # Encryption, homomorphic ops, BSGS, threshold decryption
│   ├── dkg.py           # Feldman VSS distributed key generation
│   └── proofs.py        # ZK range, budget, and decryption share proofs
├── backend.py           # Election backend server (Flask)
├── keyper.py            # Keyper server (Flask)
├── voter.py             # Voter CLI
├── test_e2e.py          # Original E2E tests (4 tests)
├── test_comprehensive.py # Full test suite (96 tests)
└── requirements.txt
```

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/election/create` | POST | Create election with group params |
| `/election/dkg` | POST | Run distributed key generation |
| `/election/params` | GET | Get public parameters (p, q, g, mpk, B, candidates) |
| `/election/vote` | POST | Submit encrypted vote with ZK proofs |
| `/election/tally` | POST | Aggregate and threshold-decrypt |
| `/election/result` | GET | Get final tally |
| `/election/status` | GET | Get election phase and metadata |
| `/election/reset` | POST | Reset election state |

## Security Properties

**Implemented:**
- Ballot confidentiality (DDH assumption in order-q subgroup)
- Threshold decryption (t+1-of-n — no single keyper can decrypt)
- Vote validity (ZK range proofs: each vote in [0, B])
- Budget enforcement (ZK budget proof: sum(v_j) = B)
- Decryption correctness (DLEQ proofs on partial decryption shares)
- Feldman VSS verification (detects dishonest keypers during DKG)
- Ciphertext and commitment group membership validation
- CSPRNG for all secret material (`secrets` module)
- Fiat-Shamir hash with length-prefixed serialization (no concatenation collisions)
- Domain separation across proof types
- Optional election ID binding in proofs

**Not implemented (requires deployment context):**
- Voter authentication (OIDC / Keycloak)
- Ballot signatures and replay protection
- Transport encryption (HTTPS)
- Persistent storage / bulletin board
- Voter pseudonymization

## Dependencies

- **pycryptodome** — Safe prime generation, primality testing
- **Flask** — HTTP servers for backend and keypers
- **requests** — HTTP client for voter CLI and backend↔keyper communication
