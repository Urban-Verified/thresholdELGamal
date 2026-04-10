"""
Non-interactive Zero-Knowledge Proofs for the threshold ElGamal voting system.

Implements three proof types (all Fiat-Shamir transformed):

1. Range Proof (Vote Validity):
   Proves a ciphertext encrypts a value in {0, 1, ..., B} using a
   (B+1)-branch OR-composition of DLEQ proofs.

2. Budget Proof (Exact Budget):
   Proves the sum of encrypted votes equals exactly B using a DLEQ proof
   on the homomorphically aggregated ciphertext.

3. Decryption Share Proof:
   Proves a partial decryption share sigma_k = C1^msk_k is correctly formed,
   i.e., log_g(mpk_k) = log_C1(sigma_k), using a DLEQ proof.
"""

import secrets
from .primitives import hash_to_int

# Domain separation tags for Fiat-Shamir hashes
_DOMAIN_RANGE = b"THRESHOLD_ELGAMAL_RANGE_PROOF_V1"
_DOMAIN_BUDGET = b"THRESHOLD_ELGAMAL_BUDGET_PROOF_V1"
_DOMAIN_DECRYPT = b"THRESHOLD_ELGAMAL_DECRYPT_PROOF_V1"


# ---------------------------------------------------------------------------
#  1. Range Proof: v ∈ {0, 1, ..., B}
# ---------------------------------------------------------------------------

def prove_range(p, q, g, pk, c1, c2, m, r, B, election_id=""):
    """Prove that ciphertext (c1, c2) encrypts m ∈ {0, 1, ..., B}.

    Uses a (B+1)-branch OR-composition of DLEQ proofs.
    For each possible value i, define D_i = c2 * g^(-i).
    If m == i (real branch): the prover knows r such that c1 = g^r and D_i = pk^r.
    If m != i (simulated branch): the prover simulates a DLEQ proof.

    Args:
        p, q, g: group parameters
        pk: election public key (mpk)
        c1, c2: ciphertext components
        m: actual encrypted value (0 <= m <= B)
        r: encryption randomness
        B: upper bound of allowed range
        election_id: optional election identifier bound into the proof

    Returns:
        List of (e_i, z_i) tuples for i = 0..B.
    """
    assert 0 <= m <= B, f"Message {m} not in range [0, {B}]"

    # D_i = c2 * g^(-i) mod p for each possible value i
    D = [(c2 * pow(g, -i, p)) % p for i in range(B + 1)]

    # Generate commitments for each branch
    a_values = [None] * (B + 1)
    challenges = [None] * (B + 1)
    responses = [None] * (B + 1)

    # Real branch: random commitment
    w = secrets.randbelow(q - 1) + 1
    a_values[m] = (pow(g, w, p), pow(pk, w, p))

    # Simulated branches: random challenge and response, derive commitments
    for i in range(B + 1):
        if i == m:
            continue
        e_i = secrets.randbelow(q - 1) + 1
        z_i = secrets.randbelow(q - 1) + 1
        a1 = (pow(g, z_i, p) * pow(c1, -e_i, p)) % p
        a2 = (pow(pk, z_i, p) * pow(D[i], -e_i, p)) % p
        a_values[i] = (a1, a2)
        challenges[i] = e_i
        responses[i] = z_i

    # Fiat-Shamir challenge: hash with domain separation and election context
    hash_args = [g, pk, c1, c2]
    for a1, a2 in a_values:
        hash_args.extend([a1, a2])
    if election_id:
        hash_args.append(election_id)
    e = hash_to_int(*hash_args, domain=_DOMAIN_RANGE) % q

    # Real branch: compute challenge and response
    e_sum_sim = sum(c for c in challenges if c is not None) % q
    e_real = (e - e_sum_sim) % q
    z_real = (w + r * e_real) % q
    challenges[m] = e_real
    responses[m] = z_real

    return list(zip(challenges, responses))


def verify_range(p, q, g, pk, c1, c2, proof, B, election_id=""):
    """Verify a range proof that (c1, c2) encrypts a value in {0, ..., B}.

    For each branch i, recomputes commitments from (e_i, z_i) and checks
    that the sum of challenges equals the Fiat-Shamir hash.

    Returns True if the proof is valid.
    """
    if len(proof) != B + 1:
        return False

    D = [(c2 * pow(g, -i, p)) % p for i in range(B + 1)]

    a_values = []
    e_sum = 0
    for i in range(B + 1):
        e_i, z_i = proof[i]
        a1 = (pow(g, z_i, p) * pow(c1, -e_i, p)) % p
        a2 = (pow(pk, z_i, p) * pow(D[i], -e_i, p)) % p
        a_values.append((a1, a2))
        e_sum = (e_sum + e_i) % q

    hash_args = [g, pk, c1, c2]
    for a1, a2 in a_values:
        hash_args.extend([a1, a2])
    if election_id:
        hash_args.append(election_id)
    e_expected = hash_to_int(*hash_args, domain=_DOMAIN_RANGE) % q

    return e_sum == e_expected


# ---------------------------------------------------------------------------
#  2. Budget Proof: sum(v_j) = B exactly
# ---------------------------------------------------------------------------

def prove_exact_budget(p, q, g, pk, sum_c1, sum_c2, B, r_sum, election_id=""):
    """Prove that the aggregated ciphertext encrypts exactly B.

    This is a DLEQ proof showing log_g(sum_c1) = log_pk(D) = r_sum,
    where D = sum_c2 * g^(-B). If the sum of votes equals B, then
    D = pk^r_sum.

    Args:
        p, q, g: group parameters
        pk: election public key
        sum_c1, sum_c2: homomorphically aggregated ciphertext
        B: exact budget value
        r_sum: sum of all encryption randomness values
        election_id: optional election identifier bound into the proof

    Returns:
        Tuple (e, z) constituting the DLEQ proof.
    """
    D = (sum_c2 * pow(g, -B, p)) % p

    w = secrets.randbelow(q - 1) + 1
    a1 = pow(g, w, p)
    a2 = pow(pk, w, p)

    hash_args = [sum_c1, D, a1, a2]
    if election_id:
        hash_args.append(election_id)
    e = hash_to_int(*hash_args, domain=_DOMAIN_BUDGET) % q
    z = (w + r_sum * e) % q

    return (e, z)


def verify_exact_budget(p, q, g, pk, sum_c1, sum_c2, B, proof, election_id=""):
    """Verify an exact budget proof.

    Recomputes the DLEQ commitments and checks the Fiat-Shamir hash.
    Returns True if the proof is valid.
    """
    e, z = proof
    D = (sum_c2 * pow(g, -B, p)) % p

    a1 = (pow(g, z, p) * pow(sum_c1, -e, p)) % p
    a2 = (pow(pk, z, p) * pow(D, -e, p)) % p

    hash_args = [sum_c1, D, a1, a2]
    if election_id:
        hash_args.append(election_id)
    e_check = hash_to_int(*hash_args, domain=_DOMAIN_BUDGET) % q
    return e == e_check


# ---------------------------------------------------------------------------
#  3. Decryption Share Proof: log_g(mpk_k) = log_C1(sigma_k)
# ---------------------------------------------------------------------------

def prove_decryption_share(p, q, g, c1, msk_k, mpk_k, sigma_k):
    """Prove correct partial decryption: sigma_k = c1^msk_k.

    This is a DLEQ proof showing that the same secret key msk_k was used
    to form both mpk_k = g^msk_k and sigma_k = c1^msk_k.

    Returns:
        Tuple (e, z) constituting the DLEQ proof.
    """
    w = secrets.randbelow(q - 1) + 1
    a1 = pow(g, w, p)
    a2 = pow(c1, w, p)

    e = hash_to_int(g, c1, mpk_k, sigma_k, a1, a2, domain=_DOMAIN_DECRYPT) % q
    z = (w + msk_k * e) % q

    return (e, z)


def verify_decryption_share(p, q, g, c1, mpk_k, sigma_k, proof):
    """Verify a decryption share proof.

    Checks that log_g(mpk_k) = log_c1(sigma_k) using the provided DLEQ proof.
    Returns True if the proof is valid.
    """
    e, z = proof

    a1 = (pow(g, z, p) * pow(mpk_k, -e, p)) % p
    a2 = (pow(c1, z, p) * pow(sigma_k, -e, p)) % p

    e_check = hash_to_int(g, c1, mpk_k, sigma_k, a1, a2, domain=_DOMAIN_DECRYPT) % q
    return e == e_check

    e_check = hash_to_int(mpk_k, sigma_k, a1, a2) % q
    return e == e_check
