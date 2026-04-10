"""
Linear homomorphic ElGamal encryption in the exponent.

Encrypt(m) = (g^r, pk^r * g^m) where r is random.
Homomorphic: Enc(m1) * Enc(m2) = Enc(m1 + m2).
Decryption requires solving DLog for small m (baby-step-giant-step).
"""

import secrets
import math


def encrypt(p, q, g, pk, m):
    """ElGamal encryption in the exponent.

    Returns (c1, c2, r) where:
      c1 = g^r mod p
      c2 = pk^r * g^m mod p
      r  = encryption randomness (needed for ZK proofs)
    """
    r = secrets.randbelow(q - 1) + 1  # uniform in [1, q-1]
    c1 = pow(g, r, p)
    c2 = (pow(pk, r, p) * pow(g, m, p)) % p
    return c1, c2, r


def homomorphic_add(ct_a, ct_b, p):
    """Homomorphically add two ciphertexts (component-wise multiplication)."""
    return (ct_a[0] * ct_b[0]) % p, (ct_a[1] * ct_b[1]) % p


def aggregate_ciphertexts(ciphertexts, p):
    """Aggregate a list of ciphertexts homomorphically."""
    result = (1, 1)  # identity: encrypts 0 with r=0
    for ct in ciphertexts:
        result = homomorphic_add(result, ct, p)
    return result


def baby_step_giant_step(g, target, p, max_val):
    """Find m in [0, max_val] such that g^m = target mod p.

    Uses baby-step-giant-step algorithm: O(sqrt(max_val)) time and space.
    Returns m or None if not found.
    """
    if max_val == 0:
        return 0 if target % p == 1 else None

    n = int(math.isqrt(max_val)) + 2

    # Baby steps: table[g^j mod p] = j for j = 0, ..., n-1
    table = {}
    power = 1
    for j in range(n):
        table[power] = j
        power = (power * g) % p

    # Giant steps: check target * g^(-in) for i = 0, 1, ...
    g_neg_n = pow(g, -n, p)
    gamma = target
    for i in range(n + 1):
        if gamma in table:
            m = i * n + table[gamma]
            if m <= max_val:
                return m
        gamma = (gamma * g_neg_n) % p

    return None


def combine_decryption_shares(shares, p, q):
    """Combine partial decryption shares via Lagrange interpolation in the exponent.

    shares: list of (keyper_id, sigma_i) where sigma_i = C1^msk_i
    Returns combined sigma = C1^msk
    """
    result = 1
    for j_idx, (j_id, sigma_j) in enumerate(shares):
        # Lagrange coefficient for j_id evaluated at x=0
        lam_num = 1
        lam_den = 1
        for k_idx, (k_id, _) in enumerate(shares):
            if k_idx == j_idx:
                continue
            lam_num = (lam_num * (0 - k_id)) % q
            lam_den = (lam_den * (j_id - k_id)) % q
        lam = (lam_num * pow(lam_den, -1, q)) % q
        result = (result * pow(sigma_j, lam, p)) % p
    return result


def threshold_decrypt(c1, c2, shares, p, q, g, max_val):
    """Full threshold decryption.

    c1, c2: ciphertext components
    shares: list of (keyper_id, sigma_i) decryption shares
    max_val: upper bound on plaintext for BSGS
    Returns plaintext m or None if decryption fails.
    """
    sigma = combine_decryption_shares(shares, p, q)
    tau = (c2 * pow(sigma, -1, p)) % p  # tau = g^m
    return baby_step_giant_step(g, tau, p, max_val)
