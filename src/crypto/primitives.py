"""
Group parameter generation and hash utilities for threshold ElGamal.
Uses safe prime groups: p = 2q + 1 where both p and q are prime.
The order-q subgroup of Z_p* provides DDH hardness.
"""

import hashlib
import random
from Crypto.Util.number import getPrime, isPrime


def hash_to_int(*args):
    """Fiat-Shamir hash: SHA-256 of concatenated string representations."""
    h = hashlib.sha256()
    for a in args:
        h.update(str(a).encode())
    return int(h.hexdigest(), 16)


def generate_group_params(bits=256):
    """Generate safe prime group parameters (p, q, g).

    p = 2q + 1 (safe prime)
    g = generator of the order-q subgroup of Z_p*
    """
    while True:
        q = getPrime(bits - 1)
        p = 2 * q + 1
        if isPrime(p):
            break

    while True:
        h = random.randrange(2, p - 1)
        g = pow(h, 2, p)
        if g > 1:
            assert pow(g, q, p) == 1, "Generator not in subgroup"
            return p, q, g
