"""
Group parameter generation and hash utilities for threshold ElGamal.
Uses safe prime groups: p = 2q + 1 where both p and q are prime.
The order-q subgroup of Z_p* provides DDH hardness.
"""

import hashlib
import secrets
from Crypto.Util.number import getPrime, isPrime


def hash_to_int(*args, domain=b""):
    """Fiat-Shamir hash with length-prefixed serialization and domain separation.

    Each argument is converted to bytes and preceded by its 4-byte length,
    preventing ambiguous concatenation (e.g. H(1,23) != H(12,3)).
    An optional *domain* tag isolates different proof types.
    """
    h = hashlib.sha256()
    # Domain separation tag (length-prefixed)
    h.update(len(domain).to_bytes(4, "big"))
    h.update(domain)
    for a in args:
        if isinstance(a, int):
            # Use variable-length encoding for big integers
            b = a.to_bytes((a.bit_length() + 8) // 8, "big", signed=True)
        elif isinstance(a, bytes):
            b = a
        else:
            b = str(a).encode()
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
    return int.from_bytes(h.digest(), "big")


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
        h = secrets.randbelow(p - 3) + 2  # uniform in [2, p-2]
        g = pow(h, 2, p)
        if g > 1:
            assert pow(g, q, p) == 1, "Generator not in subgroup"
            return p, q, g


def validate_group_element(x, p, q):
    """Validate that x is a member of the order-q subgroup of Z_p*.

    Checks: 1 <= x < p  and  x^q ≡ 1 (mod p).
    Raises ValueError on failure.
    """
    if not (1 <= x < p):
        raise ValueError(f"Element {x} not in Z_p* (must be 1 <= x < p={p})")
    if pow(x, q, p) != 1:
        raise ValueError(f"Element {x} not in order-q subgroup (x^q mod p != 1)")
