"""
BLS12-381 G2 group primitives and hash utilities for threshold ElGamal.

All encryption operates in G2 of BLS12-381 (Type-3 pairing curve).
DDH is hard in G2 under the SXDH assumption.

Uses py_ecc optimized BLS12-381 implementation.
"""

import hashlib
import secrets

from py_ecc.optimized_bls12_381 import optimized_curve as bls
from py_ecc.optimized_bls12_381 import optimized_curve

# BLS12-381 curve order (scalar field order)
CURVE_ORDER = bls.curve_order

# Generator of G2
G2 = bls.G2

# Identity element in G2
Z2 = bls.Z2

# Field modulus (for serialization)
FIELD_MODULUS = bls.field_modulus


def hash_to_scalar(*args, domain=b""):
    """Fiat-Shamir hash to scalar in Z_q with domain separation.

    Each argument is converted to bytes and preceded by its 4-byte length,
    preventing ambiguous concatenation (e.g. H(1,23) != H(12,3)).
    An optional *domain* tag isolates different proof types.

    Accepts: int, bytes, str, and G2 points (tuples).
    Returns an integer in [0, CURVE_ORDER).
    """
    h = hashlib.sha256()
    # Domain separation tag (length-prefixed)
    h.update(len(domain).to_bytes(4, "big"))
    h.update(domain)
    for a in args:
        if isinstance(a, int):
            b = a.to_bytes((a.bit_length() + 8) // 8, "big", signed=True)
        elif isinstance(a, bytes):
            b = a
        elif isinstance(a, tuple):
            # G2 point — serialize to canonical bytes
            b = point_to_bytes(a)
        else:
            b = str(a).encode()
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
    return int.from_bytes(h.digest(), "big") % CURVE_ORDER


# ------------------------------------------------------------------
#  Point arithmetic helpers (thin wrappers for clarity)
# ------------------------------------------------------------------

def point_multiply(P, scalar):
    """Scalar multiplication: scalar * P in G2."""
    return bls.multiply(P, scalar % CURVE_ORDER)


def point_add(P, Q):
    """Point addition: P + Q in G2."""
    return bls.add(P, Q)


def point_neg(P):
    """Point negation: -P in G2."""
    return bls.neg(P)


def point_eq(P, Q):
    """Point equality check in G2."""
    return bls.eq(P, Q)


def is_identity(P):
    """Check if P is the identity (point at infinity) in G2."""
    return bls.eq(P, Z2)


# ------------------------------------------------------------------
#  Serialization: G2 points <-> bytes / dict (for JSON transport)
# ------------------------------------------------------------------

def point_to_bytes(P):
    """Serialize a G2 point to canonical bytes (uncompressed, 192 bytes for non-identity).

    Identity is serialized as a single zero byte.
    Non-identity points are normalized to affine (x, y) with x, y ∈ FQ2,
    each FQ2 having two 48-byte integer coefficients, for 4 × 48 = 192 bytes total.
    """
    if is_identity(P):
        return b"\x00"
    norm = bls.normalize(P)
    x_coeffs = norm[0].coeffs
    y_coeffs = norm[1].coeffs
    return b"\x01" + b"".join(
        int(c).to_bytes(48, "big") for c in [x_coeffs[0], x_coeffs[1], y_coeffs[0], y_coeffs[1]]
    )


def point_to_dict(P):
    """Serialize a G2 point to a JSON-compatible dict.

    Returns {"identity": true} for the identity point, or
    {"x0": hex, "x1": hex, "y0": hex, "y1": hex} for non-identity points.
    """
    if is_identity(P):
        return {"identity": True}
    norm = bls.normalize(P)
    x_coeffs = norm[0].coeffs
    y_coeffs = norm[1].coeffs
    return {
        "x0": hex(int(x_coeffs[0])),
        "x1": hex(int(x_coeffs[1])),
        "y0": hex(int(y_coeffs[0])),
        "y1": hex(int(y_coeffs[1])),
    }


def dict_to_point(d):
    """Deserialize a G2 point from a JSON dict.

    Raises ValueError if the point is not on the G2 curve.
    """
    if d.get("identity"):
        return Z2
    from py_ecc.fields import optimized_bls12_381_FQ2 as FQ2
    x = FQ2([int(d["x0"], 16), int(d["x1"], 16)])
    y = FQ2([int(d["y0"], 16), int(d["y1"], 16)])
    # Convert to projective coordinates (x, y, 1)
    one = FQ2.one()
    P = (x, y, one)
    # Validate point is on the curve by checking it's in G2
    if not bls.is_on_curve(P, bls.b2):
        raise ValueError("Point is not on the G2 curve")
    # Subgroup check: P must have order CURVE_ORDER (cofactor attack protection)
    if not bls.eq(bls.multiply(P, CURVE_ORDER), Z2):
        raise ValueError("Point is not in the G2 prime-order subgroup")
    return P


def validate_g2_point(P):
    """Validate that P is a valid non-identity G2 point.

    Checks: P is on the curve and P != identity.
    Raises ValueError on failure.
    """
    if is_identity(P):
        raise ValueError("Point is the identity element")
    if not bls.is_on_curve(P, bls.b2):
        raise ValueError("Point is not on the G2 curve")


def random_scalar():
    """Generate a cryptographically random scalar in [1, CURVE_ORDER - 1]."""
    return secrets.randbelow(CURVE_ORDER - 1) + 1
