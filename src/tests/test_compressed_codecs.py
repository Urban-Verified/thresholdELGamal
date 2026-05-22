"""Roundtrip tests for compressed G1/G2 codecs (zcash BLS12-381 format).

These verify the byte layout used on the contract wire and by the SDK.
"""

import pytest

from crypto.primitives import (
    CURVE_ORDER,
    G1,
    G2,
    Z1,
    Z2,
    G1_COMPRESSED_BYTES,
    G2_COMPRESSED_BYTES,
    g1_from_compressed,
    g1_to_compressed,
    g2_from_compressed,
    g2_to_compressed,
    point_add,
    point_eq,
    point_multiply,
    random_scalar,
)


# ------------------------------------------------------------------
#  G2
# ------------------------------------------------------------------

def test_g2_generator_roundtrip():
    b = g2_to_compressed(G2)
    assert len(b) == G2_COMPRESSED_BYTES == 96
    assert point_eq(g2_from_compressed(b), G2)


def test_g2_identity_roundtrip():
    b = g2_to_compressed(Z2)
    assert len(b) == 96
    assert point_eq(g2_from_compressed(b), Z2)


def test_g2_random_roundtrip():
    for _ in range(20):
        P = point_multiply(G2, random_scalar())
        b = g2_to_compressed(P)
        assert len(b) == 96
        assert point_eq(g2_from_compressed(b), P)


def test_g2_homomorphism_preserved_through_codec():
    a = random_scalar()
    b = random_scalar()
    P = point_multiply(G2, a)
    Q = point_multiply(G2, b)
    R = point_add(P, Q)

    P2 = g2_from_compressed(g2_to_compressed(P))
    Q2 = g2_from_compressed(g2_to_compressed(Q))
    R2 = g2_from_compressed(g2_to_compressed(R))

    assert point_eq(point_add(P2, Q2), R2)


def test_g2_wrong_length_rejected():
    with pytest.raises(ValueError, match="96-byte"):
        g2_from_compressed(b"\x00" * 95)
    with pytest.raises(ValueError, match="96-byte"):
        g2_from_compressed(b"\x00" * 97)


def test_g2_garbage_bytes_rejected():
    # First byte 0x80 = compressed flag set, infinity flag unset.
    # Remaining bytes don't yield a valid x-coordinate on the curve.
    bad = bytes([0x80]) + b"\xff" * 95
    with pytest.raises(ValueError):
        g2_from_compressed(bad)


# ------------------------------------------------------------------
#  G1
# ------------------------------------------------------------------

def test_g1_generator_roundtrip():
    b = g1_to_compressed(G1)
    assert len(b) == G1_COMPRESSED_BYTES == 48
    assert g1_from_compressed(b) == G1


def test_g1_identity_roundtrip():
    b = g1_to_compressed(Z1)
    assert len(b) == 48
    assert g1_from_compressed(b) == Z1


def test_g1_random_roundtrip():
    # G1 doesn't expose * with arkworks Scalar in this binding the same way
    # G2 does in the existing helpers, so multiply via the native API.
    from py_arkworks_bls12381 import Scalar

    for _ in range(20):
        s = random_scalar()
        P = G1 * Scalar(s % CURVE_ORDER)
        b = g1_to_compressed(P)
        assert len(b) == 48
        assert g1_from_compressed(b) == P


def test_g1_wrong_length_rejected():
    with pytest.raises(ValueError, match="48-byte"):
        g1_from_compressed(b"\x00" * 47)
    with pytest.raises(ValueError, match="48-byte"):
        g1_from_compressed(b"\x00" * 49)


def test_g1_garbage_bytes_rejected():
    bad = bytes([0x80]) + b"\xff" * 47
    with pytest.raises(ValueError):
        g1_from_compressed(bad)


# ------------------------------------------------------------------
#  Cross-format check: identity has the standard high-bit flag (0xc0)
# ------------------------------------------------------------------

def test_identity_compressed_high_bit_flag():
    # zcash compressed encoding sets bit 0x40 on the first byte for the
    # infinity flag, plus bit 0x80 for "compressed", so identity starts
    # with 0xc0.
    assert g1_to_compressed(Z1)[0] == 0xc0
    assert g2_to_compressed(Z2)[0] == 0xc0
