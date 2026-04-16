#!/usr/bin/env python3
"""
Comprehensive test suite for the threshold ElGamal voting system over BLS12-381.

Tests are organized in layers:
  1. Unit tests: BLS12-381 primitives, ElGamal, DKG, ZK proofs
  2. Integration tests: full DKG + encryption + decryption without servers
  3. System (E2E) tests: full HTTP server lifecycle

Run:
    python test_comprehensive.py          # all tests
    python test_comprehensive.py -v       # verbose
    python test_comprehensive.py -k dkg   # only DKG tests
"""

import unittest
import threading
import time
import math
import sys
import os
import logging
import requests

# Suppress Flask/werkzeug noise during tests
logging.getLogger("werkzeug").setLevel(logging.ERROR)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.primitives import (
    CURVE_ORDER, G2, Z2, FIELD_MODULUS,
    hash_to_scalar, point_multiply, point_add, point_neg, point_eq,
    is_identity, point_to_bytes, point_to_dict, dict_to_point,
    validate_g2_point, random_scalar,
)
from crypto.elgamal import (
    encrypt, homomorphic_add, aggregate_ciphertexts,
    baby_step_giant_step, lagrange_coefficient, combine_decryption_shares,
    threshold_decrypt,
)
from crypto.dkg import KeyperDKGState
from crypto.proofs import (
    prove_range, verify_range,
    prove_exact_budget, verify_exact_budget,
    prove_decryption_share, verify_decryption_share,
)


# ======================================================================
#  1. UNIT TESTS: BLS12-381 Primitives
# ======================================================================

class TestCurveConstants(unittest.TestCase):
    """Test BLS12-381 curve constants are correct."""

    def test_curve_order_is_prime(self):
        # BLS12-381 scalar field order: well-known 255-bit prime
        self.assertEqual(CURVE_ORDER.bit_length(), 255)
        # Fermat test (sufficient for a known constant)
        self.assertEqual(pow(2, CURVE_ORDER - 1, CURVE_ORDER), 1)

    def test_generator_not_identity(self):
        self.assertFalse(is_identity(G2))

    def test_identity_is_identity(self):
        self.assertTrue(is_identity(Z2))

    def test_generator_order(self):
        # q * G2 should be identity
        self.assertTrue(is_identity(point_multiply(G2, CURVE_ORDER)))

    def test_generator_half_order_not_identity(self):
        half = CURVE_ORDER // 2
        self.assertFalse(is_identity(point_multiply(G2, half)))


class TestPointArithmetic(unittest.TestCase):
    """Test EC point operations in G2."""

    def test_add_identity(self):
        P = point_multiply(G2, 42)
        self.assertTrue(point_eq(point_add(P, Z2), P))
        self.assertTrue(point_eq(point_add(Z2, P), P))

    def test_add_inverse(self):
        P = point_multiply(G2, 42)
        neg_P = point_neg(P)
        self.assertTrue(is_identity(point_add(P, neg_P)))

    def test_scalar_mult_distributive(self):
        # (a+b)*G = a*G + b*G
        a, b = 123, 456
        lhs = point_multiply(G2, a + b)
        rhs = point_add(point_multiply(G2, a), point_multiply(G2, b))
        self.assertTrue(point_eq(lhs, rhs))

    def test_scalar_mult_associative(self):
        # a*(b*G) = (a*b)*G
        a, b = 7, 13
        lhs = point_multiply(point_multiply(G2, b), a)
        rhs = point_multiply(G2, a * b)
        self.assertTrue(point_eq(lhs, rhs))

    def test_double(self):
        P = point_multiply(G2, 5)
        double = point_add(P, P)
        expected = point_multiply(G2, 10)
        self.assertTrue(point_eq(double, expected))

    def test_neg_neg_is_identity(self):
        P = point_multiply(G2, 99)
        self.assertTrue(point_eq(point_neg(point_neg(P)), P))

    def test_multiply_by_zero(self):
        self.assertTrue(is_identity(point_multiply(G2, 0)))

    def test_multiply_by_one(self):
        self.assertTrue(point_eq(point_multiply(G2, 1), G2))

    def test_multiply_mod_order(self):
        # (CURVE_ORDER + 5) * G = 5 * G
        self.assertTrue(point_eq(
            point_multiply(G2, CURVE_ORDER + 5),
            point_multiply(G2, 5)
        ))


class TestSerialization(unittest.TestCase):
    """Test G2 point serialization/deserialization."""

    def test_identity_to_bytes(self):
        b = point_to_bytes(Z2)
        self.assertEqual(b, b"\x00")

    def test_non_identity_to_bytes(self):
        P = point_multiply(G2, 42)
        b = point_to_bytes(P)
        self.assertEqual(b[0:1], b"\x01")
        self.assertEqual(len(b), 1 + 4 * 48)  # 193 bytes

    def test_identity_dict_roundtrip(self):
        d = point_to_dict(Z2)
        self.assertTrue(d.get("identity"))
        P = dict_to_point(d)
        self.assertTrue(is_identity(P))

    def test_point_dict_roundtrip(self):
        P = point_multiply(G2, 12345)
        d = point_to_dict(P)
        Q = dict_to_point(d)
        self.assertTrue(point_eq(P, Q))

    def test_generator_dict_roundtrip(self):
        d = point_to_dict(G2)
        Q = dict_to_point(d)
        self.assertTrue(point_eq(G2, Q))

    def test_invalid_point_dict(self):
        # A point not on the curve
        d = {"x0": hex(1), "x1": hex(2), "y0": hex(3), "y1": hex(4)}
        with self.assertRaises(ValueError):
            dict_to_point(d)

    def test_different_points_have_different_bytes(self):
        P1 = point_multiply(G2, 1)
        P2 = point_multiply(G2, 2)
        self.assertNotEqual(point_to_bytes(P1), point_to_bytes(P2))


class TestValidation(unittest.TestCase):
    """Test G2 point validation."""

    def test_valid_point(self):
        P = point_multiply(G2, 42)
        validate_g2_point(P)  # should not raise

    def test_identity_rejected(self):
        with self.assertRaises(ValueError):
            validate_g2_point(Z2)

    def test_generator_valid(self):
        validate_g2_point(G2)


class TestHashToScalar(unittest.TestCase):
    """Test Fiat-Shamir hash function."""

    def test_basic_hash(self):
        h = hash_to_scalar(1, 2, 3)
        self.assertIsInstance(h, int)
        self.assertTrue(0 <= h < CURVE_ORDER)

    def test_deterministic(self):
        h1 = hash_to_scalar(1, 2, 3, domain=b"test")
        h2 = hash_to_scalar(1, 2, 3, domain=b"test")
        self.assertEqual(h1, h2)

    def test_domain_separation(self):
        h1 = hash_to_scalar(1, 2, 3, domain=b"domain_a")
        h2 = hash_to_scalar(1, 2, 3, domain=b"domain_b")
        self.assertNotEqual(h1, h2)

    def test_different_inputs(self):
        h1 = hash_to_scalar(1, 23)
        h2 = hash_to_scalar(12, 3)
        self.assertNotEqual(h1, h2)

    def test_length_prefixed_prevents_collision(self):
        h1 = hash_to_scalar(b"ab", b"cd")
        h2 = hash_to_scalar(b"abc", b"d")
        self.assertNotEqual(h1, h2)

    def test_hash_with_point(self):
        P = point_multiply(G2, 42)
        h = hash_to_scalar(P, 1, 2)
        self.assertTrue(0 <= h < CURVE_ORDER)

    def test_hash_with_identity(self):
        h = hash_to_scalar(Z2, 1)
        self.assertTrue(0 <= h < CURVE_ORDER)

    def test_hash_with_string(self):
        h = hash_to_scalar("election_123", 1)
        self.assertTrue(0 <= h < CURVE_ORDER)


class TestRandomScalar(unittest.TestCase):
    """Test cryptographic random scalar generation."""

    def test_in_range(self):
        for _ in range(10):
            s = random_scalar()
            self.assertTrue(1 <= s < CURVE_ORDER)

    def test_not_constant(self):
        scalars = {random_scalar() for _ in range(10)}
        self.assertGreater(len(scalars), 1)


# ======================================================================
#  2. UNIT TESTS: ElGamal Encryption
# ======================================================================

class TestElGamalEncryption(unittest.TestCase):
    """Test ElGamal encryption in the exponent over G2."""

    def setUp(self):
        self.sk = random_scalar()
        self.pk = point_multiply(G2, self.sk)

    def test_encrypt_decrypt_zero(self):
        C1, C2, r = encrypt(self.pk, 0)
        sigma = point_multiply(C1, self.sk)
        tau = point_add(C2, point_neg(sigma))
        self.assertTrue(is_identity(tau))

    def test_encrypt_decrypt_one(self):
        C1, C2, r = encrypt(self.pk, 1)
        sigma = point_multiply(C1, self.sk)
        tau = point_add(C2, point_neg(sigma))
        self.assertTrue(point_eq(tau, G2))

    def test_encrypt_decrypt_small(self):
        for m in [0, 1, 5, 10, 42]:
            C1, C2, r = encrypt(self.pk, m)
            sigma = point_multiply(C1, self.sk)
            tau = point_add(C2, point_neg(sigma))
            expected = point_multiply(G2, m)
            self.assertTrue(point_eq(tau, expected), f"Failed for m={m}")

    def test_ciphertext_is_g2_points(self):
        C1, C2, r = encrypt(self.pk, 5)
        validate_g2_point(C1)
        validate_g2_point(C2)

    def test_randomness_in_range(self):
        _, _, r = encrypt(self.pk, 0)
        self.assertTrue(1 <= r < CURVE_ORDER)

    def test_different_encryptions_differ(self):
        C1a, C2a, _ = encrypt(self.pk, 5)
        C1b, C2b, _ = encrypt(self.pk, 5)
        # Overwhelmingly likely to differ (different randomness)
        self.assertFalse(point_eq(C1a, C1b))


class TestHomomorphicAdd(unittest.TestCase):
    """Test homomorphic addition of ElGamal ciphertexts."""

    def setUp(self):
        self.sk = random_scalar()
        self.pk = point_multiply(G2, self.sk)

    def test_add_two_ciphertexts(self):
        C1a, C2a, _ = encrypt(self.pk, 3)
        C1b, C2b, _ = encrypt(self.pk, 7)
        C1s, C2s = homomorphic_add((C1a, C2a), (C1b, C2b))

        sigma = point_multiply(C1s, self.sk)
        tau = point_add(C2s, point_neg(sigma))
        expected = point_multiply(G2, 10)
        self.assertTrue(point_eq(tau, expected))

    def test_aggregate_multiple(self):
        values = [1, 2, 3, 4, 5]
        cts = [encrypt(self.pk, v)[:2] for v in values]  # (C1, C2) only
        agg = aggregate_ciphertexts(cts)

        sigma = point_multiply(agg[0], self.sk)
        tau = point_add(agg[1], point_neg(sigma))
        expected = point_multiply(G2, sum(values))
        self.assertTrue(point_eq(tau, expected))

    def test_aggregate_empty(self):
        agg = aggregate_ciphertexts([])
        self.assertTrue(is_identity(agg[0]))
        self.assertTrue(is_identity(agg[1]))

    def test_aggregate_single(self):
        C1, C2, _ = encrypt(self.pk, 7)
        agg = aggregate_ciphertexts([(C1, C2)])

        sigma = point_multiply(agg[0], self.sk)
        tau = point_add(agg[1], point_neg(sigma))
        expected = point_multiply(G2, 7)
        self.assertTrue(point_eq(tau, expected))


class TestBabyStepGiantStep(unittest.TestCase):
    """Test EC discrete log solver."""

    def test_find_zero(self):
        target = Z2  # 0 * G2
        self.assertEqual(baby_step_giant_step(target, 10), 0)

    def test_find_small_values(self):
        for m in range(11):
            target = point_multiply(G2, m)
            result = baby_step_giant_step(target, 10)
            self.assertEqual(result, m, f"Failed for m={m}")

    def test_find_max_value(self):
        target = point_multiply(G2, 100)
        self.assertEqual(baby_step_giant_step(target, 100), 100)

    def test_not_found(self):
        target = point_multiply(G2, 50)
        self.assertIsNone(baby_step_giant_step(target, 10))


class TestLagrangeCoefficients(unittest.TestCase):
    """Test Lagrange interpolation coefficients."""

    def test_two_points(self):
        # For IDs {1, 2}, lambda_1 = (0-2)/(1-2) = 2, lambda_2 = (0-1)/(2-1) = -1
        q = CURVE_ORDER
        lam1 = lagrange_coefficient(1, [1, 2], q)
        lam2 = lagrange_coefficient(2, [1, 2], q)
        self.assertEqual(lam1, 2 % q)
        self.assertEqual(lam2, (-1) % q)

    def test_reconstruction(self):
        # f(x) = 5 + 3x, f(0)=5, f(1)=8, f(2)=11
        q = CURVE_ORDER
        ids = [1, 2]
        vals = [8, 11]
        result = sum(lagrange_coefficient(ids[i], ids, q) * vals[i] for i in range(2)) % q
        self.assertEqual(result, 5)


# ======================================================================
#  3. UNIT TESTS: DKG
# ======================================================================

class TestDKGBasic(unittest.TestCase):
    """Test Distributed Key Generation basics."""

    def test_n2_t1_dkg(self):
        """n=2, t=1: simplest nontrivial DKG."""
        n, t = 2, 1
        keypers = [KeyperDKGState() for _ in range(n)]

        # Round 1
        all_comms = {}
        all_shares = {}
        for k in range(n):
            kid = k + 1
            comms, shares = keypers[k].round1(kid, n, t)
            all_comms[kid] = comms
            all_shares[kid] = shares

        # Round 2
        for k in range(n):
            kid = k + 1
            received = {d: all_shares[d][kid] for d in range(1, n + 1)}
            keypers[k].round2(all_comms, received)

        # Check: all keypers have consistent public key shares
        for k in range(n):
            expected_pk = point_multiply(G2, keypers[k].combined_share)
            self.assertTrue(point_eq(expected_pk, keypers[k].public_key_share))

    def test_3_of_5_dkg(self):
        """Standard case: n=5, t=2 (need 3 for reconstruction)."""
        n, t = 5, 2
        keypers = [KeyperDKGState() for _ in range(n)]

        all_comms = {}
        all_shares = {}
        for k in range(n):
            kid = k + 1
            comms, shares = keypers[k].round1(kid, n, t)
            all_comms[kid] = comms
            all_shares[kid] = shares

        for k in range(n):
            kid = k + 1
            received = {d: all_shares[d][kid] for d in range(1, n + 1)}
            keypers[k].round2(all_comms, received)

        # Verify MPK consistency
        mpk = Z2
        for kid in range(1, n + 1):
            mpk = point_add(mpk, all_comms[kid][0])

        for k in range(n):
            self.assertTrue(point_eq(
                keypers[k].public_key_share,
                point_multiply(G2, keypers[k].combined_share)
            ))

    def test_feldman_vss_bad_share_rejected(self):
        """Corrupted share should fail Feldman VSS verification."""
        n, t = 3, 1
        keypers = [KeyperDKGState() for _ in range(n)]

        all_comms = {}
        all_shares = {}
        for k in range(n):
            kid = k + 1
            comms, shares = keypers[k].round1(kid, n, t)
            all_comms[kid] = comms
            all_shares[kid] = shares

        # Corrupt a share from keyper 1 to keyper 2
        corrupted_shares = dict(all_shares)
        original = corrupted_shares[1][2]
        corrupted_shares[1] = dict(corrupted_shares[1])
        corrupted_shares[1][2] = (original + 1) % CURVE_ORDER

        received = {d: corrupted_shares[d][2] for d in range(1, n + 1)}
        with self.assertRaises(ValueError):
            keypers[1].round2(all_comms, received)

    def test_commitments_are_valid_g2_points(self):
        n, t = 3, 1
        ks = KeyperDKGState()
        comms, _ = ks.round1(1, n, t)
        for c in comms:
            validate_g2_point(c)


# ======================================================================
#  4. UNIT TESTS: Zero-Knowledge Proofs
# ======================================================================

class TestRangeProof(unittest.TestCase):
    """Test OR-composition DLEQ range proofs."""

    def setUp(self):
        self.sk = random_scalar()
        self.mpk = point_multiply(G2, self.sk)

    def test_valid_range_proof_binary(self):
        """Prove m in {0, 1} -- binary vote."""
        for m in [0, 1]:
            C1, C2, r = encrypt(self.mpk, m)
            proof = prove_range(self.mpk, C1, C2, m, r, 1)
            self.assertTrue(verify_range(self.mpk, C1, C2, proof, 1))

    def test_valid_range_proof_budget(self):
        """Prove m in {0, 1, 2, 3} -- budget=3."""
        for m in range(4):
            C1, C2, r = encrypt(self.mpk, m)
            proof = prove_range(self.mpk, C1, C2, m, r, 3)
            self.assertTrue(verify_range(self.mpk, C1, C2, proof, 3))

    def test_invalid_range_proof_wrong_message(self):
        """Proof for m=0 should not verify for a ciphertext encrypting m=1."""
        C1, C2, r = encrypt(self.mpk, 1)
        # prove_range computes the real DLEQ for branch m; when we pass m=0
        # but the ciphertext actually encrypts m=1, the real branch is wrong
        proof = prove_range(self.mpk, C1, C2, 0, r, 1)
        self.assertFalse(verify_range(self.mpk, C1, C2, proof, 1))

    def test_proof_length(self):
        C1, C2, r = encrypt(self.mpk, 2)
        proof = prove_range(self.mpk, C1, C2, 2, r, 5)
        self.assertEqual(len(proof), 6)  # B+1 = 6 branches

    def test_range_proof_with_election_id(self):
        C1, C2, r = encrypt(self.mpk, 1)
        proof = prove_range(self.mpk, C1, C2, 1, r, 1, election_id="election_42")
        self.assertTrue(verify_range(self.mpk, C1, C2, proof, 1, election_id="election_42"))
        # Wrong election ID should fail
        self.assertFalse(verify_range(self.mpk, C1, C2, proof, 1, election_id="election_99"))

    def test_proof_tampered_challenge(self):
        C1, C2, r = encrypt(self.mpk, 1)
        proof = prove_range(self.mpk, C1, C2, 1, r, 2)
        self.assertTrue(verify_range(self.mpk, C1, C2, proof, 2))
        # Tamper with a challenge
        tampered = list(proof)
        e, z = tampered[0]
        tampered[0] = ((e + 1) % CURVE_ORDER, z)
        self.assertFalse(verify_range(self.mpk, C1, C2, tampered, 2))


class TestBudgetProof(unittest.TestCase):
    """Test exact budget DLEQ proofs."""

    def setUp(self):
        self.sk = random_scalar()
        self.mpk = point_multiply(G2, self.sk)

    def test_valid_budget_proof(self):
        """Budget B=3 with vote vector summing to 3."""
        votes = [1, 0, 2]  # sum = 3
        cts = []
        rands = []
        for v in votes:
            C1, C2, r = encrypt(self.mpk, v)
            cts.append((C1, C2))
            rands.append(r)
        agg = aggregate_ciphertexts(cts)
        r_sum = sum(rands) % CURVE_ORDER
        proof = prove_exact_budget(self.mpk, agg[0], agg[1], 3, r_sum)
        self.assertTrue(verify_exact_budget(self.mpk, agg[0], agg[1], 3, proof))

    def test_invalid_budget_wrong_sum(self):
        """Proof should fail if budget claim doesn't match actual sum."""
        votes = [1, 1]  # sum = 2
        cts = []
        rands = []
        for v in votes:
            C1, C2, r = encrypt(self.mpk, v)
            cts.append((C1, C2))
            rands.append(r)
        agg = aggregate_ciphertexts(cts)
        r_sum = sum(rands) % CURVE_ORDER
        # Claim budget is 3 (wrong)
        proof = prove_exact_budget(self.mpk, agg[0], agg[1], 3, r_sum)
        self.assertFalse(verify_exact_budget(self.mpk, agg[0], agg[1], 3, proof))

    def test_budget_proof_with_election_id(self):
        C1, C2, r = encrypt(self.mpk, 1)
        agg = aggregate_ciphertexts([(C1, C2)])
        proof = prove_exact_budget(self.mpk, agg[0], agg[1], 1, r, election_id="e1")
        self.assertTrue(verify_exact_budget(self.mpk, agg[0], agg[1], 1, proof, election_id="e1"))
        self.assertFalse(verify_exact_budget(self.mpk, agg[0], agg[1], 1, proof, election_id="e2"))

    def test_budget_proof_b_equals_1(self):
        """Single-choice election: B=1."""
        C1, C2, r = encrypt(self.mpk, 1)
        agg = aggregate_ciphertexts([(C1, C2)])
        proof = prove_exact_budget(self.mpk, agg[0], agg[1], 1, r)
        self.assertTrue(verify_exact_budget(self.mpk, agg[0], agg[1], 1, proof))


class TestDecryptionShareProof(unittest.TestCase):
    """Test DLEQ proofs for decryption shares."""

    def setUp(self):
        self.msk_k = random_scalar()
        self.mpk_k = point_multiply(G2, self.msk_k)
        self.election_sk = random_scalar()
        self.election_pk = point_multiply(G2, self.election_sk)

    def test_valid_decryption_proof(self):
        C1, C2, _ = encrypt(self.election_pk, 5)
        sigma_k = point_multiply(C1, self.msk_k)
        proof = prove_decryption_share(C1, self.msk_k, self.mpk_k, sigma_k)
        self.assertTrue(verify_decryption_share(C1, self.mpk_k, sigma_k, proof))

    def test_invalid_decryption_proof_wrong_sigma(self):
        C1, C2, _ = encrypt(self.election_pk, 5)
        sigma_k = point_multiply(C1, self.msk_k)
        wrong_sigma = point_multiply(C1, random_scalar())
        proof = prove_decryption_share(C1, self.msk_k, self.mpk_k, sigma_k)
        self.assertFalse(verify_decryption_share(C1, self.mpk_k, wrong_sigma, proof))

    def test_invalid_decryption_proof_wrong_mpk(self):
        C1, C2, _ = encrypt(self.election_pk, 5)
        sigma_k = point_multiply(C1, self.msk_k)
        proof = prove_decryption_share(C1, self.msk_k, self.mpk_k, sigma_k)
        wrong_mpk = point_multiply(G2, random_scalar())
        self.assertFalse(verify_decryption_share(C1, wrong_mpk, sigma_k, proof))

    def test_invalid_decryption_proof_tampered(self):
        C1, C2, _ = encrypt(self.election_pk, 5)
        sigma_k = point_multiply(C1, self.msk_k)
        e, z = prove_decryption_share(C1, self.msk_k, self.mpk_k, sigma_k)
        self.assertFalse(verify_decryption_share(C1, self.mpk_k, sigma_k, (e, (z + 1) % CURVE_ORDER)))


# ======================================================================
#  5. INTEGRATION TESTS: DKG + Encrypt + Decrypt (no servers)
# ======================================================================

def _run_dkg(n, t):
    """Run DKG for n keypers with threshold t. Returns (keypers, mpk)."""
    keypers = [KeyperDKGState() for _ in range(n)]
    all_comms = {}
    all_shares = {}
    for k in range(n):
        kid = k + 1
        comms, shares = keypers[k].round1(kid, n, t)
        all_comms[kid] = comms
        all_shares[kid] = shares
    for k in range(n):
        kid = k + 1
        received = {d: all_shares[d][kid] for d in range(1, n + 1)}
        keypers[k].round2(all_comms, received)
    mpk = Z2
    for kid in range(1, n + 1):
        mpk = point_add(mpk, all_comms[kid][0])
    return keypers, mpk


class TestIntegrationThresholdDecrypt(unittest.TestCase):
    """Full threshold ElGamal: DKG -> Encrypt -> Threshold Decrypt."""

    def test_2_of_3_threshold_decrypt(self):
        """n=3, t=1: encrypt m=7, decrypt with 2 shares."""
        keypers, mpk = _run_dkg(3, 1)

        m = 7
        C1, C2, _ = encrypt(mpk, m)

        shares = []
        for k in [0, 1]:  # keypers 1 and 2
            kid = k + 1
            sigma = keypers[k].partial_decrypt(C1)
            shares.append((kid, sigma))

        result = threshold_decrypt(C1, C2, shares, m * 2)
        self.assertEqual(result, m)

    def test_3_of_5_threshold_decrypt(self):
        """n=5, t=2: encrypt m=42, decrypt with 3 shares."""
        keypers, mpk = _run_dkg(5, 2)

        m = 42
        C1, C2, _ = encrypt(mpk, m)

        shares = [(k + 1, keypers[k].partial_decrypt(C1)) for k in [1, 2, 4]]
        result = threshold_decrypt(C1, C2, shares, 100)
        self.assertEqual(result, m)

    def test_any_t_plus_1_subset_works(self):
        """Any t+1 keypers should be able to decrypt."""
        import itertools
        n, t = 4, 1  # use n=4 to keep combinatorics manageable
        keypers, mpk = _run_dkg(n, t)

        m = 10
        C1, C2, _ = encrypt(mpk, m)

        for subset in itertools.combinations(range(n), t + 1):
            shares = [(k + 1, keypers[k].partial_decrypt(C1)) for k in subset]
            result = threshold_decrypt(C1, C2, shares, 20)
            self.assertEqual(result, m, f"Failed with keyper subset {subset}")

    def test_insufficient_shares_fail(self):
        """With only t shares (not t+1), decryption should fail."""
        keypers, mpk = _run_dkg(5, 2)

        m = 10
        C1, C2, _ = encrypt(mpk, m)

        # Only 2 shares (need 3)
        shares = [(k + 1, keypers[k].partial_decrypt(C1)) for k in [0, 1]]
        result = threshold_decrypt(C1, C2, shares, 20)
        self.assertNotEqual(result, m)


class TestIntegrationHomomorphicVoting(unittest.TestCase):
    """Multiple votes, homomorphic sum, threshold decrypt."""

    def test_single_choice_tally(self):
        keypers, mpk = _run_dkg(3, 1)

        # 5 voters, 3 candidates, B=1
        votes = [[1, 0, 0], [1, 0, 0], [0, 1, 0], [0, 0, 1], [0, 1, 0]]
        expected = [2, 2, 1]
        num_cand = 3

        all_cts = {j: [] for j in range(num_cand)}
        for vote in votes:
            for j in range(num_cand):
                C1, C2, _ = encrypt(mpk, vote[j])
                all_cts[j].append((C1, C2))

        for j in range(num_cand):
            agg = aggregate_ciphertexts(all_cts[j])
            shares = [(k + 1, keypers[k].partial_decrypt(agg[0])) for k in range(2)]
            result = threshold_decrypt(agg[0], agg[1], shares, 10)
            self.assertEqual(result, expected[j], f"Candidate {j}")

    def test_budget_vote_with_proofs(self):
        """Full budget vote with range proofs and budget proof."""
        keypers, mpk = _run_dkg(3, 1)
        B = 3

        votes = [1, 0, 2]  # sum = 3
        cts = []
        rands = []
        for v in votes:
            C1, C2, r = encrypt(mpk, v)
            cts.append((C1, C2))
            rands.append(r)

        # Range proofs
        for j, v in enumerate(votes):
            proof = prove_range(mpk, cts[j][0], cts[j][1], v, rands[j], B)
            self.assertTrue(verify_range(mpk, cts[j][0], cts[j][1], proof, B))

        # Budget proof
        agg = aggregate_ciphertexts(cts)
        r_sum = sum(rands) % CURVE_ORDER
        bp = prove_exact_budget(mpk, agg[0], agg[1], B, r_sum)
        self.assertTrue(verify_exact_budget(mpk, agg[0], agg[1], B, bp))

        # Decrypt each candidate
        for j in range(3):
            agg_j = aggregate_ciphertexts([cts[j]])
            shares = [(k + 1, keypers[k].partial_decrypt(agg_j[0])) for k in range(2)]
            result = threshold_decrypt(agg_j[0], agg_j[1], shares, 10)
            self.assertEqual(result, votes[j])

    def test_decryption_share_proofs(self):
        """Decryption share DLEQ proofs verified correctly."""
        keypers, mpk = _run_dkg(3, 1)

        C1, C2, _ = encrypt(mpk, 5)

        for k in range(3):
            sigma = keypers[k].partial_decrypt(C1)
            msk_k = keypers[k].combined_share
            mpk_k = keypers[k].public_key_share
            proof = prove_decryption_share(C1, msk_k, mpk_k, sigma)
            self.assertTrue(verify_decryption_share(C1, mpk_k, sigma, proof),
                            f"Decryption proof failed for keyper {k + 1}")


# ======================================================================
#  6. SYSTEM (E2E) TESTS: HTTP Server Lifecycle
# ======================================================================

def _start_flask(app, port, host="127.0.0.1"):
    """Start a Flask app in a daemon thread."""
    t = threading.Thread(
        target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False),
        daemon=True,
    )
    t.start()
    return t


def _wait_for(url, retries=30, delay=0.2):
    """Wait for a server to become available."""
    for _ in range(retries):
        try:
            requests.get(url, timeout=1)
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(delay)
    return False


def _submit_vote_http(backend_url, vote_vector):
    """Client-side: encrypt, prove, submit via HTTP."""
    params = requests.get(f"{backend_url}/election/params", timeout=5).json()
    mpk = dict_to_point(params["mpk"])
    B = params["budget"]
    num_cand = params["num_candidates"]
    election_id = params.get("election_id", "")

    assert len(vote_vector) == num_cand
    assert sum(vote_vector) == B

    cts = []
    rands = []
    for v in vote_vector:
        C1, C2, r = encrypt(mpk, v)
        cts.append((C1, C2))
        rands.append(r)

    range_proofs = []
    for j in range(num_cand):
        proof = prove_range(mpk, cts[j][0], cts[j][1], vote_vector[j], rands[j], B, election_id=election_id)
        range_proofs.append(proof)

    agg = aggregate_ciphertexts(cts)
    r_sum = sum(rands) % CURVE_ORDER
    bp = prove_exact_budget(mpk, agg[0], agg[1], B, r_sum, election_id=election_id)

    payload = {
        "ciphertexts": [
            {"c1": point_to_dict(ct[0]), "c2": point_to_dict(ct[1])} for ct in cts
        ],
        "range_proofs": [
            [{"e": str(e), "z": str(z)} for (e, z) in proof]
            for proof in range_proofs
        ],
        "budget_proof": {"e": str(bp[0]), "z": str(bp[1])},
    }

    resp = requests.post(f"{backend_url}/election/vote", json=payload, timeout=30)
    return resp.json()


# Use different port ranges for each E2E test to avoid conflicts
_PORT_COUNTER = [7000]


def _next_ports(n_keypers):
    """Allocate unique ports for a test (backend + keypers + bulletin board)."""
    base = _PORT_COUNTER[0]
    _PORT_COUNTER[0] += n_keypers + 2  # +1 backend, +n_keypers, +1 BB
    backend_port = base
    keyper_ports = list(range(base + 1, base + 1 + n_keypers))
    bb_port = base + 1 + n_keypers
    return backend_port, keyper_ports, bb_port


class TestE2ESingleChoice(unittest.TestCase):
    """E2E: Single-choice election (B=1) with HTTP servers."""

    @classmethod
    def setUpClass(cls):
        from keyper import create_keyper_app
        from backend import create_backend_app
        from bulletin_board import create_bb_app

        n_keypers = 3
        cls.backend_port, cls.keyper_ports, cls.bb_port = _next_ports(n_keypers)
        cls.backend_url = f"http://127.0.0.1:{cls.backend_port}"
        cls.keyper_urls = [f"http://127.0.0.1:{p}" for p in cls.keyper_ports]
        cls.bb_url = f"http://127.0.0.1:{cls.bb_port}"

        bb_app = create_bb_app()
        _start_flask(bb_app, cls.bb_port)

        for i, port in enumerate(cls.keyper_ports):
            app = create_keyper_app(i + 1)
            _start_flask(app, port)

        backend_app = create_backend_app(cls.keyper_urls, cls.bb_url)
        _start_flask(backend_app, cls.backend_port)

        assert _wait_for(f"{cls.bb_url}/bb/status"), "Bulletin board not ready"
        for url in cls.keyper_urls:
            assert _wait_for(f"{url}/status"), f"Keyper at {url} not ready"
        assert _wait_for(f"{cls.backend_url}/election/status"), "Backend not ready"

    def test_full_single_choice_election(self):
        """3 candidates, B=1, 5 voters -> expected tally [2, 2, 1]."""
        resp = requests.post(f"{self.backend_url}/election/create", json={
            "n": 3, "t": 1, "num_candidates": 3, "budget": 1,
            "candidate_names": ["Alice", "Bob", "Charlie"],
        }, timeout=30)
        self.assertEqual(resp.status_code, 200)

        resp = requests.post(f"{self.backend_url}/election/dkg", timeout=120)
        self.assertEqual(resp.status_code, 200)

        voter_choices = [[1,0,0], [1,0,0], [0,1,0], [0,1,0], [0,0,1]]
        for choice in voter_choices:
            result = _submit_vote_http(self.backend_url, choice)
            self.assertEqual(result.get("status"), "ok")

        resp = requests.post(f"{self.backend_url}/election/tally", timeout=120)
        self.assertEqual(resp.status_code, 200)
        results = resp.json()["results"]
        self.assertEqual(results["Alice"], 2)
        self.assertEqual(results["Bob"], 2)
        self.assertEqual(results["Charlie"], 1)


class TestE2EBudgetVote(unittest.TestCase):
    """E2E: Budget vote (B=3) with HTTP servers."""

    @classmethod
    def setUpClass(cls):
        from keyper import create_keyper_app
        from backend import create_backend_app
        from bulletin_board import create_bb_app

        n_keypers = 3
        cls.backend_port, cls.keyper_ports, cls.bb_port = _next_ports(n_keypers)
        cls.backend_url = f"http://127.0.0.1:{cls.backend_port}"
        cls.keyper_urls = [f"http://127.0.0.1:{p}" for p in cls.keyper_ports]
        cls.bb_url = f"http://127.0.0.1:{cls.bb_port}"

        bb_app = create_bb_app()
        _start_flask(bb_app, cls.bb_port)

        for i, port in enumerate(cls.keyper_ports):
            app = create_keyper_app(i + 1)
            _start_flask(app, port)

        backend_app = create_backend_app(cls.keyper_urls, cls.bb_url)
        _start_flask(backend_app, cls.backend_port)

        assert _wait_for(f"{cls.bb_url}/bb/status"), "Bulletin board not ready"
        for url in cls.keyper_urls:
            assert _wait_for(f"{url}/status"), f"Keyper at {url} not ready"
        assert _wait_for(f"{cls.backend_url}/election/status"), "Backend not ready"

    def test_full_budget_election(self):
        """3 candidates, B=3, 3 voters -> expected tally [4, 3, 2]."""
        resp = requests.post(f"{self.backend_url}/election/create", json={
            "n": 3, "t": 1, "num_candidates": 3, "budget": 3,
            "candidate_names": ["X", "Y", "Z"],
        }, timeout=30)
        self.assertEqual(resp.status_code, 200)

        resp = requests.post(f"{self.backend_url}/election/dkg", timeout=120)
        self.assertEqual(resp.status_code, 200)

        for votes in [[2,1,0], [1,1,1], [1,1,1]]:
            result = _submit_vote_http(self.backend_url, votes)
            self.assertEqual(result.get("status"), "ok")

        resp = requests.post(f"{self.backend_url}/election/tally", timeout=120)
        self.assertEqual(resp.status_code, 200)
        results = resp.json()["results"]
        self.assertEqual(results["X"], 4)
        self.assertEqual(results["Y"], 3)
        self.assertEqual(results["Z"], 2)


class TestE2ERejectInvalidVote(unittest.TestCase):
    """E2E: Backend rejects votes with invalid proofs."""

    @classmethod
    def setUpClass(cls):
        from keyper import create_keyper_app
        from backend import create_backend_app
        from bulletin_board import create_bb_app

        n_keypers = 3
        cls.backend_port, cls.keyper_ports, cls.bb_port = _next_ports(n_keypers)
        cls.backend_url = f"http://127.0.0.1:{cls.backend_port}"
        cls.keyper_urls = [f"http://127.0.0.1:{p}" for p in cls.keyper_ports]
        cls.bb_url = f"http://127.0.0.1:{cls.bb_port}"

        bb_app = create_bb_app()
        _start_flask(bb_app, cls.bb_port)

        for i, port in enumerate(cls.keyper_ports):
            app = create_keyper_app(i + 1)
            _start_flask(app, port)

        backend_app = create_backend_app(cls.keyper_urls, cls.bb_url)
        _start_flask(backend_app, cls.backend_port)

        assert _wait_for(f"{cls.bb_url}/bb/status"), "Bulletin board not ready"
        for url in cls.keyper_urls:
            assert _wait_for(f"{url}/status"), f"Keyper at {url} not ready"
        assert _wait_for(f"{cls.backend_url}/election/status"), "Backend not ready"

    def test_reject_tampered_proof(self):
        """Vote with tampered range proof should be rejected."""
        resp = requests.post(f"{self.backend_url}/election/create", json={
            "n": 3, "t": 1, "num_candidates": 2, "budget": 1,
            "candidate_names": ["Yes", "No"],
        }, timeout=30)
        self.assertEqual(resp.status_code, 200)

        resp = requests.post(f"{self.backend_url}/election/dkg", timeout=120)
        self.assertEqual(resp.status_code, 200)

        params = requests.get(f"{self.backend_url}/election/params", timeout=5).json()
        mpk = dict_to_point(params["mpk"])

        C1a, C2a, r1 = encrypt(mpk, 1)
        C1b, C2b, r2 = encrypt(mpk, 0)

        proof1 = prove_range(mpk, C1a, C2a, 1, r1, 1)
        proof2 = prove_range(mpk, C1b, C2b, 0, r2, 1)

        agg = aggregate_ciphertexts([(C1a, C2a), (C1b, C2b)])
        r_sum = (r1 + r2) % CURVE_ORDER
        bp = prove_exact_budget(mpk, agg[0], agg[1], 1, r_sum)

        # Tamper with proof1
        tampered_proof1 = list(proof1)
        e, z = tampered_proof1[0]
        tampered_proof1[0] = ((e + 1) % CURVE_ORDER, z)

        payload = {
            "ciphertexts": [
                {"c1": point_to_dict(C1a), "c2": point_to_dict(C2a)},
                {"c1": point_to_dict(C1b), "c2": point_to_dict(C2b)},
            ],
            "range_proofs": [
                [{"e": str(ei), "z": str(zi)} for (ei, zi) in tampered_proof1],
                [{"e": str(ei), "z": str(zi)} for (ei, zi) in proof2],
            ],
            "budget_proof": {"e": str(bp[0]), "z": str(bp[1])},
        }
        resp = requests.post(f"{self.backend_url}/election/vote", json=payload, timeout=30)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("invalid", resp.json()["error"].lower())


# ======================================================================
#  Main
# ======================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
