#!/usr/bin/env python3
"""
Comprehensive test suite for the threshold ElGamal voting system.

Tests are organized in layers:
  1. Unit tests: crypto primitives, ElGamal, DKG, ZK proofs
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
import random
import math
import sys
import os
import logging
import requests

# Suppress Flask/werkzeug noise during tests
logging.getLogger("werkzeug").setLevel(logging.ERROR)

from crypto.primitives import generate_group_params, hash_to_int, validate_group_element
from crypto.elgamal import (
    encrypt, homomorphic_add, aggregate_ciphertexts,
    baby_step_giant_step, combine_decryption_shares, threshold_decrypt,
)
from crypto.dkg import KeyperDKGState
from crypto.proofs import (
    prove_range, verify_range,
    prove_exact_budget, verify_exact_budget,
    prove_decryption_share, verify_decryption_share,
)


# ======================================================================
#  Shared fixtures
# ======================================================================

# Pre-generate one set of group params (expensive) and reuse across tests.
# 256-bit safe prime is standard; we also test with a small prime for speed.
_PARAMS_256 = None
_SMALL_PARAMS = None


def get_params_256():
    global _PARAMS_256
    if _PARAMS_256 is None:
        _PARAMS_256 = generate_group_params(bits=256)
    return _PARAMS_256


def get_small_params():
    """Small safe prime for fast tests: p = 2*q + 1 where q = 1019, p = 2039."""
    global _SMALL_PARAMS
    if _SMALL_PARAMS is None:
        # Find a small safe prime manually
        for q_candidate in range(1000, 5000):
            from Crypto.Util.number import isPrime
            if isPrime(q_candidate):
                p_candidate = 2 * q_candidate + 1
                if isPrime(p_candidate):
                    p, q = p_candidate, q_candidate
                    # Find generator of order-q subgroup
                    for h in range(2, p):
                        g = pow(h, 2, p)
                        if g > 1 and pow(g, q, p) == 1:
                            _SMALL_PARAMS = (p, q, g)
                            return _SMALL_PARAMS
        raise RuntimeError("Could not find small safe prime")
    return _SMALL_PARAMS


# ======================================================================
#  1. UNIT TESTS: Primitives
# ======================================================================

class TestGroupParams(unittest.TestCase):
    """Test safe prime group parameter generation."""

    def test_safe_prime_property(self):
        """p = 2q + 1 where both p and q are prime."""
        p, q, g = get_params_256()
        self.assertEqual(p, 2 * q + 1)

    def test_p_and_q_are_prime(self):
        from Crypto.Util.number import isPrime
        p, q, g = get_params_256()
        self.assertTrue(isPrime(p))
        self.assertTrue(isPrime(q))

    def test_generator_order(self):
        """g has order q in Z_p*."""
        p, q, g = get_params_256()
        self.assertEqual(pow(g, q, p), 1)
        self.assertNotEqual(g, 1)

    def test_generator_not_trivial(self):
        """g != 1 and g != p-1."""
        p, q, g = get_params_256()
        self.assertNotEqual(g, 1)
        self.assertNotEqual(g, p - 1)

    def test_different_calls_produce_different_params(self):
        """Two calls generate different primes (probabilistic)."""
        p1, q1, g1 = generate_group_params(bits=128)
        p2, q2, g2 = generate_group_params(bits=128)
        self.assertNotEqual(p1, p2)

    def test_hash_deterministic(self):
        """hash_to_int is deterministic for same input."""
        h1 = hash_to_int(42, "hello", 99)
        h2 = hash_to_int(42, "hello", 99)
        self.assertEqual(h1, h2)

    def test_hash_different_inputs(self):
        """Different inputs produce different hashes."""
        h1 = hash_to_int(1, 2, 3)
        h2 = hash_to_int(1, 2, 4)
        self.assertNotEqual(h1, h2)

    def test_hash_no_concatenation_collision(self):
        """Length-prefixed serialization prevents H(1,23) == H(12,3)."""
        h1 = hash_to_int(1, 23)
        h2 = hash_to_int(12, 3)
        self.assertNotEqual(h1, h2)

    def test_hash_no_string_int_collision(self):
        """H(123) as int != H('123') as string."""
        h1 = hash_to_int(123)
        h2 = hash_to_int("123")
        self.assertNotEqual(h1, h2)

    def test_hash_domain_separation(self):
        """Different domain tags produce different hashes for same input."""
        h1 = hash_to_int(1, 2, 3, domain=b"RANGE")
        h2 = hash_to_int(1, 2, 3, domain=b"BUDGET")
        self.assertNotEqual(h1, h2)

    def test_hash_domain_vs_no_domain(self):
        """Hash with domain != hash without domain."""
        h1 = hash_to_int(1, 2, 3)
        h2 = hash_to_int(1, 2, 3, domain=b"TAG")
        self.assertNotEqual(h1, h2)


class TestValidateGroupElement(unittest.TestCase):
    """Test subgroup membership validation."""

    def setUp(self):
        self.p, self.q, self.g = get_params_256()

    def test_generator_is_valid(self):
        """Generator g passes validation."""
        validate_group_element(self.g, self.p, self.q)  # should not raise

    def test_identity_is_valid(self):
        """1 (identity) has 1^q = 1 mod p, so it's valid."""
        validate_group_element(1, self.p, self.q)

    def test_zero_rejected(self):
        """0 is not in Z_p*."""
        with self.assertRaises(ValueError):
            validate_group_element(0, self.p, self.q)

    def test_p_rejected(self):
        """p is not < p."""
        with self.assertRaises(ValueError):
            validate_group_element(self.p, self.p, self.q)

    def test_negative_rejected(self):
        """Negative numbers rejected."""
        with self.assertRaises(ValueError):
            validate_group_element(-1, self.p, self.q)

    def test_non_subgroup_element_rejected(self):
        """Element of order 2 (= p-1) is not in order-q subgroup."""
        # p-1 has order 2 in Z_p* (since (p-1)^2 = 1 mod p)
        # For safe prime p=2q+1, p-1 is NOT in the order-q subgroup
        # (p-1)^q mod p = (-1)^q mod p; since q is odd prime, = p-1 != 1
        element = self.p - 1
        with self.assertRaises(ValueError):
            validate_group_element(element, self.p, self.q)

    def test_random_subgroup_element_valid(self):
        """g^x is always in the subgroup."""
        import secrets
        x = secrets.randbelow(self.q - 1) + 1
        elem = pow(self.g, x, self.p)
        validate_group_element(elem, self.p, self.q)

    def test_ciphertext_components_valid(self):
        """Ciphertext from encrypt() passes validation."""
        pk = pow(self.g, 42, self.p)
        c1, c2, r = encrypt(self.p, self.q, self.g, pk, 5)
        validate_group_element(c1, self.p, self.q)
        validate_group_element(c2, self.p, self.q)


# ======================================================================
#  2. UNIT TESTS: ElGamal Encryption
# ======================================================================

class TestElGamalEncryption(unittest.TestCase):
    """Test ElGamal encryption in the exponent."""

    def setUp(self):
        self.p, self.q, self.g = get_params_256()
        self.sk = random.randrange(1, self.q)
        self.pk = pow(self.g, self.sk, self.p)

    def test_encrypt_decrypt_zero(self):
        """Encrypt and brute-force decrypt m=0."""
        c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, 0)
        tau = (c2 * pow(pow(c1, self.sk, self.p), -1, self.p)) % self.p
        m = baby_step_giant_step(self.g, tau, self.p, 10)
        self.assertEqual(m, 0)

    def test_encrypt_decrypt_small_values(self):
        """Encrypt and decrypt small values 0..10."""
        for m_orig in range(11):
            c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, m_orig)
            tau = (c2 * pow(pow(c1, self.sk, self.p), -1, self.p)) % self.p
            m = baby_step_giant_step(self.g, tau, self.p, 20)
            self.assertEqual(m, m_orig, f"Failed for m={m_orig}")

    def test_ciphertext_in_group(self):
        """Ciphertext components are in Z_p* and in the subgroup."""
        c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, 5)
        self.assertTrue(1 <= c1 < self.p)
        self.assertTrue(1 <= c2 < self.p)
        # c1 = g^r should be in subgroup
        self.assertEqual(pow(c1, self.q, self.p), 1)

    def test_randomized_encryption(self):
        """Encrypting the same message twice gives different ciphertexts."""
        c1a, c2a, _ = encrypt(self.p, self.q, self.g, self.pk, 3)
        c1b, c2b, _ = encrypt(self.p, self.q, self.g, self.pk, 3)
        self.assertNotEqual((c1a, c2a), (c1b, c2b))


class TestHomomorphicProperties(unittest.TestCase):
    """Test linear homomorphic properties of ElGamal."""

    def setUp(self):
        self.p, self.q, self.g = get_params_256()
        self.sk = random.randrange(1, self.q)
        self.pk = pow(self.g, self.sk, self.p)

    def _decrypt(self, c1, c2, max_val=100):
        tau = (c2 * pow(pow(c1, self.sk, self.p), -1, self.p)) % self.p
        return baby_step_giant_step(self.g, tau, self.p, max_val)

    def test_add_two_ciphertexts(self):
        """Enc(3) + Enc(5) = Enc(8)."""
        ct_a = encrypt(self.p, self.q, self.g, self.pk, 3)[:2]
        ct_b = encrypt(self.p, self.q, self.g, self.pk, 5)[:2]
        ct_sum = homomorphic_add(ct_a, ct_b, self.p)
        self.assertEqual(self._decrypt(*ct_sum), 8)

    def test_add_zero(self):
        """Enc(7) + Enc(0) = Enc(7)."""
        ct_a = encrypt(self.p, self.q, self.g, self.pk, 7)[:2]
        ct_b = encrypt(self.p, self.q, self.g, self.pk, 0)[:2]
        ct_sum = homomorphic_add(ct_a, ct_b, self.p)
        self.assertEqual(self._decrypt(*ct_sum), 7)

    def test_aggregate_many(self):
        """Aggregate 10 encryptions of 1 = Enc(10)."""
        cts = [encrypt(self.p, self.q, self.g, self.pk, 1)[:2] for _ in range(10)]
        agg = aggregate_ciphertexts(cts, self.p)
        self.assertEqual(self._decrypt(*agg), 10)

    def test_aggregate_empty(self):
        """Aggregating empty list yields encryption of 0."""
        agg = aggregate_ciphertexts([], self.p)
        self.assertEqual(self._decrypt(*agg), 0)

    def test_aggregate_mixed_values(self):
        """Aggregate [0, 3, 0, 2, 1] = Enc(6)."""
        values = [0, 3, 0, 2, 1]
        cts = [encrypt(self.p, self.q, self.g, self.pk, v)[:2] for v in values]
        agg = aggregate_ciphertexts(cts, self.p)
        self.assertEqual(self._decrypt(*agg), 6)

    def test_commutativity(self):
        """Enc(a) + Enc(b) == Enc(b) + Enc(a)."""
        ct_a = encrypt(self.p, self.q, self.g, self.pk, 2)[:2]
        ct_b = encrypt(self.p, self.q, self.g, self.pk, 5)[:2]
        sum_ab = homomorphic_add(ct_a, ct_b, self.p)
        sum_ba = homomorphic_add(ct_b, ct_a, self.p)
        self.assertEqual(sum_ab, sum_ba)

    def test_associativity(self):
        """(Enc(a) + Enc(b)) + Enc(c) == Enc(a) + (Enc(b) + Enc(c))."""
        ct_a = encrypt(self.p, self.q, self.g, self.pk, 1)[:2]
        ct_b = encrypt(self.p, self.q, self.g, self.pk, 2)[:2]
        ct_c = encrypt(self.p, self.q, self.g, self.pk, 3)[:2]
        lhs = homomorphic_add(homomorphic_add(ct_a, ct_b, self.p), ct_c, self.p)
        rhs = homomorphic_add(ct_a, homomorphic_add(ct_b, ct_c, self.p), self.p)
        self.assertEqual(lhs, rhs)


class TestBabyStepGiantStep(unittest.TestCase):
    """Test BSGS discrete log algorithm."""

    def setUp(self):
        self.p, self.q, self.g = get_small_params()

    def test_find_zero(self):
        self.assertEqual(baby_step_giant_step(self.g, 1, self.p, 100), 0)

    def test_find_one(self):
        target = pow(self.g, 1, self.p)
        self.assertEqual(baby_step_giant_step(self.g, target, self.p, 100), 1)

    def test_find_all_in_range(self):
        """Find all values 0..50."""
        for m in range(51):
            target = pow(self.g, m, self.p)
            result = baby_step_giant_step(self.g, target, self.p, 50)
            self.assertEqual(result, m, f"Failed for m={m}")

    def test_out_of_range_returns_none(self):
        """Value above max_val is not found."""
        target = pow(self.g, 60, self.p)
        result = baby_step_giant_step(self.g, target, self.p, 50)
        self.assertIsNone(result)

    def test_max_val_zero(self):
        """max_val=0 only finds m=0."""
        self.assertEqual(baby_step_giant_step(self.g, 1, self.p, 0), 0)
        target = pow(self.g, 1, self.p)
        self.assertIsNone(baby_step_giant_step(self.g, target, self.p, 0))


# ======================================================================
#  3. UNIT TESTS: Distributed Key Generation
# ======================================================================

class TestDKGLocal(unittest.TestCase):
    """Test DKG protocol without network (direct function calls)."""

    def setUp(self):
        self.p, self.q, self.g = get_params_256()

    def _run_dkg(self, n, t):
        """Run full DKG locally and return (mpk, keypers)."""
        keypers = [KeyperDKGState() for _ in range(n)]

        # Round 1: each keyper generates commitments and shares
        all_commitments = {}
        all_shares = {}
        for idx, kp in enumerate(keypers):
            kid = idx + 1
            comms, shares = kp.round1(kid, self.p, self.q, self.g, n, t)
            all_commitments[kid] = comms
            all_shares[kid] = shares

        # Round 2: each keyper receives shares and verifies
        for idx, kp in enumerate(keypers):
            kid = idx + 1
            received = {dealer_id: shares[kid] for dealer_id, shares in all_shares.items()}
            kp.round2(all_commitments, received)

        # Compute mpk from commitments
        mpk = 1
        for kid in range(1, n + 1):
            gamma_0 = all_commitments[kid][0]
            mpk = (mpk * gamma_0) % self.p

        return mpk, keypers

    def test_dkg_3_of_5(self):
        """DKG with n=5, t=2 (need 3 for decryption)."""
        mpk, keypers = self._run_dkg(n=5, t=2)
        self.assertIsNotNone(mpk)
        self.assertNotEqual(mpk, 1)
        for kp in keypers:
            self.assertIsNotNone(kp.combined_share)
            self.assertIsNotNone(kp.public_key_share)

    def test_dkg_2_of_3(self):
        """DKG with n=3, t=1."""
        mpk, keypers = self._run_dkg(n=3, t=1)
        self.assertIsNotNone(mpk)

    def test_dkg_1_of_2(self):
        """Minimal DKG: n=2, t=1."""
        mpk, keypers = self._run_dkg(n=2, t=1)
        self.assertIsNotNone(mpk)

    def test_dkg_public_key_shares_match(self):
        """Each keyper's public key share = g^msk_k."""
        _, keypers = self._run_dkg(n=4, t=2)
        for kp in keypers:
            expected = pow(self.g, kp.combined_share, self.p)
            self.assertEqual(kp.public_key_share, expected)

    def test_dkg_threshold_reconstruction(self):
        """t+1 shares can reconstruct the full secret key."""
        mpk, keypers = self._run_dkg(n=5, t=2)

        # Encrypt a known message
        m_orig = 7
        c1, c2, r = encrypt(self.p, self.q, self.g, mpk, m_orig)

        # Use exactly t+1=3 keypers to decrypt
        shares = []
        for kp in keypers[:3]:
            sigma = kp.partial_decrypt(c1)
            shares.append((kp.keyper_id, sigma))

        m = threshold_decrypt(c1, c2, shares, self.p, self.q, self.g, 20)
        self.assertEqual(m, m_orig)

    def test_dkg_any_subset_of_t_plus_1(self):
        """Any t+1 subset can decrypt, not just the first t+1."""
        mpk, keypers = self._run_dkg(n=5, t=2)
        m_orig = 4
        c1, c2, r = encrypt(self.p, self.q, self.g, mpk, m_orig)

        # Try different subsets of size 3
        from itertools import combinations
        for subset in combinations(keypers, 3):
            shares = [(kp.keyper_id, kp.partial_decrypt(c1)) for kp in subset]
            m = threshold_decrypt(c1, c2, shares, self.p, self.q, self.g, 20)
            self.assertEqual(m, m_orig,
                             f"Failed with keypers {[kp.keyper_id for kp in subset]}")

    def test_dkg_t_shares_cannot_decrypt(self):
        """Only t shares (less than t+1) cannot reconstruct the secret."""
        mpk, keypers = self._run_dkg(n=5, t=2)
        m_orig = 3
        c1, c2, r = encrypt(self.p, self.q, self.g, mpk, m_orig)

        # Use only t=2 shares (need 3)
        shares = [(kp.keyper_id, kp.partial_decrypt(c1)) for kp in keypers[:2]]
        m = threshold_decrypt(c1, c2, shares, self.p, self.q, self.g, 20)
        # With only 2 shares, Lagrange interpolation gives wrong result
        self.assertNotEqual(m, m_orig)

    def test_dkg_feldman_verification_catches_bad_share(self):
        """Tampered shares are detected during Feldman VSS verification."""
        n, t = 3, 1
        keypers = [KeyperDKGState() for _ in range(n)]

        all_commitments = {}
        all_shares = {}
        for idx, kp in enumerate(keypers):
            kid = idx + 1
            comms, shares = kp.round1(kid, self.p, self.q, self.g, n, t)
            all_commitments[kid] = comms
            all_shares[kid] = shares

        # Tamper with dealer 1's share to keyper 2
        kid = 2
        received = {dealer_id: shares[kid] for dealer_id, shares in all_shares.items()}
        received[1] = (received[1] + 42) % self.q  # corrupt

        with self.assertRaises(ValueError):
            keypers[1].round2(all_commitments, received)

    def test_dkg_different_runs_different_keys(self):
        """Two DKG runs produce different master public keys."""
        mpk1, _ = self._run_dkg(n=3, t=1)
        mpk2, _ = self._run_dkg(n=3, t=1)
        self.assertNotEqual(mpk1, mpk2)


# ======================================================================
#  4. UNIT TESTS: Zero-Knowledge Proofs
# ======================================================================

class TestRangeProofs(unittest.TestCase):
    """Test ZK range proofs: v ∈ {0, ..., B}."""

    def setUp(self):
        self.p, self.q, self.g = get_params_256()
        self.sk = random.randrange(1, self.q)
        self.pk = pow(self.g, self.sk, self.p)

    def test_valid_proof_B1_m0(self):
        """Range proof for m=0, B=1 (binary vote)."""
        c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, 0)
        proof = prove_range(self.p, self.q, self.g, self.pk, c1, c2, 0, r, 1)
        self.assertTrue(verify_range(self.p, self.q, self.g, self.pk, c1, c2, proof, 1))

    def test_valid_proof_B1_m1(self):
        """Range proof for m=1, B=1."""
        c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, 1)
        proof = prove_range(self.p, self.q, self.g, self.pk, c1, c2, 1, r, 1)
        self.assertTrue(verify_range(self.p, self.q, self.g, self.pk, c1, c2, proof, 1))

    def test_valid_proofs_B5_all_values(self):
        """Range proof for each m in {0,...,5}, B=5."""
        for m in range(6):
            c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, m)
            proof = prove_range(self.p, self.q, self.g, self.pk, c1, c2, m, r, 5)
            self.assertTrue(
                verify_range(self.p, self.q, self.g, self.pk, c1, c2, proof, 5),
                f"Range proof failed for m={m}, B=5"
            )

    def test_valid_proof_B10_boundary(self):
        """Range proof for m=B=10 (upper boundary)."""
        c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, 10)
        proof = prove_range(self.p, self.q, self.g, self.pk, c1, c2, 10, r, 10)
        self.assertTrue(verify_range(self.p, self.q, self.g, self.pk, c1, c2, proof, 10))

    def test_proof_wrong_B_fails(self):
        """Proof for B=3 does not verify if verifier uses B=2."""
        c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, 3)
        proof = prove_range(self.p, self.q, self.g, self.pk, c1, c2, 3, r, 3)
        self.assertFalse(verify_range(self.p, self.q, self.g, self.pk, c1, c2, proof, 2))

    def test_tampered_proof_challenge_fails(self):
        """Tampering with a challenge value invalidates the proof."""
        c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, 1)
        proof = prove_range(self.p, self.q, self.g, self.pk, c1, c2, 1, r, 1)
        # Tamper with the first branch challenge
        proof[0] = (proof[0][0] + 1, proof[0][1])
        self.assertFalse(verify_range(self.p, self.q, self.g, self.pk, c1, c2, proof, 1))

    def test_tampered_proof_response_fails(self):
        """Tampering with a response value invalidates the proof."""
        c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, 1)
        proof = prove_range(self.p, self.q, self.g, self.pk, c1, c2, 1, r, 1)
        proof[1] = (proof[1][0], proof[1][1] + 1)
        self.assertFalse(verify_range(self.p, self.q, self.g, self.pk, c1, c2, proof, 1))

    def test_proof_for_wrong_ciphertext_fails(self):
        """Proof for one ciphertext does not verify for a different ciphertext."""
        c1_a, c2_a, r_a = encrypt(self.p, self.q, self.g, self.pk, 1)
        c1_b, c2_b, r_b = encrypt(self.p, self.q, self.g, self.pk, 0)
        proof = prove_range(self.p, self.q, self.g, self.pk, c1_a, c2_a, 1, r_a, 1)
        self.assertFalse(verify_range(self.p, self.q, self.g, self.pk, c1_b, c2_b, proof, 1))

    def test_proof_for_wrong_pk_fails(self):
        """Proof under pk1 does not verify under pk2."""
        c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, 1)
        proof = prove_range(self.p, self.q, self.g, self.pk, c1, c2, 1, r, 1)
        pk2 = pow(self.g, random.randrange(1, self.q), self.p)
        self.assertFalse(verify_range(self.p, self.q, self.g, pk2, c1, c2, proof, 1))

    def test_out_of_range_message_assertion(self):
        """Attempting to prove m > B raises an assertion."""
        c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, 3)
        with self.assertRaises(AssertionError):
            prove_range(self.p, self.q, self.g, self.pk, c1, c2, 3, r, 2)

    def test_negative_message_assertion(self):
        """Attempting to prove m < 0 raises an assertion."""
        c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, 0)
        with self.assertRaises(AssertionError):
            prove_range(self.p, self.q, self.g, self.pk, c1, c2, -1, r, 5)

    def test_proof_length_matches_B(self):
        """Proof contains exactly B+1 branches."""
        c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, 2)
        proof = prove_range(self.p, self.q, self.g, self.pk, c1, c2, 2, r, 5)
        self.assertEqual(len(proof), 6)

    def test_election_id_binding(self):
        """Proof with election_id='A' does not verify with election_id='B'."""
        c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, 1)
        proof = prove_range(self.p, self.q, self.g, self.pk, c1, c2, 1, r, 1, election_id="election_A")
        self.assertTrue(verify_range(self.p, self.q, self.g, self.pk, c1, c2, proof, 1, election_id="election_A"))
        self.assertFalse(verify_range(self.p, self.q, self.g, self.pk, c1, c2, proof, 1, election_id="election_B"))
        self.assertFalse(verify_range(self.p, self.q, self.g, self.pk, c1, c2, proof, 1))  # no election_id


class TestBudgetProofs(unittest.TestCase):
    """Test ZK exact budget proofs: sum(v_j) = B."""

    def setUp(self):
        self.p, self.q, self.g = get_params_256()
        self.sk = random.randrange(1, self.q)
        self.pk = pow(self.g, self.sk, self.p)

    def _make_budget_vote(self, votes, B):
        """Encrypt votes and produce budget proof."""
        assert sum(votes) == B
        cts = []
        rs = []
        for v in votes:
            c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, v)
            cts.append((c1, c2))
            rs.append(r)
        sum_ct = aggregate_ciphertexts(cts, self.p)
        r_sum = sum(rs) % self.q
        proof = prove_exact_budget(self.p, self.q, self.g, self.pk,
                                   sum_ct[0], sum_ct[1], B, r_sum)
        return sum_ct, proof

    def test_valid_budget_B1(self):
        """Budget proof for [1, 0, 0], B=1."""
        sum_ct, proof = self._make_budget_vote([1, 0, 0], 1)
        self.assertTrue(verify_exact_budget(
            self.p, self.q, self.g, self.pk, sum_ct[0], sum_ct[1], 1, proof))

    def test_valid_budget_B3(self):
        """Budget proof for [1, 1, 1, 0], B=3."""
        sum_ct, proof = self._make_budget_vote([1, 1, 1, 0], 3)
        self.assertTrue(verify_exact_budget(
            self.p, self.q, self.g, self.pk, sum_ct[0], sum_ct[1], 3, proof))

    def test_valid_budget_B5_concentrated(self):
        """Budget proof for [5, 0], B=5."""
        sum_ct, proof = self._make_budget_vote([5, 0], 5)
        self.assertTrue(verify_exact_budget(
            self.p, self.q, self.g, self.pk, sum_ct[0], sum_ct[1], 5, proof))

    def test_valid_budget_B10_spread(self):
        """Budget proof for [2, 3, 2, 3], B=10."""
        sum_ct, proof = self._make_budget_vote([2, 3, 2, 3], 10)
        self.assertTrue(verify_exact_budget(
            self.p, self.q, self.g, self.pk, sum_ct[0], sum_ct[1], 10, proof))

    def test_wrong_budget_value_fails(self):
        """Proof for B=3 doesn't verify if checked against B=2."""
        sum_ct, proof = self._make_budget_vote([1, 1, 1], 3)
        self.assertFalse(verify_exact_budget(
            self.p, self.q, self.g, self.pk, sum_ct[0], sum_ct[1], 2, proof))

    def test_tampered_budget_proof_challenge(self):
        """Tampered challenge invalidates budget proof."""
        sum_ct, proof = self._make_budget_vote([1, 0], 1)
        bad_proof = (proof[0] + 1, proof[1])
        self.assertFalse(verify_exact_budget(
            self.p, self.q, self.g, self.pk, sum_ct[0], sum_ct[1], 1, bad_proof))

    def test_tampered_budget_proof_response(self):
        """Tampered response invalidates budget proof."""
        sum_ct, proof = self._make_budget_vote([1, 0], 1)
        bad_proof = (proof[0], proof[1] + 1)
        self.assertFalse(verify_exact_budget(
            self.p, self.q, self.g, self.pk, sum_ct[0], sum_ct[1], 1, bad_proof))

    def test_actual_overspend_detected(self):
        """Votes summing to B+1 cannot produce a valid proof for B."""
        # Encrypt [1, 1] = sum 2, but claim B=1
        cts = []
        rs = []
        for v in [1, 1]:
            c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, v)
            cts.append((c1, c2))
            rs.append(r)
        sum_ct = aggregate_ciphertexts(cts, self.p)
        r_sum = sum(rs) % self.q
        # The prover tries to claim B=1, but sum is actually 2
        proof = prove_exact_budget(self.p, self.q, self.g, self.pk,
                                   sum_ct[0], sum_ct[1], 1, r_sum)
        # This proof should fail because the DLEQ relation doesn't hold
        self.assertFalse(verify_exact_budget(
            self.p, self.q, self.g, self.pk, sum_ct[0], sum_ct[1], 1, proof))

    def test_budget_election_id_binding(self):
        """Budget proof with election_id='A' fails under election_id='B'."""
        sum_ct, proof = self._make_budget_vote([1, 0], 1)
        # Re-create with election_id
        cts = []
        rs = []
        for v in [1, 0]:
            c1, c2, r = encrypt(self.p, self.q, self.g, self.pk, v)
            cts.append((c1, c2))
            rs.append(r)
        sum_ct = aggregate_ciphertexts(cts, self.p)
        r_sum = sum(rs) % self.q
        proof = prove_exact_budget(self.p, self.q, self.g, self.pk,
                                   sum_ct[0], sum_ct[1], 1, r_sum, election_id="elec_A")
        self.assertTrue(verify_exact_budget(
            self.p, self.q, self.g, self.pk, sum_ct[0], sum_ct[1], 1, proof, election_id="elec_A"))
        self.assertFalse(verify_exact_budget(
            self.p, self.q, self.g, self.pk, sum_ct[0], sum_ct[1], 1, proof, election_id="elec_B"))


class TestDecryptionShareProofs(unittest.TestCase):
    """Test ZK proofs of correct partial decryption."""

    def setUp(self):
        self.p, self.q, self.g = get_params_256()

    def test_valid_decryption_proof(self):
        """Valid DLEQ proof for decryption share verifies."""
        msk_k = random.randrange(1, self.q)
        mpk_k = pow(self.g, msk_k, self.p)
        msg = 5
        r = random.randrange(1, self.q)
        c1 = pow(self.g, r, self.p)
        sigma_k = pow(c1, msk_k, self.p)

        proof = prove_decryption_share(self.p, self.q, self.g, c1, msk_k, mpk_k, sigma_k)
        self.assertTrue(verify_decryption_share(
            self.p, self.q, self.g, c1, mpk_k, sigma_k, proof))

    def test_wrong_sigma_fails(self):
        """Proof with incorrect sigma does not verify."""
        msk_k = random.randrange(1, self.q)
        mpk_k = pow(self.g, msk_k, self.p)
        r = random.randrange(1, self.q)
        c1 = pow(self.g, r, self.p)
        sigma_k = pow(c1, msk_k, self.p)

        # Create valid proof, but verify with wrong sigma
        proof = prove_decryption_share(self.p, self.q, self.g, c1, msk_k, mpk_k, sigma_k)
        wrong_sigma = pow(c1, random.randrange(1, self.q), self.p)
        self.assertFalse(verify_decryption_share(
            self.p, self.q, self.g, c1, mpk_k, wrong_sigma, proof))

    def test_wrong_mpk_fails(self):
        """Proof for mpk1 does not verify against mpk2."""
        msk_k = random.randrange(1, self.q)
        mpk_k = pow(self.g, msk_k, self.p)
        r = random.randrange(1, self.q)
        c1 = pow(self.g, r, self.p)
        sigma_k = pow(c1, msk_k, self.p)

        proof = prove_decryption_share(self.p, self.q, self.g, c1, msk_k, mpk_k, sigma_k)
        wrong_mpk = pow(self.g, random.randrange(1, self.q), self.p)
        self.assertFalse(verify_decryption_share(
            self.p, self.q, self.g, c1, wrong_mpk, sigma_k, proof))

    def test_tampered_proof_fails(self):
        """Tampered DLEQ proof (modified e) does not verify."""
        msk_k = random.randrange(1, self.q)
        mpk_k = pow(self.g, msk_k, self.p)
        r = random.randrange(1, self.q)
        c1 = pow(self.g, r, self.p)
        sigma_k = pow(c1, msk_k, self.p)

        proof = prove_decryption_share(self.p, self.q, self.g, c1, msk_k, mpk_k, sigma_k)
        bad_proof = (proof[0] + 1, proof[1])
        self.assertFalse(verify_decryption_share(
            self.p, self.q, self.g, c1, mpk_k, sigma_k, bad_proof))

    def test_multiple_candidates(self):
        """Decryption proofs work for multiple ciphertexts (candidates)."""
        msk_k = random.randrange(1, self.q)
        mpk_k = pow(self.g, msk_k, self.p)

        for _ in range(5):
            r = random.randrange(1, self.q)
            c1 = pow(self.g, r, self.p)
            sigma_k = pow(c1, msk_k, self.p)
            proof = prove_decryption_share(self.p, self.q, self.g, c1, msk_k, mpk_k, sigma_k)
            self.assertTrue(verify_decryption_share(
                self.p, self.q, self.g, c1, mpk_k, sigma_k, proof))


# ======================================================================
#  5. INTEGRATION TESTS: Full crypto pipeline (no network)
# ======================================================================

class TestFullCryptoPipeline(unittest.TestCase):
    """Integration: DKG + Encrypt + Prove + Aggregate + Threshold Decrypt."""

    def setUp(self):
        self.p, self.q, self.g = get_params_256()

    def _run_dkg(self, n, t):
        keypers = [KeyperDKGState() for _ in range(n)]
        all_commitments = {}
        all_shares = {}
        for idx, kp in enumerate(keypers):
            kid = idx + 1
            comms, shares = kp.round1(kid, self.p, self.q, self.g, n, t)
            all_commitments[kid] = comms
            all_shares[kid] = shares
        for idx, kp in enumerate(keypers):
            kid = idx + 1
            received = {d_id: shares[kid] for d_id, shares in all_shares.items()}
            kp.round2(all_commitments, received)
        mpk = 1
        for kid in range(1, n + 1):
            mpk = (mpk * all_commitments[kid][0]) % self.p
        return mpk, keypers

    def test_full_single_choice_election(self):
        """Full election: 3 candidates, B=1, 10 voters, 5 keypers (t=2)."""
        n, t = 5, 2
        num_cand = 3
        B = 1
        mpk, keypers = self._run_dkg(n, t)

        # Simulate 10 voters: random choices
        expected = [0] * num_cand
        all_cts = [[] for _ in range(num_cand)]  # per-candidate lists

        for _ in range(10):
            choice = random.randint(0, num_cand - 1)
            votes = [0] * num_cand
            votes[choice] = 1
            expected[choice] += 1

            cts = []
            rs = []
            for j in range(num_cand):
                c1, c2, r = encrypt(self.p, self.q, self.g, mpk, votes[j])
                cts.append((c1, c2))
                rs.append(r)
                all_cts[j].append((c1, c2))

                # Verify range proof
                proof = prove_range(self.p, self.q, self.g, mpk, c1, c2, votes[j], r, B)
                self.assertTrue(verify_range(self.p, self.q, self.g, mpk, c1, c2, proof, B))

            # Verify budget proof
            sum_ct = aggregate_ciphertexts(cts, self.p)
            r_sum = sum(rs) % self.q
            bp = prove_exact_budget(self.p, self.q, self.g, mpk,
                                    sum_ct[0], sum_ct[1], B, r_sum)
            self.assertTrue(verify_exact_budget(
                self.p, self.q, self.g, mpk, sum_ct[0], sum_ct[1], B, bp))

        # Homomorphic aggregation
        agg_per_cand = [aggregate_ciphertexts(all_cts[j], self.p) for j in range(num_cand)]

        # Threshold decryption with t+1 keypers
        for j in range(num_cand):
            c1_j, c2_j = agg_per_cand[j]
            shares = []
            for kp in keypers[:t + 1]:
                sigma = kp.partial_decrypt(c1_j)
                mpk_k = kp.public_key_share
                proof = prove_decryption_share(self.p, self.q, self.g, c1_j,
                                               kp.combined_share, mpk_k, sigma)
                self.assertTrue(verify_decryption_share(
                    self.p, self.q, self.g, c1_j, mpk_k, sigma, proof))
                shares.append((kp.keyper_id, sigma))

            tally = threshold_decrypt(c1_j, c2_j, shares, self.p, self.q, self.g, 10)
            self.assertEqual(tally, expected[j], f"Candidate {j}: expected {expected[j]}, got {tally}")

    def test_full_budget_election(self):
        """Full election: 4 candidates, B=5, 6 voters, 3 keypers (t=1)."""
        n, t = 3, 1
        num_cand = 4
        B = 5
        mpk, keypers = self._run_dkg(n, t)

        expected = [0] * num_cand
        all_cts = [[] for _ in range(num_cand)]

        voter_ballots = [
            [5, 0, 0, 0],
            [0, 5, 0, 0],
            [2, 1, 1, 1],
            [1, 1, 2, 1],
            [0, 0, 0, 5],
            [1, 2, 2, 0],
        ]

        for votes in voter_ballots:
            self.assertEqual(sum(votes), B)
            for j in range(num_cand):
                expected[j] += votes[j]

            cts = []
            rs = []
            for j in range(num_cand):
                c1, c2, r = encrypt(self.p, self.q, self.g, mpk, votes[j])
                cts.append((c1, c2))
                rs.append(r)
                all_cts[j].append((c1, c2))

                proof = prove_range(self.p, self.q, self.g, mpk, c1, c2, votes[j], r, B)
                self.assertTrue(verify_range(self.p, self.q, self.g, mpk, c1, c2, proof, B))

            sum_ct = aggregate_ciphertexts(cts, self.p)
            r_sum = sum(rs) % self.q
            bp = prove_exact_budget(self.p, self.q, self.g, mpk,
                                    sum_ct[0], sum_ct[1], B, r_sum)
            self.assertTrue(verify_exact_budget(
                self.p, self.q, self.g, mpk, sum_ct[0], sum_ct[1], B, bp))

        agg = [aggregate_ciphertexts(all_cts[j], self.p) for j in range(num_cand)]
        max_val = len(voter_ballots) * B

        for j in range(num_cand):
            shares = [(kp.keyper_id, kp.partial_decrypt(agg[j][0])) for kp in keypers[:t + 1]]
            tally = threshold_decrypt(agg[j][0], agg[j][1], shares, self.p, self.q, self.g, max_val)
            self.assertEqual(tally, expected[j])

    def test_zero_votes_tallied_correctly(self):
        """Edge case: All voters give 0 to a candidate."""
        n, t = 3, 1
        num_cand = 2
        B = 1
        mpk, keypers = self._run_dkg(n, t)

        # All 5 voters vote for candidate 0
        all_cts = [[] for _ in range(num_cand)]
        for _ in range(5):
            for j in range(num_cand):
                v = 1 if j == 0 else 0
                c1, c2, r = encrypt(self.p, self.q, self.g, mpk, v)
                all_cts[j].append((c1, c2))

        # Candidate 1 should get 0 votes
        agg1 = aggregate_ciphertexts(all_cts[1], self.p)
        shares = [(kp.keyper_id, kp.partial_decrypt(agg1[0])) for kp in keypers[:t + 1]]
        tally = threshold_decrypt(agg1[0], agg1[1], shares, self.p, self.q, self.g, 5)
        self.assertEqual(tally, 0)

    def test_single_voter(self):
        """Edge case: Only one voter in the election."""
        n, t = 3, 1
        num_cand = 3
        B = 1
        mpk, keypers = self._run_dkg(n, t)

        votes = [0, 1, 0]  # vote for candidate 1
        cts = []
        for j in range(num_cand):
            c1, c2, r = encrypt(self.p, self.q, self.g, mpk, votes[j])
            cts.append((c1, c2))

        for j in range(num_cand):
            agg = aggregate_ciphertexts([cts[j]], self.p)
            shares = [(kp.keyper_id, kp.partial_decrypt(agg[0])) for kp in keypers[:t + 1]]
            tally = threshold_decrypt(agg[0], agg[1], shares, self.p, self.q, self.g, B)
            self.assertEqual(tally, votes[j])

    def test_large_budget_B20(self):
        """Budget B=20, 3 candidates, 4 voters."""
        n, t = 3, 1
        num_cand = 3
        B = 20
        mpk, keypers = self._run_dkg(n, t)

        ballots = [
            [10, 7, 3],
            [0, 20, 0],
            [5, 5, 10],
            [20, 0, 0],
        ]
        expected = [35, 32, 13]

        all_cts = [[] for _ in range(num_cand)]
        for votes in ballots:
            for j in range(num_cand):
                c1, c2, r = encrypt(self.p, self.q, self.g, mpk, votes[j])
                all_cts[j].append((c1, c2))

        max_val = len(ballots) * B
        for j in range(num_cand):
            agg = aggregate_ciphertexts(all_cts[j], self.p)
            shares = [(kp.keyper_id, kp.partial_decrypt(agg[0])) for kp in keypers[:t + 1]]
            tally = threshold_decrypt(agg[0], agg[1], shares, self.p, self.q, self.g, max_val)
            self.assertEqual(tally, expected[j])


# ======================================================================
#  6. SYSTEM (E2E) TESTS: Full HTTP server lifecycle
# ======================================================================

def _start_flask(app, port, host="127.0.0.1"):
    t = threading.Thread(
        target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False),
        daemon=True,
    )
    t.start()
    return t


def _wait_for(url, retries=30, delay=0.2):
    for _ in range(retries):
        try:
            requests.get(url, timeout=1)
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(delay)
    return False


def _submit_vote_http(backend_url, vote_vector):
    """Encrypt + prove + submit vote via HTTP."""
    params = requests.get(f"{backend_url}/election/params", timeout=5).json()
    p = int(params["p"])
    q = int(params["q"])
    g = int(params["g"])
    mpk = int(params["mpk"])
    B = params["budget"]

    cts = []
    rs = []
    for v in vote_vector:
        c1, c2, r = encrypt(p, q, g, mpk, v)
        cts.append((c1, c2))
        rs.append(r)

    rps = []
    for j in range(len(vote_vector)):
        proof = prove_range(p, q, g, mpk, cts[j][0], cts[j][1], vote_vector[j], rs[j], B)
        rps.append(proof)

    sum_ct = aggregate_ciphertexts(cts, p)
    r_sum = sum(rs) % q
    bp = prove_exact_budget(p, q, g, mpk, sum_ct[0], sum_ct[1], B, r_sum)

    payload = {
        "ciphertexts": [{"c1": str(ct[0]), "c2": str(ct[1])} for ct in cts],
        "range_proofs": [[{"e": str(e), "z": str(z)} for (e, z) in proof] for proof in rps],
        "budget_proof": {"e": str(bp[0]), "z": str(bp[1])},
    }
    return requests.post(f"{backend_url}/election/vote", json=payload, timeout=30).json()


class TestE2ESingleChoice(unittest.TestCase):
    """E2E: Single-choice election via HTTP."""

    @classmethod
    def setUpClass(cls):
        from keyper import create_keyper_app
        from backend import create_backend_app

        cls.BACKEND_PORT = 7000
        cls.KEYPER_PORTS = [7001, 7002, 7003]
        cls.backend_url = f"http://127.0.0.1:{cls.BACKEND_PORT}"
        keyper_urls = [f"http://127.0.0.1:{p}" for p in cls.KEYPER_PORTS]

        for i, port in enumerate(cls.KEYPER_PORTS):
            _start_flask(create_keyper_app(i + 1), port)
        _start_flask(create_backend_app(keyper_urls), cls.BACKEND_PORT)

        for url in keyper_urls:
            assert _wait_for(f"{url}/status"), f"Keyper at {url} did not start"
        assert _wait_for(f"{cls.backend_url}/election/status"), "Backend did not start"

    def test_01_create_election(self):
        resp = requests.post(f"{self.backend_url}/election/create", json={
            "n": 3, "t": 1, "num_candidates": 3, "budget": 1,
            "candidate_names": ["Alice", "Bob", "Charlie"],
        }, timeout=30)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["phase"], "setup")

    def test_02_run_dkg(self):
        resp = requests.post(f"{self.backend_url}/election/dkg", timeout=60)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["phase"], "voting")
        self.assertIn("mpk", data)

    def test_03_submit_votes(self):
        votes = [[1,0,0], [0,1,0], [0,1,0], [1,0,0], [0,0,1]]
        for i, v in enumerate(votes):
            result = _submit_vote_http(self.backend_url, v)
            self.assertEqual(result["status"], "ok", f"Vote {i} failed: {result}")

    def test_04_status_shows_ballots(self):
        resp = requests.get(f"{self.backend_url}/election/status", timeout=5)
        data = resp.json()
        self.assertEqual(data["ballots_received"], 5)
        self.assertEqual(data["phase"], "voting")

    def test_05_tally_correct(self):
        resp = requests.post(f"{self.backend_url}/election/tally", timeout=60)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["results"]["Alice"], 2)
        self.assertEqual(data["results"]["Bob"], 2)
        self.assertEqual(data["results"]["Charlie"], 1)

    def test_06_result_endpoint(self):
        resp = requests.get(f"{self.backend_url}/election/result", timeout=5)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total_ballots"], 5)

    def test_07_vote_rejected_after_tally(self):
        """Votes are rejected once tallying is complete."""
        result = _submit_vote_http(self.backend_url, [1, 0, 0])
        self.assertIn("error", result)


class TestE2EBudgetElection(unittest.TestCase):
    """E2E: Budget election (B=3) via HTTP."""

    @classmethod
    def setUpClass(cls):
        from keyper import create_keyper_app
        from backend import create_backend_app

        cls.BACKEND_PORT = 7100
        cls.KEYPER_PORTS = [7101, 7102, 7103, 7104]
        cls.backend_url = f"http://127.0.0.1:{cls.BACKEND_PORT}"
        keyper_urls = [f"http://127.0.0.1:{p}" for p in cls.KEYPER_PORTS]

        for i, port in enumerate(cls.KEYPER_PORTS):
            _start_flask(create_keyper_app(i + 1), port)
        _start_flask(create_backend_app(keyper_urls), cls.BACKEND_PORT)

        for url in keyper_urls:
            assert _wait_for(f"{url}/status"), f"Keyper at {url} did not start"
        assert _wait_for(f"{cls.backend_url}/election/status"), "Backend did not start"

        # Setup election + DKG
        resp = requests.post(f"{cls.backend_url}/election/create", json={
            "n": 4, "t": 2, "num_candidates": 4, "budget": 3,
            "candidate_names": ["Alpha", "Beta", "Gamma", "Delta"],
        }, timeout=30)
        assert resp.status_code == 200
        resp = requests.post(f"{cls.backend_url}/election/dkg", timeout=60)
        assert resp.status_code == 200

    def test_budget_votes_and_tally(self):
        """Submit budget votes and verify tally."""
        votes = [
            [3, 0, 0, 0],  # Alpha=3
            [0, 3, 0, 0],  # Beta=3
            [1, 1, 1, 0],  # spread
            [0, 0, 1, 2],  # Gamma=1, Delta=2
        ]
        expected = {"Alpha": 4, "Beta": 4, "Gamma": 2, "Delta": 2}

        for v in votes:
            result = _submit_vote_http(self.backend_url, v)
            self.assertEqual(result["status"], "ok")

        resp = requests.post(f"{self.backend_url}/election/tally", timeout=60)
        self.assertEqual(resp.status_code, 200)
        results = resp.json()["results"]
        for name, count in expected.items():
            self.assertEqual(results[name], count, f"{name}: expected {count}, got {results[name]}")


class TestE2EInvalidVotes(unittest.TestCase):
    """E2E: Malformed and invalid votes are rejected."""

    @classmethod
    def setUpClass(cls):
        from keyper import create_keyper_app
        from backend import create_backend_app

        cls.BACKEND_PORT = 7200
        cls.KEYPER_PORTS = [7201, 7202, 7203]
        cls.backend_url = f"http://127.0.0.1:{cls.BACKEND_PORT}"
        keyper_urls = [f"http://127.0.0.1:{p}" for p in cls.KEYPER_PORTS]

        for i, port in enumerate(cls.KEYPER_PORTS):
            _start_flask(create_keyper_app(i + 1), port)
        _start_flask(create_backend_app(keyper_urls), cls.BACKEND_PORT)

        for url in keyper_urls:
            assert _wait_for(f"{url}/status")
        assert _wait_for(f"{cls.backend_url}/election/status")

        resp = requests.post(f"{cls.backend_url}/election/create", json={
            "n": 3, "t": 1, "num_candidates": 2, "budget": 1,
            "candidate_names": ["Yes", "No"],
        }, timeout=30)
        assert resp.status_code == 200
        resp = requests.post(f"{cls.backend_url}/election/dkg", timeout=60)
        assert resp.status_code == 200

    def test_wrong_number_of_ciphertexts(self):
        """Submit 3 ciphertexts for a 2-candidate election."""
        params = requests.get(f"{self.backend_url}/election/params", timeout=5).json()
        p = int(params["p"])
        q = int(params["q"])
        g = int(params["g"])
        mpk = int(params["mpk"])

        cts = []
        rps = []
        for v in [1, 0, 0]:  # 3 instead of 2
            c1, c2, r = encrypt(p, q, g, mpk, v)
            cts.append((c1, c2))
            proof = prove_range(p, q, g, mpk, c1, c2, v, r, 1)
            rps.append(proof)

        payload = {
            "ciphertexts": [{"c1": str(ct[0]), "c2": str(ct[1])} for ct in cts],
            "range_proofs": [[{"e": str(e), "z": str(z)} for (e, z) in proof] for proof in rps],
            "budget_proof": {"e": "1", "z": "1"},
        }
        resp = requests.post(f"{self.backend_url}/election/vote", json=payload, timeout=10)
        self.assertEqual(resp.status_code, 400)

    def test_fake_range_proof_rejected(self):
        """Encrypt out-of-range value with fake proof."""
        params = requests.get(f"{self.backend_url}/election/params", timeout=5).json()
        p = int(params["p"])
        q = int(params["q"])
        g = int(params["g"])
        mpk = int(params["mpk"])

        # Encrypt valid values but supply random proof
        c1, c2, r = encrypt(p, q, g, mpk, 1)
        # Fake range proof
        fake_proof = [(random.randrange(1, q), random.randrange(1, q)) for _ in range(2)]

        c1b, c2b, rb = encrypt(p, q, g, mpk, 0)
        real_proof_b = prove_range(p, q, g, mpk, c1b, c2b, 0, rb, 1)

        payload = {
            "ciphertexts": [
                {"c1": str(c1), "c2": str(c2)},
                {"c1": str(c1b), "c2": str(c2b)},
            ],
            "range_proofs": [
                [{"e": str(e), "z": str(z)} for (e, z) in fake_proof],
                [{"e": str(e), "z": str(z)} for (e, z) in real_proof_b],
            ],
            "budget_proof": {"e": "1", "z": "1"},
        }
        resp = requests.post(f"{self.backend_url}/election/vote", json=payload, timeout=10)
        self.assertEqual(resp.status_code, 400)

    def test_valid_vote_still_accepted(self):
        """After invalid attempts, valid votes still work."""
        result = _submit_vote_http(self.backend_url, [1, 0])
        self.assertEqual(result["status"], "ok")


class TestE2EPhaseEnforcement(unittest.TestCase):
    """E2E: Phase transitions are enforced."""

    @classmethod
    def setUpClass(cls):
        from keyper import create_keyper_app
        from backend import create_backend_app

        cls.BACKEND_PORT = 7300
        cls.KEYPER_PORTS = [7301, 7302]
        cls.backend_url = f"http://127.0.0.1:{cls.BACKEND_PORT}"
        keyper_urls = [f"http://127.0.0.1:{p}" for p in cls.KEYPER_PORTS]

        for i, port in enumerate(cls.KEYPER_PORTS):
            _start_flask(create_keyper_app(i + 1), port)
        _start_flask(create_backend_app(keyper_urls), cls.BACKEND_PORT)

        for url in keyper_urls:
            assert _wait_for(f"{url}/status")
        assert _wait_for(f"{cls.backend_url}/election/status")

    def test_01_vote_before_dkg_rejected(self):
        """Cannot vote before DKG is complete."""
        # Create election but skip DKG
        requests.post(f"{self.backend_url}/election/create", json={
            "n": 2, "t": 1, "num_candidates": 2, "budget": 1,
        }, timeout=30)
        # Try to vote — we're in 'setup' phase
        resp = requests.post(f"{self.backend_url}/election/vote", json={
            "ciphertexts": [{"c1": "1", "c2": "1"}, {"c1": "1", "c2": "1"}],
            "range_proofs": [[{"e": "1", "z": "1"}, {"e": "1", "z": "1"}],
                             [{"e": "1", "z": "1"}, {"e": "1", "z": "1"}]],
            "budget_proof": {"e": "1", "z": "1"},
        }, timeout=10)
        self.assertEqual(resp.status_code, 400)

    def test_02_dkg_in_wrong_phase_rejected(self):
        """Cannot run DKG again after it's already done."""
        # Do DKG first time
        requests.post(f"{self.backend_url}/election/dkg", timeout=60)
        # Now try DKG again — we're in 'voting' phase
        resp = requests.post(f"{self.backend_url}/election/dkg", timeout=10)
        self.assertEqual(resp.status_code, 400)

    def test_03_tally_empty_election_rejected(self):
        """Cannot tally with zero votes."""
        resp = requests.post(f"{self.backend_url}/election/tally", timeout=10)
        self.assertEqual(resp.status_code, 400)

    def test_04_no_result_before_tally(self):
        """Result endpoint returns 404 before tally."""
        resp = requests.get(f"{self.backend_url}/election/result", timeout=5)
        self.assertEqual(resp.status_code, 404)


class TestE2EReset(unittest.TestCase):
    """E2E: Election reset works correctly."""

    @classmethod
    def setUpClass(cls):
        from keyper import create_keyper_app
        from backend import create_backend_app

        cls.BACKEND_PORT = 7400
        cls.KEYPER_PORTS = [7401, 7402, 7403]
        cls.backend_url = f"http://127.0.0.1:{cls.BACKEND_PORT}"
        keyper_urls = [f"http://127.0.0.1:{p}" for p in cls.KEYPER_PORTS]

        for i, port in enumerate(cls.KEYPER_PORTS):
            _start_flask(create_keyper_app(i + 1), port)
        _start_flask(create_backend_app(keyper_urls), cls.BACKEND_PORT)

        for url in keyper_urls:
            assert _wait_for(f"{url}/status")
        assert _wait_for(f"{cls.backend_url}/election/status")

    def test_reset_after_full_election(self):
        """Run a full election, reset, run another with different parameters."""
        # First election
        requests.post(f"{self.backend_url}/election/create", json={
            "n": 3, "t": 1, "num_candidates": 2, "budget": 1,
            "candidate_names": ["A", "B"],
        }, timeout=30)
        requests.post(f"{self.backend_url}/election/dkg", timeout=60)
        _submit_vote_http(self.backend_url, [1, 0])
        _submit_vote_http(self.backend_url, [0, 1])
        resp = requests.post(f"{self.backend_url}/election/tally", timeout=60)
        self.assertEqual(resp.status_code, 200)
        r1 = resp.json()["results"]
        self.assertEqual(r1["A"], 1)
        self.assertEqual(r1["B"], 1)

        # Reset
        resp = requests.post(f"{self.backend_url}/election/reset", timeout=10)
        self.assertEqual(resp.status_code, 200)

        status = requests.get(f"{self.backend_url}/election/status", timeout=5).json()
        self.assertEqual(status["phase"], "idle")
        self.assertEqual(status["ballots_received"], 0)

        # Second election with different candidates
        requests.post(f"{self.backend_url}/election/create", json={
            "n": 3, "t": 1, "num_candidates": 3, "budget": 1,
            "candidate_names": ["X", "Y", "Z"],
        }, timeout=30)
        requests.post(f"{self.backend_url}/election/dkg", timeout=60)
        _submit_vote_http(self.backend_url, [0, 0, 1])
        _submit_vote_http(self.backend_url, [0, 0, 1])
        _submit_vote_http(self.backend_url, [1, 0, 0])
        resp = requests.post(f"{self.backend_url}/election/tally", timeout=60)
        self.assertEqual(resp.status_code, 200)
        r2 = resp.json()["results"]
        self.assertEqual(r2["X"], 1)
        self.assertEqual(r2["Y"], 0)
        self.assertEqual(r2["Z"], 2)


class TestE2ELargeElection(unittest.TestCase):
    """E2E: Larger election to stress test."""

    @classmethod
    def setUpClass(cls):
        from keyper import create_keyper_app
        from backend import create_backend_app

        cls.BACKEND_PORT = 7500
        cls.KEYPER_PORTS = [7501, 7502, 7503, 7504, 7505]
        cls.backend_url = f"http://127.0.0.1:{cls.BACKEND_PORT}"
        keyper_urls = [f"http://127.0.0.1:{p}" for p in cls.KEYPER_PORTS]

        for i, port in enumerate(cls.KEYPER_PORTS):
            _start_flask(create_keyper_app(i + 1), port)
        _start_flask(create_backend_app(keyper_urls), cls.BACKEND_PORT)

        for url in keyper_urls:
            assert _wait_for(f"{url}/status")
        assert _wait_for(f"{cls.backend_url}/election/status")

    def test_20_voters_5_candidates_B3(self):
        """20 voters, 5 candidates, B=3, n=5 keypers, t=2."""
        requests.post(f"{self.backend_url}/election/create", json={
            "n": 5, "t": 2, "num_candidates": 5, "budget": 3,
            "candidate_names": ["A", "B", "C", "D", "E"],
        }, timeout=30)
        resp = requests.post(f"{self.backend_url}/election/dkg", timeout=60)
        self.assertEqual(resp.status_code, 200)

        expected = [0] * 5
        for i in range(20):
            # Generate random valid ballot summing to 3
            votes = [0] * 5
            remaining = 3
            for j in range(4):
                v = random.randint(0, min(remaining, 3))
                votes[j] = v
                remaining -= v
            votes[4] = remaining
            for j in range(5):
                expected[j] += votes[j]

            result = _submit_vote_http(self.backend_url, votes)
            self.assertEqual(result["status"], "ok", f"Voter {i} failed: {result}")

        status = requests.get(f"{self.backend_url}/election/status", timeout=5).json()
        self.assertEqual(status["ballots_received"], 20)

        resp = requests.post(f"{self.backend_url}/election/tally", timeout=120)
        self.assertEqual(resp.status_code, 200)
        results = resp.json()["results"]
        candidate_names = ["A", "B", "C", "D", "E"]
        for j, name in enumerate(candidate_names):
            self.assertEqual(results[name], expected[j],
                             f"{name}: expected {expected[j]}, got {results[name]}")


class TestE2EBackendValidation(unittest.TestCase):
    """E2E: Backend input validation edge cases."""

    @classmethod
    def setUpClass(cls):
        from keyper import create_keyper_app
        from backend import create_backend_app

        cls.BACKEND_PORT = 7600
        cls.KEYPER_PORTS = [7601, 7602]
        cls.backend_url = f"http://127.0.0.1:{cls.BACKEND_PORT}"
        keyper_urls = [f"http://127.0.0.1:{p}" for p in cls.KEYPER_PORTS]

        for i, port in enumerate(cls.KEYPER_PORTS):
            _start_flask(create_keyper_app(i + 1), port)
        _start_flask(create_backend_app(keyper_urls), cls.BACKEND_PORT)

        for url in keyper_urls:
            assert _wait_for(f"{url}/status")
        assert _wait_for(f"{cls.backend_url}/election/status")

    def test_create_invalid_threshold(self):
        """t >= n is rejected."""
        resp = requests.post(f"{self.backend_url}/election/create", json={
            "n": 2, "t": 2, "num_candidates": 2, "budget": 1,
        }, timeout=10)
        self.assertEqual(resp.status_code, 400)

    def test_create_zero_candidates(self):
        """0 candidates is rejected."""
        resp = requests.post(f"{self.backend_url}/election/create", json={
            "n": 2, "t": 1, "num_candidates": 0, "budget": 1,
        }, timeout=10)
        self.assertEqual(resp.status_code, 400)

    def test_create_too_many_keypers(self):
        """Requesting more keypers than available URLs."""
        resp = requests.post(f"{self.backend_url}/election/create", json={
            "n": 10, "t": 5, "num_candidates": 2, "budget": 1,
        }, timeout=10)
        self.assertEqual(resp.status_code, 400)


# ======================================================================
#  Main runner
# ======================================================================

if __name__ == "__main__":
    # Use a text runner that writes to both stdout and a file
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])

    # Always run via normal unittest main for -v, -k, etc.
    unittest.main(module=__name__, verbosity=2)
