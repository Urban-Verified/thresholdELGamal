"""
Distributed Key Generation using Feldman Verifiable Secret Sharing over BLS12-381 G2.

Implements the DKG protocol from the crypto protocol specification:
each keyper k generates a random secret s^(k), runs Feldman VSS to
distribute shares to all other keypers, and all keypers combine their
received shares to form the joint threshold key.

Protocol (all operations in G2 with generator P₂):
  Round 1: Each keyper generates secret polynomial, commitments γⱼ = cⱼ·P₂, and shares.
  Round 2: Each keyper verifies received shares against commitments using Feldman VSS:
           sᵢ·P₂ == Σⱼ (xᵢʲ mod q)·γⱼ
           Then computes combined secret share mskⱼ = Σₖ sⱼ^(k) mod q.

The master public key is mpk = Σₖ γ₀^(k) = msk·P₂.
"""

from .primitives import (
    G2, Z2, CURVE_ORDER,
    point_multiply, point_add, point_eq, is_identity,
    random_scalar,
)


class KeyperDKGState:
    """State machine for a single keyper's participation in Distributed Key Generation."""

    def __init__(self):
        self.keyper_id = None
        self.n = None
        self.t = None  # polynomial degree; need t+1 shares to reconstruct
        self.coefficients = None
        self.commitments = None  # list of G2 points: γⱼ = cⱼ·P₂
        self.shares_for_others = {}
        self.combined_share = None  # scalar: mskⱼ
        self.public_key_share = None  # G2 point: mskⱼ·P₂

    def round1(self, keyper_id, n, t):
        """DKG Round 1: Generate secret polynomial, commitments, and shares.

        The keyper chooses a random polynomial φ(x) = c₀ + c₁x + ... + cₜxᵗ
        over Z_q, computes Feldman commitments γⱼ = cⱼ·P₂ ∈ G₂, and evaluates
        shares φ(i) for all keyper indices i = 1..n.

        Returns (commitments, shares_dict) where:
          commitments: list of G2 points γⱼ = cⱼ·P₂ for j = 0..t
          shares_dict: {recipient_keyper_id: share_value (scalar)}
        """
        self.keyper_id = keyper_id
        self.n = n
        self.t = t

        # Random polynomial φ(x) = c₀ + c₁x + ... + cₜxᵗ over Z_q
        self.coefficients = [random_scalar() for _ in range(t + 1)]

        # Feldman commitments: γⱼ = cⱼ · P₂ (G2 points)
        self.commitments = [point_multiply(G2, c) for c in self.coefficients]

        # Shares for each keyper i: sᵢ = φ(i) mod q
        self.shares_for_others = {}
        for i in range(1, n + 1):
            val = 0
            x_power = 1  # i^j mod q, starting with i^0 = 1
            for j in range(t + 1):
                val = (val + self.coefficients[j] * x_power) % CURVE_ORDER
                x_power = (x_power * i) % CURVE_ORDER
            self.shares_for_others[i] = val

        return self.commitments, self.shares_for_others

    def round2(self, all_commitments, received_shares):
        """DKG Round 2: Verify received shares and compute combined secret share.

        all_commitments: {dealer_id: [γ₀, ..., γₜ]} (G2 points)
        received_shares: {dealer_id: share_value (scalar)}

        Verifies each share against the dealer's commitments using Feldman VSS:
          sᵢ · P₂ == Σⱼ (my_id^j mod q) · γⱼ

        If all verifications pass, computes:
          combined_share = Σₖ received_shares[k] mod q (scalar)
          public_key_share = combined_share · P₂ (G2 point)

        Returns (combined_share, public_key_share).
        Raises ValueError if any share verification fails.
        """
        my_id = self.keyper_id

        for dealer_id, share in received_shares.items():
            comms = all_commitments[dealer_id]

            # Verify: sᵢ · P₂ == Σⱼ (my_id^j mod q) · γⱼ
            expected = Z2
            x_power = 1  # my_id^j mod q, starting with my_id^0 = 1
            for j in range(len(comms)):
                expected = point_add(expected, point_multiply(comms[j], x_power))
                x_power = (x_power * my_id) % CURVE_ORDER

            actual = point_multiply(G2, share)
            if not point_eq(expected, actual):
                raise ValueError(
                    f"Keyper {my_id}: Feldman VSS verification failed for share from dealer {dealer_id}"
                )

        # Compute combined secret share: mskⱼ = Σₖ sⱼ^(k) mod q
        self.combined_share = sum(received_shares.values()) % CURVE_ORDER
        self.public_key_share = point_multiply(G2, self.combined_share)

        return self.combined_share, self.public_key_share

    def partial_decrypt(self, C1):
        """Compute partial decryption share: σⱼ = mskⱼ · C₁ (G2 point)."""
        if self.combined_share is None:
            raise RuntimeError("DKG not completed; cannot decrypt")
        return point_multiply(C1, self.combined_share)
