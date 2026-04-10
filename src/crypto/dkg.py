"""
Distributed Key Generation using Feldman Verifiable Secret Sharing.

Implements the DKG protocol from the crypto protocol specification:
each keyper k generates a random secret s^(k), runs Feldman VSS to
distribute shares to all other keypers, and all keypers combine their
received shares to form the joint threshold key.

Protocol:
  Round 1: Each keyper generates secret, polynomial, commitments, and shares.
  Round 2: Each keyper verifies received shares against commitments,
           computes combined secret share msk_j = sum_k s_j^(k).

The master public key is mpk = product_k gamma_0^(k) = g^msk.
"""

import secrets


class KeyperDKGState:
    """State machine for a single keyper's participation in Distributed Key Generation."""

    def __init__(self):
        self.keyper_id = None
        self.p = None
        self.q = None
        self.g = None
        self.n = None
        self.t = None  # polynomial degree; need t+1 shares to reconstruct
        self.coefficients = None
        self.commitments = None
        self.shares_for_others = {}
        self.combined_share = None
        self.public_key_share = None

    def round1(self, keyper_id, p, q, g, n, t):
        """DKG Round 1: Generate secret polynomial, commitments, and shares.

        The keyper chooses a random polynomial phi(x) = c_0 + c_1*x + ... + c_t*x^t
        over Z_q, computes Feldman commitments gamma_j = g^c_j mod p, and evaluates
        shares phi(i) for all keyper indices i = 1..n.

        Returns (commitments, shares_dict) where:
          commitments: list of g^c_j mod p for j = 0..t
          shares_dict: {recipient_keyper_id: share_value}
        """
        self.keyper_id = keyper_id
        self.p = p
        self.q = q
        self.g = g
        self.n = n
        self.t = t

        # Random polynomial phi(x) = c_0 + c_1*x + ... + c_t*x^t over Z_q
        self.coefficients = [secrets.randbelow(q - 1) + 1 for _ in range(t + 1)]

        # Feldman commitments: gamma_j = g^c_j mod p
        self.commitments = [pow(g, c, p) for c in self.coefficients]

        # Shares for each keyper i: s_i = phi(i) mod q
        # Evaluation points are keyper IDs: 1, 2, ..., n
        self.shares_for_others = {}
        for i in range(1, n + 1):
            val = 0
            x_power = 1  # i^j mod q, starting with i^0 = 1
            for j in range(t + 1):
                val = (val + self.coefficients[j] * x_power) % q
                x_power = (x_power * i) % q
            self.shares_for_others[i] = val

        return self.commitments, self.shares_for_others

    def round2(self, all_commitments, received_shares):
        """DKG Round 2: Verify received shares and compute combined secret share.

        all_commitments: {dealer_id: [gamma_0, ..., gamma_t]}
        received_shares: {dealer_id: share_value}  (share from dealer to this keyper)

        Verifies each share against the dealer's commitments using Feldman VSS:
          g^share == product(gamma_j^(my_id^j)) mod p

        If all verifications pass, computes:
          combined_share = sum of all received shares mod q
          public_key_share = g^combined_share mod p

        Returns (combined_share, public_key_share).
        Raises ValueError if any share verification fails.
        """
        my_id = self.keyper_id

        for dealer_id, share in received_shares.items():
            comms = all_commitments[dealer_id]

            # Verify: g^share == product(gamma_j^(my_id^j)) mod p
            expected = 1
            x_power = 1  # my_id^j, starting with my_id^0 = 1
            for j in range(len(comms)):
                expected = (expected * pow(comms[j], x_power, self.p)) % self.p
                x_power = (x_power * my_id) % self.q

            actual = pow(self.g, share, self.p)
            if expected != actual:
                raise ValueError(
                    f"Keyper {my_id}: Feldman VSS verification failed for share from dealer {dealer_id}"
                )

        # Compute combined secret share: msk_j = sum_k s_j^(k) mod q
        self.combined_share = sum(received_shares.values()) % self.q
        self.public_key_share = pow(self.g, self.combined_share, self.p)

        return self.combined_share, self.public_key_share

    def partial_decrypt(self, c1):
        """Compute partial decryption share: sigma_j = c1^msk_j mod p."""
        if self.combined_share is None:
            raise RuntimeError("DKG not completed; cannot decrypt")
        return pow(c1, self.combined_share, self.p)
