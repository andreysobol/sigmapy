from curve import G, H
from polynomial_commitment import PolynomialCommitment, generate_polynomial_commitment_proof, verify_polynomial_commitment_proof

import unittest

class TestPolinomialCommitment(unittest.TestCase):

    def test_polinomial_commitment(self):

        point = 54354453
        coeffs = [33234, 43434, 4343, 43455]
        rand_vals = [243, 234, 242, 343]

        poly_comm = PolynomialCommitment(G, H, coeffs, rand_vals)

        (proof, value) = generate_polynomial_commitment_proof(
            H,
            coeffs,
            rand_vals,
            point,
            434,
        )

        assert verify_polynomial_commitment_proof(
            G,
            H,
            point,
            value,
            poly_comm,
            proof
        )
