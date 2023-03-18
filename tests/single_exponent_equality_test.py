import unittest

from sigma_protocols import generate_single_exponent_equality_proof, verify_single_exponent_equality_proof
from curve import G, H

class TestSignleExponentEquality(unittest.TestCase):

    def test_commitment(self):
        proof = generate_single_exponent_equality_proof(
            42, G, H, 13
        )

        result = verify_single_exponent_equality_proof(
            proof
        )

        assert result == True