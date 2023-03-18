import unittest

from sigma_protocols import generate_single_exponent_proof, verify_single_exponent_proof
from curve import G

class TestSignleExponent(unittest.TestCase):

    def test_commitment(self):
        proof = generate_single_exponent_proof(42, G, 13)
        result = verify_single_exponent_proof(proof)
        assert result == True