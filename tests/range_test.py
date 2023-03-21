import unittest

from curve import G, H
from range_proof import generate_range_proof, verify_range_proof

class TestRange(unittest.TestCase):

    def test_range_proof(self):

        # blinding factors - from 1 .. 40
        blinding_factors = [i for i in range(1, 41)]

        range_proof = generate_range_proof(
            G,
            H,
            641,
            1024,
            12345,
            blinding_factors,
            456
        )

        assert(verify_range_proof(
            range_proof,
            1024
        ))