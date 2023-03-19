import unittest

from boolean_proof import generate_boolean_proof, verify_boolean_proof
from curve import G, H

class TestBoolean(unittest.TestCase):

    def test_commitment(self):

        proof = generate_boolean_proof(
            0,
            G,
            H,
            12345,
            123,
            456,
            789,
        )

        assert(verify_boolean_proof(proof))

        proof = generate_boolean_proof(
            1,
            G,
            H,
            1,
            2,
            3,
            4,
        )

        assert(verify_boolean_proof(proof))

        self.assertRaises(TypeError, generate_boolean_proof(
            3,
            G,
            H,
            4,
            7,
            8,
            9,
        ))