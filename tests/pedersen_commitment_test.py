from curve import G, H, point_mul, point_sub, lift_x, x
from pedersen_commitment import pedersen_commitment

import unittest

class TestPedersenCommitment(unittest.TestCase):

    def test_commitment(self):
        generator_1 = G
        generator_2 = H
        
        value = 42
        blinding_factor = 13
        commitment = pedersen_commitment(
            generator_1,
            generator_2,
            value,
            blinding_factor
        )

        # Check that the commitment is a point on the curve
        self.assertTrue(lift_x(x(commitment)) is not None)

        # Check that the commitment is not the generator point
        self.assertNotEqual(commitment, G)

        # Check that the commitment is not the hash point
        self.assertNotEqual(commitment, H)

        # Check that the commitment can be opened with the blinding factor
        value_point = point_sub(commitment, point_mul(H, blinding_factor))
        self.assertEqual(value_point, point_mul(G, value))