from curve import G, H, Point, point_mul, point_add, point_sub, lift_x, x

def pedersen_commitment(value: int, blinding_factor: int) -> Point:
    # Compute the commitment
    commitment = point_add(point_mul(G, value), point_mul(H, blinding_factor))
    return commitment

import unittest
from curve import G, H, Point, point_mul, point_add
from pedersen_commitment import pedersen_commitment

class TestPedersenCommitment(unittest.TestCase):

    def test_commitment(self):
        #from curve import point_sub
        
        value = 42
        blinding_factor = 13
        commitment = pedersen_commitment(value, blinding_factor)

        # Check that the commitment is a point on the curve
        self.assertTrue(lift_x(x(commitment)) is not None)

        # Check that the commitment is not the generator point
        self.assertNotEqual(commitment, G)

        # Check that the commitment is not the hash point
        self.assertNotEqual(commitment, H)

        # Check that the commitment can be opened with the blinding factor
        value_point = point_sub(commitment, point_mul(H, blinding_factor))
        self.assertEqual(value_point, point_mul(G, value))

if __name__ == '__main__':
    unittest.main()