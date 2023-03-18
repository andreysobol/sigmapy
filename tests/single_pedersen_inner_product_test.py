import unittest

from sigma_protocols import generate_single_pedersen_inner_product_proof, verify_single_pedersen_inner_product_proof
from curve import G, H

class TestSinglePedersenInnerProduct(unittest.TestCase):

    def test_commitment(self):

        # 546 / 13 = 42 / 1

        proof = generate_single_pedersen_inner_product_proof(
            G,
            H,
            13,
            546,
            1,
            42,
            10, # random value for pedersen commitment
            20, # random value for pedersen commitment
            30, # random value for pedersen commitment
            40, # random value for pedersen commitment
            1234, # random value for outer proof
            100, # random value for inner proof 1
            200, # random value for inner proof 2
        )

        assert(verify_single_pedersen_inner_product_proof(proof))