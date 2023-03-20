# k is 0 to 2**n - 1

# we prove that
# k0*2**0 + k1*1**0 + k2*2**0 + ... + kn = k
# and we prove that
# k0, k1, k2 ... kn-1 are 0 or 1

import math
from itertools import reduce
from typing import List

from boolean_proof import generate_boolean_proof
from curve import G, H, Point, point_mul, point_add
from pedersen_commitment import pedersen_commitment
from sigma_protocols import *

def is_power_of_two(n):
    return (n != 0 and math.log2(n).is_integer())

def get_power_of_two(n):
    assert is_power_of_two(n)
    return int(math.log2(n))

def get_bit(n, i):
    """Returns the value of the i-th bit of n"""
    return (n >> i) & 1

class RangeProof:
    def __init__(
        self,
        main_commitment,
        witness_bit_commitments: List[Point],
        boolean_proofs: List[SinglePedersenInnerProductProof],
        final_inner_proof: SingleExponentProof,
    ):
        self.main_commitment = main_commitment
        self.witness_bit_commitments = witness_bit_commitments
        self.boolean_proofs = boolean_proofs
        self.final_inner_proof = final_inner_proof

def range_proof(
    generator_1: Point,
    generator_2: Point,
    value: int,
    n: int,
    value_commitment: Point,
    blinding_factor_for_value_commitment: int,
    blinding_factors: List[int]
) -> bool:
    
    assert value < n
    
    power_of_two = get_power_of_two(n)
    value_bits = [get_bit(value, i) for i in range(power_of_two)]

    assert len(blinding_factors) == power_of_two * 4

    boolean_proofs = [generate_boolean_proof(
        value_bits[i],
        generator_1,
        generator_2,
        blinding_factors[4*i],
        blinding_factors[4*i+1],
        blinding_factors[4*i+2],
        blinding_factors[4*i+3],
    ) for i in range(power_of_two)]

    coeffs = value_bits

    b_muls = [blinding_factors[4*i+1] * 2**i for i in range(power_of_two)]
    b_sum = reduce(lambda x,y: x+y, b_muls, 0)

    """
    pedersen_commitments = [pedersen_commitment(
        G,
        H,
        value_bits[i],
        12345,
    ) for i in range(power_of_two)]
    """