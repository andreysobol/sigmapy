# k is 0 to 2**n - 1

# we prove that
# k0*2**0 + k1*1**0 + k2*2**0 + ... + kn = k
# and we prove that
# k0, k1, k2 ... kn-1 are 0 or 1

import math
from functools import reduce
from typing import List

from boolean_proof import generate_boolean_proof, verify_boolean_proof
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
        generator_1: Point,
        generator_2: Point,
        main_commitment,
        boolean_proofs: List[SinglePedersenInnerProductProof],
        final_inner_proof: SingleExponentProof,
    ):
        self.generator_1 = generator_1
        self.generator_2 = generator_2
        self.main_commitment = main_commitment
        self.boolean_proofs = boolean_proofs
        self.final_inner_proof = final_inner_proof

def generate_range_proof(
    generator_1: Point,
    generator_2: Point,
    value: int,
    n: int,
    blinding_factor_for_value_commitment: int,
    blinding_factors: List[int],
    random_value_for_inner_proof: int,
) -> RangeProof:
    
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

    b_muls = [blinding_factors[4*i] * 2**i for i in range(power_of_two)]
    b_sum = reduce(lambda x,y: x+y, b_muls)

    inner_exponent = b_sum - blinding_factor_for_value_commitment

    inner_proof = generate_single_exponent_proof(
        inner_exponent,
        generator_2,
        random_value_for_inner_proof,
    )

    main_commitment = pedersen_commitment(
        generator_1,
        generator_2,
        value,
        blinding_factor_for_value_commitment
    )

    range_proof = RangeProof(
        generator_1,
        generator_2,
        main_commitment,
        boolean_proofs,
        inner_proof,
    )

    return range_proof

def verify_range_proof(
    proof: RangeProof,
    n: int,
) -> bool:
    power_of_two = get_power_of_two(n)

    if power_of_two != len(proof.boolean_proofs):
        return False
    
    if proof.generator_2 != proof.final_inner_proof.generator:
        return False

    if not verify_single_exponent_proof(
        proof.final_inner_proof,
    ):
        return False
    
    for i in range(power_of_two):
        if proof.boolean_proofs[i].generator_1 != proof.generator_1:
            return False
        
        if proof.boolean_proofs[i].generator_2 != proof.generator_2:
            return False

        if not verify_boolean_proof(
            proof.boolean_proofs[i],
        ):
            return False

    witness_bit_commitments = [proof.boolean_proofs[i].pedersen_commitment_b for i in range(power_of_two)]

    witness_bit_commitments_mul = [point_mul(witness_bit_commitments[i], 2**i) for i in range(power_of_two)]
    witness_bit_commitments_sum = reduce(point_add, witness_bit_commitments_mul)

    if point_sub(witness_bit_commitments_sum, proof.main_commitment) != proof.final_inner_proof.pedersen_hash:
        print("commitment check failed")
        return False

    return True