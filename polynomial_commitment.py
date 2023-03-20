from typing import List

from curve import *
from pedersen_commitment import *
from sigma_protocols import *

# P(x) = c_0 + x*c_1 + x^2*c_2 + ...
# c_i := coefficients[i]
class PolynomialCommitment:
    def __init__(
        self,
        generator_1: Point,
        generator_2: Point,
        coefficients: List[int], 
        random_values: List[int]
    ):
        self.commitments = []

        length = len(coefficients)
        assert(len(random_values) == length)

        for i in range(length):
            self.commitments.append(
                pedersen_commitment(generator_1, generator_2, coefficients[i], random_values[i])
            )


def generate_polynomial_commitment_proof(
    generator_2: Point,
    coefficients: List[int],
    random_values: List[int],
    point: int,
    inner_random_value: int
) -> tuple[SingleExponentProof, int]:
    length = len(coefficients)
    assert(len(random_values) == length)

    result = 0
    random_sum = 0
    point_pow = 1

    for i in range(length):
        result = (result + coefficients[i] * point_pow) % n
        random_sum = (random_sum + random_values[i] * point_pow) % n
        point_pow = (point_pow * point) % n

    proof = generate_single_exponent_proof(random_sum, generator_2, inner_random_value)

    return (proof, result)

def verify_polynomial_commitment_proof(
    generator_1: Point,
    generator_2: Point,
    point: int,
    value: int,
    poly_commitment: PolynomialCommitment,
    inner_proof: SingleExponentProof,
) -> bool:
    if inner_proof.generator != generator_2:
        return False
    
    if not verify_single_exponent_proof(inner_proof):
        return False
    
    length = len(poly_commitment.commitments)
    commitment_sum = None
    point_pow = 1

    for i in range(length):
        commitment_sum = point_add(commitment_sum, point_mul(poly_commitment.commitments[i], point_pow))
        point_pow = (point_pow * point) % n

    expected = point_mul(generator_1, value)

    if inner_proof.pedersen_hash != point_sub(commitment_sum, expected):
        return False
    
    return True