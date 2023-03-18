from sigma_protocols import *

def generate_boolean_proof(
    value: int,
    generator_1: Point,
    generator_2: Point,
    random_value: int,
    outer_random_value_1: int,
    inner_random_value_1: int,
    inner_random_value_2: int,
) -> SinglePedersenInnerProductProof:
    return generate_single_pedersen_inner_product_proof(
        generator_1,
        generator_2,
        1,
        value,
        1 - value,
        0,
        0,
        random_value,
        n - (random_value % n),
        0,
        outer_random_value_1,
        inner_random_value_1,
        inner_random_value_2
    )

def verify_boolean_proof(
    proof: SinglePedersenInnerProductProof
) -> bool:
    
    # Check that a == 1 and r1 == 0
    if proof.pedersen_commitment_a != proof.generator_1:
        return False
    
    # Check that d == 0 and r4 == 0
    if proof.pedersen_commitment_d != None:
        return False
    
    # Check that c == 1 - b and r2 == -r3
    if point_add(proof.pedersen_commitment_b, proof.pedersen_commitment_c) != proof.generator_1:
        return False

    return verify_single_pedersen_inner_product_proof(proof)