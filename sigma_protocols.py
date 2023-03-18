from curve import *
from pedersen_commitment import *

class SingleExponentProof:
    def __init__(
        self,
        gen: Point,
        gen_x: Point,
        commitment: Point,
        response: int,
    ):
        self.generator = gen
        self.pedersen_hash = gen_x
        self.commitment = commitment
        self.responce = response

def generate_single_exponent_proof(
    value: int,
    generator: Point,
    random_value: int,
) -> SingleExponentProof:
    pedersen_hash = point_mul(generator, value)
    commitment = point_mul(generator, random_value)

    seed = bytes_from_point(pedersen_hash) + bytes_from_point(commitment)
    challenge_bytes = hash_sha256(seed)
    challenge = int_from_bytes(challenge_bytes) % n

    responce = (value * challenge + random_value) % n

    return SingleExponentProof(
        generator,
        pedersen_hash,
        commitment,
        responce
    )

def verify_single_exponent_proof(
    proof: SingleExponentProof,
) -> bool:
    seed = bytes_from_point(proof.pedersen_hash) + bytes_from_point(proof.commitment)
    challenge_bytes = hash_sha256(seed)
    challenge = int_from_bytes(challenge_bytes) % n

    left = point_add(
        point_mul(proof.pedersen_hash, challenge),
        proof.commitment
    )
    right = point_mul(proof.generator, proof.responce) 

    return left == right

class SingleExponentEqualityProof:
    def __init__(
        self,
        generator_1: Point,
        generator_2: Point,
        pedersen_hash_1: Point,
        pedersen_hash_2: Point,
        commitment_1: Point,
        commitment_2: Point,
        response: int,
    ):
        self.generator_1 = generator_1
        self.generator_2 = generator_2
        self.pedersen_hash_1 = pedersen_hash_1
        self.pedersen_hash_2 = pedersen_hash_2
        self.commitment_1 = commitment_1
        self.commitment_2 = commitment_2
        self.responce = response

def generate_single_exponent_equality_proof(
    value: int,
    generator_1: Point,
    generator_2: Point,
    random_value: int,
) -> SingleExponentEqualityProof:
    pedersen_hash_1 = point_mul(generator_1, value)
    pedersen_hash_2 = point_mul(generator_2, value)

    commitment_1 = point_mul(generator_1, random_value)
    commitment_2 = point_mul(generator_2, random_value)

    seed = bytes_from_point(pedersen_hash_1) + bytes_from_point(pedersen_hash_2) + bytes_from_point(commitment_1) + bytes_from_point(commitment_2)
    challenge_bytes = hash_sha256(seed)
    challenge = int_from_bytes(challenge_bytes) % n

    responce = (value * challenge + random_value) % n

    return SingleExponentEqualityProof(
        generator_1,
        generator_2,
        pedersen_hash_1,
        pedersen_hash_2,
        commitment_1,
        commitment_2,
        responce
    )

def verify_single_exponent_equality_proof(
    proof: SingleExponentEqualityProof,
) -> SingleExponentEqualityProof:
    seed = bytes_from_point(proof.pedersen_hash_1) + bytes_from_point(proof.pedersen_hash_2) + bytes_from_point(proof.commitment_1) + bytes_from_point(proof.commitment_2)
    challenge_bytes = hash_sha256(seed)
    challenge = int_from_bytes(challenge_bytes) % n

    left1 = point_add(
        point_mul(proof.pedersen_hash_1, challenge),
        proof.commitment_1
    )
    right1 = point_mul(proof.generator_1, proof.responce)

    left2 = point_add(
        point_mul(proof.pedersen_hash_2, challenge),
        proof.commitment_2
    )
    right2 = point_mul(proof.generator_2, proof.responce)

    return (left1 == right1) and (left2 == right2)

# Prove that b / a = d / c
class SinglePedersenInnerProductProof:
    def __init__(
        self,
        gen_1: Point,
        gen_2: Point,
        comm_a: Point,
        comm_b: Point,
        comm_c: Point,
        comm_d: Point,
        commitment_1: Point,
        commitment_2: Point,
        response: int,
        inner_proof_1: SingleExponentProof,
        inner_proof_2: SingleExponentProof
    ):
        assert(inner_proof_1.generator == gen_2)
        assert(inner_proof_2.generator == gen_2)

        self.generator_1 = gen_1
        self.generator_2 = gen_2
        self.pedersen_commitment_a = comm_a
        self.pedersen_commitment_b = comm_b
        self.pedersen_commitment_c = comm_c
        self.pedersen_commitment_d = comm_d
        self.commitment_1 = commitment_1
        self.commitment_2 = commitment_2
        self.responce = response
        self.inner_proof_1 = inner_proof_1
        self.inner_proof_2 = inner_proof_2

def generate_single_pedersen_inner_product_proof(
    generator_1: Point,
    generator_2: Point,
    a: int,
    b: int,
    c: int,
    d: int,
    r1: int,
    r2: int,
    r3: int,
    r4: int,
    random_value: int,
    inner_random_value_1: int,
    inner_random_value_2: int,
) -> SinglePedersenInnerProductProof:
    pedersen_comm_a = pedersen_commitment(generator_1, generator_2, a, r1)
    pedersen_comm_b = pedersen_commitment(generator_1, generator_2, b, r2)
    pedersen_comm_c = pedersen_commitment(generator_1, generator_2, c, r3)
    pedersen_comm_d = pedersen_commitment(generator_1, generator_2, d, r4)

    commitment_1 = point_mul(G, a * random_value)
    commitment_2 = point_mul(G, c * random_value)

    seed = bytes_from_point(pedersen_comm_a) + bytes_from_point(pedersen_comm_b) 
    seed += bytes_from_point(pedersen_comm_c) + bytes_from_point(pedersen_comm_d)
    seed += bytes_from_point(commitment_1) + bytes_from_point(commitment_2)
    
    challenge_bytes = hash_sha256(seed)
    challenge = int_from_bytes(challenge_bytes) % n

    value = (pow(a, n-2, n) * b) % n
    value_2 = (pow(c, n-2, n) * d) % n
    assert(value == value_2)

    responce = (value * challenge + random_value) % n

    inner_exponent_1 = (responce * r1 - challenge * r2) % n
    inner_exponent_2 = (responce * r3 - challenge * r4) % n

    inner_proof_1 = generate_single_exponent_proof(inner_exponent_1, H, inner_random_value_1)
    inner_proof_2 = generate_single_exponent_proof(inner_exponent_2, H, inner_random_value_2)


    return SinglePedersenInnerProductProof(
        generator_1,
        generator_2,
        pedersen_comm_a,
        pedersen_comm_b,
        pedersen_comm_c,
        pedersen_comm_d,
        commitment_1,
        commitment_2,
        responce,
        inner_proof_1,
        inner_proof_2
    )

def verify_single_pedersen_inner_product_proof(
    proof: SinglePedersenInnerProductProof
) -> bool:
    
    if proof.inner_proof_1.generator != proof.generator_2:
        return False

    result_single_exponent1 = verify_single_exponent_proof(proof.inner_proof_1)
    if not result_single_exponent1:
        return False

    if proof.inner_proof_2.generator != proof.generator_2:
        return False

    result_single_exponent2 = verify_single_exponent_proof(proof.inner_proof_2)
    if not result_single_exponent2:
        return False

    seed = bytes_from_point(proof.pedersen_commitment_a) + bytes_from_point(proof.pedersen_commitment_b) 
    seed += bytes_from_point(proof.pedersen_commitment_c) + bytes_from_point(proof.pedersen_commitment_d)
    seed += bytes_from_point(proof.commitment_1) + bytes_from_point(proof.commitment_2)

    challenge_bytes = hash_sha256(seed)
    challenge = int_from_bytes(challenge_bytes) % n

    # pedersen_comm_a * responce = pedersen_comm_b * challenge + commitment_1 + inner_pedersen_hash_1
    # pedersen_comm_c * responce = pedersen_comm_d * challenge + commitment_2 + inner_pedersen_hash_2

    left1 = point_mul(proof.pedersen_commitment_a, proof.responce)
    right1 = point_add(
        point_add(
            point_mul(proof.pedersen_commitment_b, challenge),
            proof.commitment_1
        ),
        proof.inner_proof_1.pedersen_hash
    )

    if left1 != right1:
        return False

    left2 = point_mul(proof.pedersen_commitment_c, proof.responce)
    right2 = point_add(
        point_add(
            point_mul(proof.pedersen_commitment_d, challenge),
            proof.commitment_2
        ),
        proof.inner_proof_2.pedersen_hash
    )

    if left2 != right2:
        return False
    
    return True

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

print(verify_single_pedersen_inner_product_proof(proof))

print(proof)

assert(verify_single_pedersen_inner_product_proof(proof))