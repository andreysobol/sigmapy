from curve import *

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

    assert left1 == right1

    left2 = point_add(
        point_mul(proof.pedersen_hash_2, challenge),
        proof.commitment_2
    )
    right2 = point_mul(proof.generator_2, proof.responce)

    return (left1 == right1) and (left2 == right2)

proof = generate_single_exponent_equality_proof(
    42, G, H, 13
)

result = verify_single_exponent_equality_proof(
    proof
)

assert result == True