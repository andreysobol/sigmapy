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
        gen_1: Point,
        gen_1_x: Point,
        gen_2: Point,
        gen_2_x: Point,
        commitment_1: Point,
        commitment_2: Point,
        response: int,
    ):
        self.generator_1 = gen_1
        self.generator_2 = gen_2
        self.pedersen_hash_1 = gen_1_x
        self.pedersen_hash_2 = gen_2_x
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
