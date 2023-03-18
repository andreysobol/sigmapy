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

    print(challenge)

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
    print(challenge)
    left = point_sub(
        point_mul(proof.generator, proof.responce),
        point_mul(proof.pedersen_hash, challenge)
    )
    right = proof.commitment
    return left == right

proof = generate_single_exponent_proof(42, G, 13)

result = verify_single_exponent_proof(proof)
assert result == True