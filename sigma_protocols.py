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
    challenge = hash_sha256(seed)

    responce = value * challenge + random_value

    return SingleExponentProof(
        generator,
        pedersen_hash,
        commitment,
        responce
    )

