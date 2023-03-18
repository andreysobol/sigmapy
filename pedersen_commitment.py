from curve import G, H, Point, point_mul, point_add

def pedersen_commitment(
        generator_1: Point,
        generator_2: Point,
        value: int,
        blinding_factor: int
    ) -> Point:
    # Compute the commitment
    commitment = point_add(point_mul(generator_1, value), point_mul(generator_2, blinding_factor))
    return commitment