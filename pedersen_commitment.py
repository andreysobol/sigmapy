from curve import G, H, Point, point_mul, point_add

def pedersen_commitment(value: int, blinding_factor: int) -> Point:
    # Compute the commitment
    commitment = point_add(point_mul(G, value), point_mul(H, blinding_factor))
    return commitment