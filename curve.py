from typing import Tuple, Optional, Any
import hashlib
import binascii

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

Point = Tuple[int, int]

def is_infinite(P: Optional[Point]) -> bool:
    return P is None

def x(P: Point) -> int:
    assert not is_infinite(P)
    return P[0]

def y(P: Point) -> int:
    assert not is_infinite(P)
    return P[1]

def bytes_from_point(P: Point) -> bytes:
    return bytes_from_int(x(P))

def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="big")

def hash_sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def lift_x(x: int) -> Optional[Point]:
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return (x, y if y & 1 == 0 else p-y)

def calculate_generator_from_seed(seed: bytes) -> Point:
    sha = hash_sha256(seed)
    possible_x = int_from_bytes(sha)
    possible_point = lift_x(possible_x)
    if possible_point is None:
        seed = sha
        return calculate_generator_from_seed(seed)
    else:
        return possible_point

H = calculate_generator_from_seed(bytes_from_point(G))

assert H != G
assert H == (33552425859647397784783932218402990106808296067309630743615811230076224837562, 20913732046133990540589283421767849705011106974950605707443476096511212835430)