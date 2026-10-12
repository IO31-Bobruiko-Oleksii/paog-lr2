import random
from dataclasses import dataclass

from rsa_core import extended_euclid, mod_inverse


def gcd(a, b):
    return extended_euclid(a, b)[0]


def is_valid_mask(r, n):
    return 2 <= r < n and gcd(r, n) == 1


def random_mask(n, rng=None):
    rng = rng or random.SystemRandom()
    while True:
        r = rng.randrange(2, n)
        if gcd(r, n) == 1:
            return r


def blind(h, r, public):
    e, n = public
    if not (0 <= h < n):
        raise ValueError("хеш має задовольняти умову 0 <= H < n")
    if not is_valid_mask(r, n):
        raise ValueError("множник маскування має задовольняти умови 2 <= r < n та НСД(r, n) = 1")
    return (h * pow(r, e, n)) % n


def blind_sign(h_masked, private):
    d, n = private
    if not (0 <= h_masked < n):
        raise ValueError("замаскований хеш має задовольняти умову 0 <= H' < n")
    return pow(h_masked, d, n)


def unblind(s_masked, r, n):
    if not is_valid_mask(r, n):
        raise ValueError("множник маскування має задовольняти умови 2 <= r < n та НСД(r, n) = 1")
    r_inv = mod_inverse(r, n)
    return (s_masked * r_inv) % n


@dataclass(frozen=True)
class MaskedHash:
    h: int
    r: int
    h_masked: int


def mask_hash(h, public, rng=None):
    n = public[1]
    r = random_mask(n, rng)
    return MaskedHash(h=h, r=r, h_masked=blind(h, r, public))


def check_masked_hash(h, r, h_masked, public):
    e, n = public
    if not (0 <= h < n) or not is_valid_mask(r, n):
        return False
    return blind(h, r, public) == h_masked
