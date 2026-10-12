import random
from dataclasses import dataclass


def extended_euclid(a, b):
    r_prev, r_cur = a, b
    x_prev, x_cur = 1, 0
    y_prev, y_cur = 0, 1
    while r_cur != 0:
        q = r_prev // r_cur
        r_prev, r_cur = r_cur, r_prev - q * r_cur
        x_prev, x_cur = x_cur, x_prev - q * x_cur
        y_prev, y_cur = y_cur, y_prev - q * y_cur
    return r_prev, x_prev, y_prev


def mod_inverse(e, phi):
    g, x, _ = extended_euclid(e, phi)
    if g != 1:
        raise ValueError("e and phi(n) are not coprime: inverse does not exist")
    return x % phi

_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def is_prime(n, rounds=24, rng=None):
    rng = rng or random.SystemRandom()
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits, rng=None):
    rng = rng or random.SystemRandom()
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(candidate, rng=rng):
            return candidate

@dataclass(frozen=True)
class RSAKeyPair:
    p: int
    q: int
    n: int
    phi: int
    e: int
    d: int

    @property
    def public(self):
        return (self.e, self.n)

    @property
    def private(self):
        return (self.d, self.n)


def keypair_from_primes(p, q, e):
    if p == q:
        raise ValueError("p and q must be different")
    n = p * q
    phi = (p - 1) * (q - 1)
    if not (1 < e < phi) or e % 2 == 0:
        raise ValueError("e must be odd and satisfy 1 < e < phi(n)")
    d = mod_inverse(e, phi)
    return RSAKeyPair(p=p, q=q, n=n, phi=phi, e=e, d=d)


def _choose_e(phi, rng):
    if 65537 < phi and extended_euclid(65537, phi)[0] == 1:
        return 65537
    while True:
        e = rng.randrange(3, phi, 2)
        if extended_euclid(e, phi)[0] == 1:
            return e


def generate_keypair(prime_bits=64, rng=None):
    if prime_bits < 8:
        raise ValueError("prime_bits must be at least 8")
    rng = rng or random.SystemRandom()
    while True:
        p = generate_prime(prime_bits, rng)
        q = generate_prime(prime_bits, rng)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        e = _choose_e(phi, rng)
        return keypair_from_primes(p, q, e)

def encrypt_int(m, public):
    e, n = public
    if not (0 <= m < n):
        raise ValueError("message must satisfy 0 <= m < n")
    return pow(m, e, n)


def decrypt_int(c, private):
    d, n = private
    return pow(c, d, n)


def encrypt_text(text, public):
    return [encrypt_int(ord(ch), public) for ch in text]


def decrypt_text(blocks, private):
    chars = []
    for c in blocks:
        value = decrypt_int(c, private)
        if value > 0x10FFFF:
            raise ValueError("decrypted block is not a valid character")
        chars.append(chr(value))
    return "".join(chars)

def square_hash(text, n):
    h = 0
    for ch in text:
        h = pow(h + ord(ch), 2, n)
    return h


def sign(text, private):
    d, n = private
    return pow(square_hash(text, n), d, n)


def verify_detailed(text, signature, public):
    e, n = public
    h = square_hash(text, n)
    hc = pow(signature, e, n) if 0 <= signature < n else None
    return h, hc, (hc is not None and h == hc)


def verify(text, signature, public):
    return verify_detailed(text, signature, public)[2]
