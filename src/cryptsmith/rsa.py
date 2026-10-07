"""RSA attacks: Wiener, Hastad broadcast, common modulus, small exponent."""
import math


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % m


def int_nthroot(x: int, n: int) -> tuple[int, bool]:
    """Integer nth root. Returns (root, exact)."""
    if x < 0:
        raise ValueError("negative")
    if x == 0:
        return (0, True)
    bits = x.bit_length()
    high = 1 << ((bits + n - 1) // n + 1)
    low = 0
    while low < high:
        mid = (low + high) // 2
        p = mid ** n
        if p == x:
            return (mid, True)
        if p < x:
            low = mid + 1
        else:
            high = mid
    return (low - 1, (low - 1) ** n == x)


def _continued_fraction(num: int, den: int) -> list[int]:
    cf = []
    while den:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    return cf


def _convergents(cf: list[int]):
    convs = []
    for i in range(len(cf)):
        num, den = cf[i], 1
        for j in range(i - 1, -1, -1):
            num, den = den + num * cf[j], num
        convs.append((den, num))  # (k, d) style: returns denominator, numerator
    return convs


def wiener_attack(n: int, e: int) -> int | None:
    """Recover d when d < n^0.25 / 3 via Wiener's continued fraction attack."""
    cf = _continued_fraction(e, n)
    for d, k in _convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        t = math.isqrt(disc)
        if t * t != disc:
            continue
        if (s + t) % 2 == 0:
            return d
    return None


def hastad_broadcast(ns: list[int], e: int, cts: list[int]) -> int | None:
    """Hastad broadcast attack: same m, small e, e+ ciphertexts under different moduli."""
    if len(ns) < e or len(cts) < e:
        return None
    crt_val = _crt(cts[:e], ns[:e])
    m, exact = int_nthroot(crt_val, e)
    return m if exact else None


def _crt(remainders: list[int], moduli: list[int]) -> int:
    m_prod = 1
    for m in moduli:
        m_prod *= m
    result = 0
    for r, m in zip(remainders, moduli):
        p = m_prod // m
        result += r * modinv(p, m) * p
    return result % m_prod


def common_modulus(n: int, e1: int, e2: int, c1: int, c2: int) -> int | None:
    """Recover m when the same m was encrypted under the same n with coprime exponents."""
    g, a, b = egcd(e1, e2)
    if g != 1:
        return None
    if a < 0:
        c1 = modinv(c1, n)
        a = -a
    if b < 0:
        c2 = modinv(c2, n)
        b = -b
    return (pow(c1, a, n) * pow(c2, b, n)) % n


def small_exponent_decrypt(n: int, e: int, c: int) -> int | None:
    """Decrypt when m^e < n (no modular wraparound happened)."""
    m, exact = int_nthroot(c, e)
    return m if exact and pow(m, e, n) == c else None


def int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")
