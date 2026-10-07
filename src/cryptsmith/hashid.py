"""Identify hash algorithms by digest length and charset."""
import re

_HASHES = [
    (32, "md5", "md4"),
    (40, "sha1", "ripemd160"),
    (56, "sha224"),
    (64, "sha256", "sha3_256", "blake2s"),
    (96, "sha384", "sha3_384"),
    (128, "sha512", "sha3_512", "blake2b", "whirlpool"),
]


def identify(digest: str) -> list[str]:
    """Return likely hash names for a hex digest string."""
    d = digest.strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", d):
        return []
    for length, *names in _HASHES:
        if len(d) == length:
            return list(names)
    return []
