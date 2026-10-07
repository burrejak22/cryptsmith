"""Classical ciphers: caesar, vigenere, atbash, affine."""
from .analysis import english_score


def _shift_char(c: str, shift: int) -> str:
    if "a" <= c <= "z":
        return chr((ord(c) - 97 + shift) % 26 + 97)
    if "A" <= c <= "Z":
        return chr((ord(c) - 65 + shift) % 26 + 65)
    return c


def caesar_decrypt(text: str, shift: int) -> str:
    return "".join(_shift_char(c, -shift) for c in text)


def caesar_encrypt(text: str, shift: int) -> str:
    return "".join(_shift_char(c, shift) for c in text)


def caesar_bruteforce(text: str, top: int = 3) -> list[tuple[int, str, float]]:
    """Try all 26 shifts, return the top scoring (shift, plaintext, score)."""
    scored = [(s, caesar_decrypt(text, s), english_score(caesar_decrypt(text, s))) for s in range(26)]
    scored.sort(key=lambda x: -x[2])
    return scored[:top]


def atbash(text: str) -> str:
    def flip(c: str) -> str:
        if "a" <= c <= "z":
            return chr(122 - (ord(c) - 97))
        if "A" <= c <= "Z":
            return chr(90 - (ord(c) - 65))
        return c
    return "".join(flip(c) for c in text)


def vigenere_decrypt(text: str, key: str) -> str:
    key = key.lower()
    out = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 97
            out.append(_shift_char(c, -shift))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


def vigenere_encrypt(text: str, key: str) -> str:
    key = key.lower()
    out = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 97
            out.append(_shift_char(c, shift))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


def affine_decrypt(text: str, a: int, b: int) -> str | None:
    from math import gcd
    if gcd(a, 26) != 1:
        return None
    a_inv = pow(a, -1, 26)
    def dec(c: str) -> str:
        if "a" <= c <= "z":
            return chr((a_inv * (ord(c) - 97 - b)) % 26 + 97)
        if "A" <= c <= "Z":
            return chr((a_inv * (ord(c) - 65 - b)) % 26 + 65)
        return c
    return "".join(dec(c) for c in text)


def affine_bruteforce(text: str, top: int = 5) -> list[tuple[int, int, str, float]]:
    """Try all valid (a, b) pairs, return top scoring."""
    from math import gcd
    results = []
    for a in range(1, 26):
        if gcd(a, 26) != 1:
            continue
        for b in range(26):
            pt = affine_decrypt(text, a, b)
            results.append((a, b, pt, english_score(pt)))
    results.sort(key=lambda x: -x[3])
    return results[:top]
