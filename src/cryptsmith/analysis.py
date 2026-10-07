"""Statistical analysis: entropy, frequency, english scoring."""
import math
from collections import Counter

ENGLISH_FREQ = {
    "a": 0.08167, "b": 0.01492, "c": 0.02782, "d": 0.04253, "e": 0.12702,
    "f": 0.02228, "g": 0.02015, "h": 0.06094, "i": 0.06966, "j": 0.00153,
    "k": 0.00772, "l": 0.04025, "m": 0.02406, "n": 0.06749, "o": 0.07507,
    "p": 0.01929, "q": 0.00095, "r": 0.05987, "s": 0.06327, "t": 0.09056,
    "u": 0.02758, "v": 0.00978, "w": 0.02360, "x": 0.00150, "y": 0.01974,
    "z": 0.00074,
}


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte. ~8.0 is random, ~4.7 is english text."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def frequency_analysis(text: str) -> list[tuple[str, float]]:
    """Letter frequencies sorted most common first."""
    letters = [c.lower() for c in text if c.isalpha()]
    if not letters:
        return []
    counts = Counter(letters)
    total = len(letters)
    return sorted(((ch, n / total) for ch, n in counts.items()), key=lambda x: -x[1])


def index_of_coincidence(text: str) -> float:
    """IoC ~0.065 for english, ~0.038 for random. Useful to spot polyalphabetic ciphers."""
    letters = [c.lower() for c in text if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def chi_squared(text: str) -> float:
    """Chi squared distance from english letter frequencies. Lower is more english."""
    letters = [c.lower() for c in text if c.isalpha()]
    n = len(letters)
    if n == 0:
        return float("inf")
    counts = Counter(letters)
    score = 0.0
    for ch, expected in ENGLISH_FREQ.items():
        observed = counts.get(ch, 0)
        exp = n * expected
        score += ((observed - exp) ** 2) / exp if exp else 0
    return score


def english_score(text: str) -> float:
    """Higher is better. Combines chi squared with a bonus for common words and spaces."""
    if not text:
        return float("-inf")
    try:
        t = text if isinstance(text, str) else text.decode("latin1")
    except Exception:
        return float("-inf")
    chi = chi_squared(t)
    words = t.lower().split()
    common = sum(1 for w in words if w.strip(".,!?;:\"'()") in {
        "the", "and", "for", "with", "this", "that", "from", "have", "flag",
        "key", "secret", "enroll", "hello", "server", "client",
    })
    space_bonus = t.count(" ") * 2
    printable_ratio = sum(1 for c in t if 32 <= ord(c) < 127 or c in "\n\r\t") / max(len(t), 1)
    if printable_ratio < 0.9:
        return float("-inf")
    return space_bonus + common * 25 - chi / 10
