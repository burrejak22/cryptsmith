"""XOR cryptanalysis: single byte bruteforce and repeating key break."""
from .analysis import english_score


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def single_byte_xor_break(data: bytes, top: int = 5) -> list[tuple[int, bytes, float]]:
    """Bruteforce all 256 single byte keys, return top scoring (key, plaintext, score)."""
    results = []
    for key in range(256):
        pt = bytes(b ^ key for b in data)
        results.append((key, pt, english_score(pt.decode("latin1"))))
    results.sort(key=lambda x: -x[2])
    return results[:top]


def hamming_distance(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_keysize(data: bytes, max_keysize: int = 40, top: int = 3) -> list[tuple[int, float]]:
    """Guess repeating xor keysize via normalized hamming distance. Lower is better."""
    guesses = []
    for ks in range(2, min(max_keysize + 1, len(data) // 8 + 1)):
        nblocks = min(8, len(data) // ks)
        blocks = [data[i * ks:(i + 1) * ks] for i in range(nblocks)]
        dists = [hamming_distance(blocks[i], blocks[i + 1]) / ks for i in range(nblocks - 1)]
        guesses.append((ks, sum(dists) / len(dists)))
    guesses.sort(key=lambda x: x[1])
    return guesses[:top]


def _refine_key(data: bytes, key: bytes) -> tuple[bytes, float]:
    """Hill climb each key byte against the full plaintext english score."""
    best = bytearray(key)
    best_score = english_score(xor_bytes(data, bytes(best)).decode("latin1"))
    improved = True
    while improved:
        improved = False
        for i in range(len(best)):
            for b in range(256):
                if b == best[i]:
                    continue
                cand = bytearray(best)
                cand[i] = b
                s = english_score(xor_bytes(data, bytes(cand)).decode("latin1"))
                if s > best_score:
                    best, best_score = cand, s
                    improved = True
    return bytes(best), best_score


def _partial_score(data: bytes, key: bytes, keysize: int) -> float:
    """Score text decrypted with a partial key (first len(key) bytes of each keysize block)."""
    m = len(key)
    dec = bytearray()
    for t in range(len(data)):
        if t % keysize < m:
            dec.append(data[t] ^ key[t % keysize])
    if not dec:
        return float("-inf")
    return english_score(bytes(dec).decode("latin1"))


def _beam_search_key(data: bytes, keysize: int, width: int = 50, per_block: int = 8) -> bytes:
    """Beam search over per-block key candidates, scored on progressively decrypted text."""
    cands = [
        [k for k, _, _ in single_byte_xor_break(data[i::keysize], top=per_block)]
        for i in range(keysize)
    ]
    beam: list[bytes] = [b""]
    for i in range(keysize):
        expanded = []
        for partial in beam:
            for b in cands[i]:
                full = partial + bytes([b])
                expanded.append((full, _partial_score(data, full, keysize)))
        expanded.sort(key=lambda x: -x[1])
        beam = [k for k, _ in expanded[:width]]
    return beam[0]


def repeating_key_xor_break(data: bytes, max_keysize: int = 40) -> list[tuple[bytes, bytes, float]]:
    """Break repeating key xor. Returns (key, plaintext, score) for top keysize guesses."""
    results = []
    for keysize, _ in guess_keysize(data, max_keysize, top=6):
        if keysize <= 12:
            key = _beam_search_key(data, keysize)
        else:
            key = bytes(single_byte_xor_break(data[i::keysize], top=1)[0][0] for i in range(keysize))
        key, score = _refine_key(data, key)
        results.append((key, xor_bytes(data, key), score))
    results.sort(key=lambda x: -x[2])
    return results
