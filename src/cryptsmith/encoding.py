"""Encoding detection and layered auto decode (base64, hex, url, ...)."""
import base64
import re
from urllib.parse import unquote

_B64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")
_HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2})+$")


def looks_like_base64(s: str) -> bool:
    s = s.strip()
    return len(s) >= 8 and len(s) % 4 == 0 and bool(_B64_RE.match(s))


def looks_like_hex(s: str) -> bool:
    s = s.strip()
    return len(s) >= 8 and bool(_HEX_RE.match(s))


def looks_like_urlencoded(s: str) -> bool:
    return "%" in s and bool(re.search(r"%[0-9a-fA-F]{2}", s))


def _try_b64(s: str) -> bytes | None:
    try:
        return base64.b64decode(s.strip(), validate=False)
    except Exception:
        return None


def _try_hex(s: str) -> bytes | None:
    try:
        return bytes.fromhex(s.strip())
    except Exception:
        return None


def smart_decode(data: bytes, max_depth: int = 4) -> list[tuple[str, bytes]]:
    """Peel layered encodings. Returns list of (chain_label, decoded_bytes)."""
    try:
        text = data.decode("ascii").strip()
    except Exception:
        return []
    results: list[tuple[str, bytes]] = []
    stack = [(text, [])]
    seen = set()
    for _ in range(max_depth):
        next_stack = []
        for current, chain in stack:
            if current in seen:
                continue
            seen.add(current)
            candidates: list[tuple[str, bytes | None]] = []
            if looks_like_base64(current):
                candidates.append(("b64", _try_b64(current)))
            if looks_like_hex(current):
                candidates.append(("hex", _try_hex(current)))
            if looks_like_urlencoded(current):
                try:
                    candidates.append(("url", unquote(current).encode("latin1")))
                except Exception:
                    pass
            for label, decoded in candidates:
                if decoded is None or decoded == current.encode():
                    continue
                new_chain = chain + [label]
                results.append(("+".join(new_chain), decoded))
                try:
                    nxt = decoded.decode("ascii").strip()
                    if nxt != current:
                        next_stack.append((nxt, new_chain))
                except Exception:
                    pass
        stack = next_stack
        if not stack:
            break
    return results
