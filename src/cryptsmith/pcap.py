"""Pure python pcap reading, TCP stream reassembly, and payload carving.

No dependencies. Handles the classic libpcap format (little and big endian,
microsecond and nanosecond), Ethernet + IPv4 + TCP.
"""
import re
import struct
from dataclasses import dataclass, field


@dataclass
class Packet:
    ts: float
    data: bytes


class PcapReader:
    """Iterate packets from a pcap file."""

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            magic = f.read(4)
        if magic == b"\xd4\xc3\xb2\xa1":
            self._endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            self._endian = ">"
        elif magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            self._endian = "<" if magic == b"\x4d\x3c\xb2\xa1" else ">"
            self._nanosec = True
        else:
            raise ValueError("not a pcap file (bad magic)")
        self._nanosec = getattr(self, "_nanosec", magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"))

    def packets(self):
        e = self._endian
        with open(self.path, "rb") as f:
            f.read(24)  # global header
            while True:
                hdr = f.read(16)
                if len(hdr) < 16:
                    return
                ts_sec, ts_frac, incl_len, _ = struct.unpack(e + "IIII", hdr)
                data = f.read(incl_len)
                if len(data) < incl_len:
                    return
                ts = ts_sec + ts_frac / (1e9 if self._nanosec else 1e6)
                yield Packet(ts=ts, data=data)


@dataclass
class TCPFlow:
    src: str
    sport: int
    dst: str
    dport: int
    payload: bytes = b""

    @property
    def label(self) -> str:
        return f"{self.src}:{self.sport} -> {self.dst}:{self.dport}"


@dataclass
class TCPStream:
    """Both directions of one TCP conversation, reassembled."""
    endpoint_a: tuple[str, int] = field(default=("", 0))
    endpoint_b: tuple[str, int] = field(default=("", 0))
    a_to_b: bytes = b""
    b_to_a: bytes = b""
    packet_count: int = 0

    @property
    def label(self) -> str:
        a = f"{self.endpoint_a[0]}:{self.endpoint_a[1]}"
        b = f"{self.endpoint_b[0]}:{self.endpoint_b[1]}"
        return f"{a} <-> {b}"

    @property
    def payload(self) -> bytes:
        return self.a_to_b + b"\n--- direction flip ---\n" + self.b_to_a


def _parse_ipv4(data: bytes):
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    if len(data) < ihl or data[9] != 6:  # protocol 6 = TCP
        return None
    src = ".".join(str(b) for b in data[12:16])
    dst = ".".join(str(b) for b in data[16:20])
    return src, dst, data[ihl:]


def _parse_tcp(data: bytes):
    if len(data) < 20:
        return None
    sport, dport, seq = struct.unpack("!HHI", data[:8])
    data_offset = (data[12] >> 4) * 4
    if len(data) < data_offset:
        return None
    return sport, dport, seq, data[data_offset:]


def parse_packet(raw: bytes) -> TCPFlow | None:
    """Parse one link layer frame into a TCPFlow. Returns None if not TCP/IPv4."""
    if len(raw) < 14:
        return None
    ethertype = struct.unpack("!H", raw[12:14])[0]
    if ethertype != 0x0800:  # IPv4 only
        return None
    ip = _parse_ipv4(raw[14:])
    if ip is None:
        return None
    src, dst, tcp_seg = ip
    tcp = _parse_tcp(tcp_seg)
    if tcp is None:
        return None
    sport, dport, seq, payload = tcp
    flow = TCPFlow(src=src, sport=sport, dst=dst, dport=dport, payload=b"")
    flow.seq = seq  # type: ignore[attr-defined]
    flow.payload = payload
    return flow


def reassemble_streams(reader: PcapReader) -> list[TCPStream]:
    """Reassemble TCP streams from a pcap. Returns streams with payloads in order."""
    # key: frozenset of endpoints -> stream; per direction seq buckets
    streams: dict[frozenset, TCPStream] = {}
    buckets: dict[frozenset, dict[tuple, list[tuple[int, bytes]]]] = {}

    for pkt in reader.packets():
        flow = parse_packet(pkt.data)
        if flow is None or not flow.payload:
            continue
        key = frozenset({(flow.src, flow.sport), (flow.dst, flow.dport)})
        if key not in streams:
            eps = sorted(key)
            streams[key] = TCPStream(endpoint_a=eps[0], endpoint_b=eps[1])
            buckets[key] = {}
        direction = ((flow.src, flow.sport), (flow.dst, flow.dport))
        buckets[key].setdefault(direction, []).append((flow.seq, flow.payload))
        streams[key].packet_count += 1

    for key, stream in streams.items():
        for direction, segs in buckets[key].items():
            segs.sort(key=lambda x: x[0])
            merged = bytearray()
            next_seq = None
            for seq, payload in segs:
                if next_seq is None:
                    merged += payload
                    next_seq = seq + len(payload)
                elif seq >= next_seq:
                    merged += payload
                    next_seq = seq + len(payload)
                elif seq + len(payload) > next_seq:
                    merged += payload[next_seq - seq:]
                    next_seq = seq + len(payload)
            data = bytes(merged)
            if direction[0] == stream.endpoint_a:
                stream.a_to_b = data
            else:
                stream.b_to_a = data
    return list(streams.values())


def carve_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Extract printable ascii strings like the `strings` utility."""
    out = []
    cur = []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out


def opaque_runs(data: bytes, min_len: int = 12) -> list[bytes]:
    """Maximal runs of non printable bytes. Obfuscated blobs hide in these."""
    runs = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            if len(cur) >= min_len:
                runs.append(bytes(cur))
            cur = bytearray()
        else:
            cur.append(b)
    if len(cur) >= min_len:
        runs.append(bytes(cur))
    return runs


def suspicious_spans(data: bytes, min_len: int = 16, max_printable: float = 0.7) -> list[bytes]:
    """Spans that look obfuscated: mixed binary where xor'd text often hides.

    Xor obfuscation with a byte key leaves some bytes printable, so strict
    non printable runs miss it. These spans tolerate printable bytes up to
    max_printable ratio.
    """
    flags = [32 <= b < 127 for b in data]
    n = len(data)
    spans = []
    i = 0
    while i < n:
        if flags[i]:
            i += 1
            continue
        j = i
        while j < n:
            seg = flags[i:j + 1]
            if sum(seg) / len(seg) > max_printable and (j - i + 1) >= min_len:
                break
            j += 1
        if j - i >= min_len:
            spans.append(data[i:j])
        i = j if j > i else i + 1
    return spans


def hunt_alpha_tokens(data: bytes, length: int = 12) -> list[str]:
    """Find alpha only tokens of exactly `length` chars, e.g. enrollment keys.

    Looks at raw bytes and at printable strings, deduped, in order of appearance.
    """
    text = data.decode("latin1")
    pattern = re.compile(rf"(?<![A-Za-z])[A-Za-z]{{{length}}}(?![A-Za-z])")
    seen = set()
    hits = []
    for m in pattern.finditer(text):
        tok = m.group(0)
        if tok not in seen:
            seen.add(tok)
            hits.append(tok)
    return hits


def hunt_alpha_runs(data: bytes, min_length: int = 12) -> list[str]:
    """Find alpha only runs of at least min_length chars.

    Looser than hunt_alpha_tokens: for decoded or deobfuscated text where
    token boundaries are unreliable, e.g. a key glued to framing bytes.
    """
    text = data.decode("latin1")
    seen = set()
    hits = []
    for m in re.finditer(r"[A-Za-z]+", text):
        tok = m.group(0)
        if len(tok) >= min_length and tok not in seen:
            seen.add(tok)
            hits.append(tok)
    return hits


_ALPHA = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

# BYTE_MASKS[b]: bitmask of xor keys k where (b ^ k) is an ascii letter.
# Precomputed once; key k corresponds to bit (1 << k).
_BYTE_MASKS: list[int] = []
for _b in range(256):
    _m = 0
    for _c in _ALPHA:
        _m |= 1 << (_b ^ _c)
    _BYTE_MASKS.append(_m)


def xor_token_scan(data: bytes, min_length: int = 12) -> list[tuple[int, int, str]]:
    """Find (offset, key, token) where data[offset:] xored with key starts with
    an alpha only run of at least min_length chars.

    This catches xor obfuscated tokens buried in mixed binary traffic, where
    whole blob english scoring fails because plaintext and obfuscated regions
    mix. Bitmask sliding window makes it O(n): for each byte, the set of keys
    yielding a letter; AND the sets across the window. Any nonzero result
    means some key decodes the whole window to letters.
    """
    n = len(data)
    if n < min_length:
        return []
    masks = [_BYTE_MASKS[b] for b in data]
    hits: list[tuple[int, int, str]] = []
    for start in range(n - min_length + 1):
        window_and = masks[start]
        for i in range(start + 1, start + min_length):
            window_and &= masks[i]
            if not window_and:
                break
        if not window_and:
            continue
        mm, k = window_and, 0
        while mm:
            if mm & 1:
                end = start + min_length
                while end < n and (data[end] ^ k) in _ALPHA:
                    end += 1
                token = bytes(b ^ k for b in data[start:end]).decode("ascii")
                # skip trivial keys: the token is already sitting in the raw
                # bytes (e.g. key 0x00 identity or 0x20 case flip on plaintext)
                raw = data[start:end].decode("latin1")
                if raw.lower() != token.lower():
                    hits.append((start, k, token))
            mm >>= 1
            k += 1
    # dedupe by (key, token), keep earliest offset
    seen = set()
    deduped = []
    for offset, k, token in hits:
        if (k, token) not in seen:
            seen.add((k, token))
            deduped.append((offset, k, token))
    return deduped


def hunt_pattern(data: bytes, pattern: str) -> list[str]:
    """Find all matches of a custom regex against the payload as latin1 text."""
    rx = re.compile(pattern)
    text = data.decode("latin1")
    seen = set()
    hits = []
    for m in rx.finditer(text):
        tok = m.group(0)
        if tok not in seen:
            seen.add(tok)
            hits.append(tok)
    return hits
