import base64
import os
import struct
import tempfile

from cryptsmith import analysis, classical, encoding, hashid, pcap, rsa, xor


def test_caesar_roundtrip_and_bruteforce():
    pt = "the quick brown fox jumps over the lazy dog"
    ct = classical.caesar_encrypt(pt, 7)
    assert classical.caesar_decrypt(ct, 7) == pt
    top = classical.caesar_bruteforce(ct, top=1)[0]
    assert top[0] == 7
    assert "quick brown fox" in top[1]


def test_atbash():
    assert classical.atbash("hello") == "svool"
    assert classical.atbash(classical.atbash("Hello World")) == "Hello World"


def test_vigenere_roundtrip():
    pt = "attack at dawn"
    ct = classical.vigenere_encrypt(pt, "lemon")
    assert classical.vigenere_decrypt(ct, "lemon") == pt


def test_affine_bruteforce():
    pt = "this is a secret message hidden well"
    a, b = 5, 8
    enc = "".join(
        chr((a * (ord(c) - 97) + b) % 26 + 97) if c.isalpha() else c for c in pt
    )
    best = classical.affine_bruteforce(enc, top=1)[0]
    assert best[0] == a and best[1] == b
    assert best[2] == pt


def test_single_byte_xor_break():
    pt = b"the enrollment key is hidden in this packet capture data"
    ct = xor.xor_bytes(pt, b"\x42")
    key, recovered, score = xor.single_byte_xor_break(ct, top=1)[0]
    assert key == 0x42
    assert recovered == pt


def test_repeating_key_xor_break():
    pt = (b"the quick brown fox jumps over the lazy dog and then some more text here "
          b"so the sample is long enough for keysize detection to work well")
    key = b"SECRET"
    ct = xor.xor_bytes(pt, key)
    guesses = xor.repeating_key_xor_break(ct)
    assert guesses[0][0] == key
    assert guesses[0][1] == pt


def test_wiener_attack():
    # d must be small: d < n^0.25 / 3
    p, q = 100003, 100019
    n = p * q
    phi = (p - 1) * (q - 1)
    d = 53
    e = pow(d, -1, phi)
    assert rsa.wiener_attack(n, e) == d


def test_hastad_broadcast():
    m = 500
    e = 3
    ns = [10007 * 10009, 10037 * 10039, 10061 * 10067]
    cts = [pow(m, e, n) for n in ns]
    assert rsa.hastad_broadcast(ns, e, cts) == m


def test_common_modulus():
    p, q = 101, 103
    n = p * q
    m = 1234
    e1, e2 = 7, 11
    c1, c2 = pow(m, e1, n), pow(m, e2, n)
    assert rsa.common_modulus(n, e1, e2, c1, c2) == m


def test_entropy_and_ioc():
    assert analysis.shannon_entropy(b"a" * 100) < 1.0
    assert analysis.shannon_entropy(os.urandom(1000)) > 7.0
    english = ("the enrollment key was hidden inside the packet capture "
               "and the analyst needed to find it before the server responded ") * 5
    assert analysis.index_of_coincidence(english) > 0.06


def test_smart_decode_layered():
    inner = base64.b64encode(b"hello world").decode()
    outer = base64.b64encode(inner.encode()).decode()
    chains = encoding.smart_decode(outer.encode())
    labels = [c[0] for c in chains]
    assert "b64" in labels
    assert "b64+b64" in labels
    assert any(c[1] == b"hello world" for c in chains)


def test_hashid():
    assert "md5" in hashid.identify("5d41402abc4b2a76b9719d911017c592")
    assert "sha256" in hashid.identify("a" * 64)
    assert hashid.identify("xyz") == []


def _build_pcap(path):
    def frame(src_ip, dst_ip, sport, dport, seq, payload):
        eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
        ver_ihl, tos = 0x45, 0
        total = 20 + 20 + len(payload)
        ip = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total, 0, 0, 64, 6, 0,
                         bytes(map(int, src_ip.split("."))), bytes(map(int, dst_ip.split("."))))
        tcp = struct.pack("!HHIIHHHH", sport, dport, seq, 0, 0x5000, 0, 0, 0)
        return eth + ip + tcp + payload

    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        pkts = [
            frame("10.0.0.5", "10.0.0.9", 1337, 9000, 1, b"HELLO distsrv"),
            frame("10.0.0.5", "10.0.0.9", 1337, 9000, 14, b"ENROLL QwErTyUiOpAs"),
            frame("10.0.0.9", "10.0.0.5", 9000, 1337, 1, b"OK welcome"),
        ]
        for p in pkts:
            f.write(struct.pack("<IIII", 0, 0, len(p), len(p)) + p)


def test_xor_token_scan_finds_obfuscated_key():
    key = b"KxQwErTyUiOp"
    blob = b"\x03\x10" + bytes(b ^ 0x42 for b in b"ENROLL:" + key) + b"\x05\x00GET /x"
    hits = pcap.xor_token_scan(blob, min_length=12)
    assert hits, "expected to find the xor hidden key"
    assert any(k == 0x42 and key.decode() in t for _, k, t in hits)
    # no trivial keys: plaintext words should not report under 0x00 or 0x20
    plain_hits = pcap.xor_token_scan(b"xx communication yy", min_length=12)
    assert all(k not in (0x00, 0x20) for _, k, _ in plain_hits)


def test_pcap_reassembly_and_token_hunt():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as t:
        path = t.name
    try:
        _build_pcap(path)
        streams = pcap.reassemble_streams(pcap.PcapReader(path))
        assert len(streams) == 1
        s = streams[0]
        assert b"HELLO distsrv" in s.a_to_b
        assert b"OK welcome" in s.b_to_a
        assert pcap.hunt_alpha_tokens(s.payload, length=12) == ["QwErTyUiOpAs"]
        assert any("HELLO" in st for st in pcap.carve_strings(s.payload))
    finally:
        os.unlink(path)
