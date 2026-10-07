# cryptsmith

Crypto attack primitives and analysis toolkit for CTF players and security researchers. Zero dependencies, stdlib only.

Built for challenges like NSA Codebreakers style pcaps: custom protocols, hidden enrollment keys, obfuscated traffic.

## What it does

* **Classical ciphers** — caesar bruteforce with english scoring, vigenere, atbash, affine
* **XOR** — single byte bruteforce, repeating key break via hamming distance keysize guessing
* **RSA attacks** — Wiener's attack, Hastad broadcast, common modulus, small exponent
* **Analysis** — shannon entropy, index of coincidence, chi squared english scoring, frequency analysis
* **Encoding** — layered auto decode for base64, hex, url encoding, with the decode chain reported
* **Hash ID** — identify hash algorithms by digest length and charset
* **PCAP** — pure python pcap reader, IPv4/TCP parsing, TCP stream reassembly, payload carving, token hunting

## Install

```bash
pip install cryptsmith
```

## Quick use

```python
from cryptsmith import xor, rsa, pcap, analysis

# break single byte xor
for key, plaintext, score in xor.single_byte_xor_break(data)[:3]:
    print(key, plaintext)

# wiener attack on weak rsa
d = rsa.wiener_attack(n, e)

# pull tcp streams out of a pcap and hunt 12 char alpha tokens
streams = pcap.reassemble_streams(pcap.PcapReader("capture.pcap"))
for s in streams:
    for token in pcap.hunt_alpha_tokens(s.payload, length=12):
        print(s.label, token)
```

## Companion project

**flaghunter** builds on cryptsmith: point it at a challenge file or a pcap and it runs a full battery of attacks automatically and writes you a report.

## License

MIT
