# cryptsmith

Crypto attack primitives and analysis toolkit for CTF players and security researchers. Zero dependencies, stdlib only.

Built for the NSA Codebreakers style of challenge. Custom protocols, hidden enrollment keys, obfuscated traffic, weird RSA.

## What's in the box

* **Classical ciphers**. Caesar bruteforce with english scoring, vigenere, atbash, affine.
* **XOR**. Single-byte bruteforce, repeating-key break via hamming-distance keysize guessing.
* **RSA**. Wiener's attack, Hastad broadcast, common modulus, small exponent.
* **Analysis**. Shannon entropy, index of coincidence, chi-squared english scoring, frequency analysis.
* **Encoding**. Layered auto-decode for base64, hex, url. Reports the decode chain it took.
* **Hash ID**. Identify hash algorithms by digest length and charset.
* **PCAP**. Pure Python pcap reader. IPv4/TCP parsing, TCP stream reassembly, payload carving, token hunting.

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

**[flaghunter](https://github.com/burrejak22/flaghunter)** sits on top of this. Point it at a challenge file or pcap, it runs the whole attack battery for you and writes up what fell out.

## License

MIT
