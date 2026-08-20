# Reference Poly1305 for cross-checking the Rust port.
def poly1305(msg, key):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    a = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        b = block + b"\x01" + b"\x00" * (16 - len(block) - 1)
        n = int.from_bytes(b, "little")
        a = ((a + n) * r) % p
    return ((a + s) & ((1 << 128) - 1)).to_bytes(16, "little").hex()


key = bytes.fromhex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
msg = b'"Is it that clear already?" "Rather not, for the layman."'
print("computed:", poly1305(msg, key))
print("expected: eea86fa5efdd5d834eadf09f5f47a5bd")

key2 = bytes.fromhex("0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e")
msg2 = (b'Any submission to the IETF intended by the Contributor for publication as all or part of an IETF '
        b'Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an '
        b'"IETF Contribution". Such statements include oral statements in IETF sessions, as well as written and '
        b'electronic communications made at any time or place, which are addressed to')
print("vec2:", poly1305(msg2, key2))
print("exp2: 36e5f6b5c5e06070f0efca96227a863e")
