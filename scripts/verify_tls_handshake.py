#!/usr/bin/env python3
"""Independently verify the courierust client's TLS 1.3 handshake math.

Reads the debug dump (COURIERUST_TLS_DEBUG=1) and recomputes, from first
principles, the shared secret, transcript hash, and server handshake
traffic keys, then attempts to decrypt the captured server record with
AES-128-GCM. This isolates whether a failed interop handshake is caused
by wrong keys or wrong record handling on our side.

Usage: python scripts/verify_tls_handshake.py <debug_dump_file>
"""
import hashlib
import hmac
import re
import sys

from Crypto.Cipher import AES

P = 2**255 - 19


def clamp(k: bytes) -> bytes:
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def x25519(k: bytes, u: bytes) -> bytes:
    k = clamp(k)
    x1 = int.from_bytes(u, "little") & (2**255 - 1)
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k[t // 8] >> (t % 8)) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        A = (x2 + z2) % P
        AA = A * A % P
        B = (x2 - z2) % P
        BB = B * B % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        D = (x3 - z3) % P
        DA = D * A % P
        CB = C * B % P
        x3 = (DA + CB) ** 2 % P
        z3 = x1 * (DA - CB) ** 2 % P
        x2 = AA * BB % P
        z2 = E * (AA + 121665 * E) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, P - 2, P)) % P).to_bytes(32, "little")


def hkdf_extract(salt: bytes, ikm: bytes, h=hashlib.sha256) -> bytes:
    return hmac.new(salt, ikm, h).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, h=hashlib.sha256) -> bytes:
    hlen = h().digest_size
    n = (length + hlen - 1) // hlen
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), h).digest()
        okm += t
    return okm[:length]


def hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int, h=hashlib.sha256) -> bytes:
    full = b"tls13 " + label.encode()
    info = (length).to_bytes(2, "big") + bytes([len(full)]) + full + bytes([len(context)]) + context
    return hkdf_expand(secret, info, length, h)


def derive_secret(secret: bytes, label: str, transcript_hash: bytes, h=hashlib.sha256) -> bytes:
    return hkdf_expand_label(secret, label, transcript_hash, h().digest_size, h)


def gcm_decrypt(key: bytes, iv: bytes, aad: bytes, ct: bytes, tag: bytes):
    c = AES.new(key, AES.MODE_GCM, nonce=iv)
    c.update(aad)
    return c.decrypt_and_verify(ct, tag)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: verify_tls_handshake.py <dump>")
        return 2
    txt = open(sys.argv[1], "r", encoding="utf-16", errors="replace").read()
    flat = re.sub(r"\s+", "", txt)
    m = re.search(
        r"DBGsuite=([0-9a-f]+)priv=([0-9a-f]+)pub=([0-9a-f]+)srv_ks=([0-9a-f]+)shared=([0-9a-f]+)th=([0-9a-f]+)",
        flat,
    )
    if not m:
        print("no debug data found")
        return 1
    suite, priv, pub, srv_ks, shared_crate, th = m.groups()
    ch = re.search(r"DBGch=([0-9a-f]+)", flat).group(1)
    sh = re.search(r"DBGsh_msg=([0-9a-f]+)", flat).group(1)
    rec = re.search(r"DBGrecct=([0-9a-f]{2})len=(\d+)seq=(\d+)keylen=(\d+)hex=([0-9a-f]+)", flat)
    if not rec:
        print("no captured record found")
        return 1

    chb = bytes.fromhex(ch)
    shb = bytes.fromhex(sh)
    privb = bytes.fromhex(priv)
    srvb = bytes.fromhex(srv_ks)
    thb = bytes.fromhex(th)

    # 1. X25519 shared secret.
    shared = x25519(privb, srvb)
    print("X25519 shared matches crate:", shared.hex() == shared_crate)

    # 2. Transcript hash.
    calc_th = hashlib.sha256(chb + shb).digest()
    print("transcript matches crate:", calc_th.hex() == th)

    # 3. Key schedule.
    zeros = bytes(32)
    early = hkdf_extract(zeros, zeros)
    empty_hash = hashlib.sha256(b"").digest()
    derived = derive_secret(early, "derived", empty_hash)
    hs = hkdf_extract(derived, shared)
    s_hs = derive_secret(hs, "s hs traffic", thb)
    c_hs = derive_secret(hs, "c hs traffic", thb)

    # 4. Server handshake AEAD key/IV.
    s_key = hkdf_expand_label(s_hs, "key", b"", 16)
    s_iv = hkdf_expand_label(s_hs, "iv", b"", 12)
    c_key = hkdf_expand_label(c_hs, "key", b"", 16)
    c_iv = hkdf_expand_label(c_hs, "iv", b"", 12)
    print("server hs key:", s_key.hex())
    print("server hs iv :", s_iv.hex())
    print("client hs key:", c_key.hex())
    print("client hs iv :", c_iv.hex())

    # 5. Decrypt the captured server record.
    rec_ct = int(rec.group(2))
    rec_seq = int(rec.group(3))
    rec_hex = bytes.fromhex(rec.group(5))
    header = rec_hex[:5]
    sealed = rec_hex[5:]
    ct = sealed[:-16]
    tag = sealed[-16:]
    # nonce = iv XOR (0^4 || seq_be8)
    nonce = bytearray(s_iv)
    seqb = rec_seq.to_bytes(8, "big")
    for i in range(8):
        nonce[4 + i] ^= seqb[i]
    print("record header:", header.hex(), "aad len ok:", len(header) == 5, "ct len:", len(ct))
    try:
        pt = gcm_decrypt(s_key, bytes(nonce), header, ct, tag)
        print("GCM DECRYPT OK, plaintext len:", len(pt))
        print("plaintext head:", pt[:20].hex())
        # Show the handshake messages inside.
        off = 0
        while off < len(pt):
            mtype = pt[off]
            mlen = int.from_bytes(pt[off + 1 : off + 4], "big")
            print(f"  handshake msg type={mtype} len={mlen}")
            off += 4 + mlen
    except Exception as e:  # noqa: BLE001
        print("GCM DECRYPT FAILED:", e)

    # Sanity: RFC 8448 key-schedule cross-check values.
    print("RFC8448 c_hs check:", c_hs.hex() ==
          "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    return 0


if __name__ == "__main__":
    sys.exit(main())
