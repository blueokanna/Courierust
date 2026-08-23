# Independently verify the P-384 intermediate cert signature with openssl.
# Extracts tbsCertificate + signature from the intermediate DER, then runs
# `openssl dgst -sha384 -verify <root pubkey> -signature sig.der tbs.der`.
import subprocess, sys

def read_tlv(data, pos):
    """Return (tag, value, next_pos, elem_start, elem_len) where elem covers
    tag+length+value (the full DER element bytes)."""
    start = pos
    tag = data[pos]; pos += 1
    b = data[pos]; pos += 1
    if b & 0x80:
        n = b & 0x7f
        ln = int.from_bytes(data[pos:pos+n], 'big'); pos += n
    else:
        ln = b
    val = data[pos:pos+ln]; pos += ln
    return tag, val, pos, start, pos - start

def main():
    root_pem = r"d:\RustProject\Courierust\tests\certs\p384_ca_cert.pem"
    inter_der = open(r"d:\RustProject\Courierust\tests\certs\p384_intermediate_cert.der", 'rb').read()

    # Outer SEQUENCE
    tag, outer, pos, _, _ = read_tlv(inter_der, 0)
    assert tag == 0x30
    # First element = tbsCertificate: full element bytes = outer[0 : elem_len]
    tag, _, _, _, tbs_len = read_tlv(outer, 0)
    assert tag == 0x30
    tbs = outer[0:tbs_len]
    open(r"d:\RustProject\Courierust\tmp_p384_tbs.der", 'wb').write(tbs)

    # Walk to the signature BIT STRING: tbs, then sigAlgorithm SEQ, then BIT STRING
    _, _, p2, _, _ = read_tlv(outer, 0)
    _, _, p2, _, _ = read_tlv(outer, p2)
    _, sigbits, _, _, _ = read_tlv(outer, p2)
    # BIT STRING: first byte = unused bits count
    sig = sigbits[1:]
    open(r"d:\RustProject\Courierust\tmp_p384_sig.der", 'wb').write(sig)

    # Extract root public key
    r = subprocess.run(["C:\\msys64\\usr\\bin\\openssl.exe", "x509", "-in", root_pem, "-pubkey", "-noout"],
                       capture_output=True)
    open(r"d:\RustProject\Courierust\tmp_p384_root_pub.pem", 'wb').write(r.stdout)

    # Verify
    v = subprocess.run(["C:\\msys64\\usr\\bin\\openssl.exe", "dgst", "-sha384",
                        "-verify", r"d:\RustProject\Courierust\tmp_p384_root_pub.pem",
                        "-signature", r"d:\RustProject\Courierust\tmp_p384_sig.der",
                        r"d:\RustProject\Courierust\tmp_p384_tbs.der"],
                       capture_output=True, text=True)
    print("openssl verify stdout:", v.stdout)
    print("openssl verify stderr:", v.stderr)

    import hashlib
    print("sha384(tbs) =", hashlib.sha384(tbs).hexdigest())
    print("sig hex =", sig.hex())
    print("tbs len =", len(tbs))

if __name__ == "__main__":
    main()
