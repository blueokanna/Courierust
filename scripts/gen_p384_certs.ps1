# Generate a P-384 CA hierarchy to exercise the ECDSA P-384 certificate
# verification path:
#
#   p384_ca (self-signed P-384 root, CA:TRUE, keyCertSign)
#     └── p384_intermediate (P-384, CA:TRUE, keyCertSign, signed by root)
#           └── p384_leaf (P-384, CA:FALSE, serverAuth, CN=localhost,
#                          SAN DNS:localhost + IP:127.0.0.1, signed by the
#                          P-384 intermediate with ecdsa-with-SHA384)
#
# This chain is the exact scenario the verifier must accept: an
# intermediate CA whose SPKI is a P-384 key (97-byte uncompressed point),
# with both the leaf and the intermediate signed using ECDSA SHA-384.
# Outputs DER files under tests/certs for include_bytes! embedding.
$ErrorActionPreference = "Stop"
$env:OPENSSL_CONF = ""
$openssl = "C:\msys64\usr\bin\openssl.exe"
$out = "tests\certs"
New-Item -ItemType Directory -Force -Path $out | Out-Null

$days = 3650 # ~2036, inside the NOW window used by the tests (2027)

# --- P-384 root CA (self-signed) ---
& $openssl ecparam -name secp384r1 -genkey -noout -out "$out\p384_ca_key.pem"
& $openssl req -new -x509 -key "$out\p384_ca_key.pem" -out "$out\p384_ca_cert.pem" `
    -days $days -sha384 `
    -subj "/CN=courierust P-384 test root" `
    -addext "basicConstraints=critical,CA:TRUE" `
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# --- P-384 intermediate CA (signed by the P-384 root) ---
& $openssl ecparam -name secp384r1 -genkey -noout -out "$out\p384_intermediate_key.pem"
& $openssl req -new -key "$out\p384_intermediate_key.pem" -out "$out\p384_intermediate.csr" `
    -subj "/CN=courierust P-384 intermediate"
$interExt = @"
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
"@
$interExtFile = Join-Path $out "p384_intermediate_ext.cnf"
[System.IO.File]::WriteAllText($interExtFile, $interExt, [System.Text.Encoding]::ASCII)
& $openssl x509 -req -in "$out\p384_intermediate.csr" -CA "$out\p384_ca_cert.pem" `
    -CAkey "$out\p384_ca_key.pem" -CAcreateserial -out "$out\p384_intermediate_cert.pem" `
    -days $days -sha384 -extfile $interExtFile

# --- P-384 leaf (CN=localhost, CA:FALSE, serverAuth) ---
& $openssl ecparam -name secp384r1 -genkey -noout -out "$out\p384_leaf_key.pem"
& $openssl req -new -key "$out\p384_leaf_key.pem" -out "$out\p384_leaf.csr" `
    -subj "/CN=localhost"
$leafExt = @"
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
"@
$leafExtFile = Join-Path $out "p384_leaf_ext.cnf"
[System.IO.File]::WriteAllText($leafExtFile, $leafExt, [System.Text.Encoding]::ASCII)
& $openssl x509 -req -in "$out\p384_leaf.csr" -CA "$out\p384_intermediate_cert.pem" `
    -CAkey "$out\p384_intermediate_key.pem" -CAcreateserial -out "$out\p384_leaf_cert.pem" `
    -days $days -sha384 -extfile $leafExtFile

# --- DER outputs ---
& $openssl x509 -in "$out\p384_ca_cert.pem" -outform DER -out "$out\p384_ca_cert.der"
& $openssl x509 -in "$out\p384_intermediate_cert.pem" -outform DER -out "$out\p384_intermediate_cert.der"
& $openssl x509 -in "$out\p384_leaf_cert.pem" -outform DER -out "$out\p384_leaf_cert.der"
& $openssl pkcs8 -topk8 -nocrypt -in "$out\p384_leaf_key.pem" -outform DER -out "$out\p384_leaf_key.der"

# --- Sanity checks ---
& $openssl verify -CAfile "$out\p384_ca_cert.pem" -untrusted "$out\p384_intermediate_cert.pem" "$out\p384_leaf_cert.pem"
& $openssl x509 -in "$out\p384_leaf_cert.pem" -noout -text | Select-String -Pattern "Public Key Algorithm|NIST CURVE|Signature Algorithm|Subject Alternative Name" -Context 0,1

Write-Output "P-384 certs generated under $out"
