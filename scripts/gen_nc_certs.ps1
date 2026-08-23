# Generate a CA hierarchy with a nameConstraints extension on the
# intermediate, plus two leaves (one inside the permitted subtree, one
# outside) to exercise RFC 5280 §4.2.1.10 enforcement.
#
#   nc_ca (self-signed root)
#     └── nc_intermediate
#           nameConstraints = critical, permitted;DNS:localhost,
#                                      permitted;IP:127.0.0.0/8
#           ├── nc_leaf_ok   (CN=localhost, SAN DNS:localhost + IP:127.0.0.1)
#           └── nc_leaf_bad  (CN=evil.com, SAN DNS:evil.com)
$ErrorActionPreference = "Stop"
$env:OPENSSL_CONF = ""
$openssl = "C:\msys64\usr\bin\openssl.exe"
$out = "tests\certs"
New-Item -ItemType Directory -Force -Path $out | Out-Null

$days = 3650

# --- Root CA ---
& $openssl ecparam -name prime256v1 -genkey -noout -out "$out\nc_ca_key.pem"
& $openssl req -new -x509 -key "$out\nc_ca_key.pem" -out "$out\nc_ca_cert.pem" `
    -days $days -sha256 -subj "/CN=courierust NC root" `
    -addext "basicConstraints=critical,CA:TRUE" `
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# --- Intermediate with nameConstraints ---
& $openssl ecparam -name prime256v1 -genkey -noout -out "$out\nc_intermediate_key.pem"
& $openssl req -new -key "$out\nc_intermediate_key.pem" -out "$out\nc_intermediate.csr" `
    -subj "/CN=courierust NC intermediate"
$interExt = @"
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
nameConstraints=critical,permitted;DNS:localhost
"@
$interExtFile = Join-Path $out "nc_intermediate_ext.cnf"
[System.IO.File]::WriteAllText($interExtFile, $interExt, [System.Text.Encoding]::ASCII)
& $openssl x509 -req -in "$out\nc_intermediate.csr" -CA "$out\nc_ca_cert.pem" `
    -CAkey "$out\nc_ca_key.pem" -CAcreateserial -out "$out\nc_intermediate_cert.pem" `
    -days $days -sha256 -extfile $interExtFile

# --- Leaf inside the permitted subtree (localhost) ---
& $openssl ecparam -name prime256v1 -genkey -noout -out "$out\nc_leaf_ok_key.pem"
& $openssl req -new -key "$out\nc_leaf_ok_key.pem" -out "$out\nc_leaf_ok.csr" -subj "/CN=localhost"
$leafOkExt = @"
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
"@
$leafOkExtFile = Join-Path $out "nc_leaf_ok_ext.cnf"
[System.IO.File]::WriteAllText($leafOkExtFile, $leafOkExt, [System.Text.Encoding]::ASCII)
& $openssl x509 -req -in "$out\nc_leaf_ok.csr" -CA "$out\nc_intermediate_cert.pem" `
    -CAkey "$out\nc_intermediate_key.pem" -CAcreateserial -out "$out\nc_leaf_ok_cert.pem" `
    -days $days -sha256 -extfile $leafOkExtFile

# --- Leaf outside the permitted subtree (evil.com) ---
& $openssl ecparam -name prime256v1 -genkey -noout -out "$out\nc_leaf_bad_key.pem"
& $openssl req -new -key "$out\nc_leaf_bad_key.pem" -out "$out\nc_leaf_bad.csr" -subj "/CN=evil.com"
$leafBadExt = @"
subjectAltName=DNS:evil.com
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
"@
$leafBadExtFile = Join-Path $out "nc_leaf_bad_ext.cnf"
[System.IO.File]::WriteAllText($leafBadExtFile, $leafBadExt, [System.Text.Encoding]::ASCII)
& $openssl x509 -req -in "$out\nc_leaf_bad.csr" -CA "$out\nc_intermediate_cert.pem" `
    -CAkey "$out\nc_intermediate_key.pem" -CAcreateserial -out "$out\nc_leaf_bad_cert.pem" `
    -days $days -sha256 -extfile $leafBadExtFile

# --- DER outputs ---
foreach ($n in @("nc_ca_cert", "nc_intermediate_cert", "nc_leaf_ok_cert", "nc_leaf_bad_cert")) {
    & $openssl x509 -in "$out\$n.pem" -outform DER -out "$out\$n.der"
}

# --- Sanity ---
Write-Output "=== good leaf should verify ==="
& $openssl verify -CAfile "$out\nc_ca_cert.pem" -untrusted "$out\nc_intermediate_cert.pem" "$out\nc_leaf_ok_cert.pem"
Write-Output "=== bad leaf should FAIL (name constraints) ==="
& $openssl verify -CAfile "$out\nc_ca_cert.pem" -untrusted "$out\nc_intermediate_cert.pem" "$out\nc_leaf_bad_cert.pem"
Write-Output "NC certs generated"
