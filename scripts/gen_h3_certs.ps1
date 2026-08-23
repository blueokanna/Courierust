# Generate a proper CA + end-entity certificate pair for the HTTP/3
# interop benches (quinn + rustls require a leaf that is CA:FALSE with
# serverAuth EKU; a self-signed CA:TRUE cert is rejected as an end-entity).
# Outputs DER files under benches/certs for include_bytes! embedding.
$ErrorActionPreference = "Stop"
$env:OPENSSL_CONF = ""
$openssl = "C:\msys64\usr\bin\openssl.exe"
$out = "benches\certs"
New-Item -ItemType Directory -Force -Path $out | Out-Null

# --- CA (self-signed, CA:TRUE, keyCertSign) ---
& $openssl ecparam -name prime256v1 -genkey -noout -out "$out\h3_ca_key.pem"
& $openssl req -new -x509 -key "$out\h3_ca_key.pem" -out "$out\h3_ca.pem" `
    -days 3650 -sha256 `
    -subj "/CN=courierust test CA" `
    -addext "basicConstraints=critical,CA:TRUE" `
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# --- Leaf (CN=localhost, CA:FALSE, serverAuth, signed by CA) ---
& $openssl ecparam -name prime256v1 -genkey -noout -out "$out\h3_server_key.pem"
& $openssl req -new -key "$out\h3_server_key.pem" -out "$out\h3_server.csr" `
    -subj "/CN=localhost"
$ext = @"
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:0:0:0:0:0:0:0:1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
"@
$extFile = Join-Path $out "h3_server_ext.cnf"
[System.IO.File]::WriteAllText($extFile, $ext, [System.Text.Encoding]::ASCII)
& $openssl x509 -req -in "$out\h3_server.csr" -CA "$out\h3_ca.pem" `
    -CAkey "$out\h3_ca_key.pem" -CAcreateserial -out "$out\h3_server.pem" `
    -days 3650 -sha256 -extfile $extFile

# --- DER outputs ---
& $openssl x509 -in "$out\h3_ca.pem" -outform DER -out "$out\h3_ca.der"
& $openssl x509 -in "$out\h3_server.pem" -outform DER -out "$out\h3_server.der"
& $openssl pkcs8 -topk8 -nocrypt -in "$out\h3_server_key.pem" -outform DER -out "$out\h3_server_key.der"

# --- Sanity: verify chain and properties ---
& $openssl verify -CAfile "$out\h3_ca.pem" "$out\h3_server.pem"
& $openssl x509 -in "$out\h3_server.pem" -noout -text | Select-String -Pattern "CA:|DNS:|IP Address|Extended Key" | Select-Object -First 6
Write-Output "generated under $out"
