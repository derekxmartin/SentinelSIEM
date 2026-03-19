#!/bin/sh
# gen-certs.sh — Generate self-signed TLS certificates for syslog TLS testing.
#
# Usage: ./scripts/gen-certs.sh [--force]
#
# Outputs:
#   certs/ca-key.pem       CA private key
#   certs/ca-cert.pem      CA certificate
#   certs/server-key.pem   Server private key
#   certs/server-cert.pem  Server certificate (signed by CA)
#
# SANs: localhost, 127.0.0.1, ::1
# Validity: 365 days

set -e

CERT_DIR="certs"
FORCE=0

for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
    esac
done

if [ -f "$CERT_DIR/server-cert.pem" ] && [ "$FORCE" -eq 0 ]; then
    echo "Certificates already exist in $CERT_DIR/. Use --force to regenerate."
    exit 0
fi

mkdir -p "$CERT_DIR"

echo "==> Generating CA key and certificate..."
openssl genrsa -out "$CERT_DIR/ca-key.pem" 2048 2>/dev/null
openssl req -new -x509 -days 365 -key "$CERT_DIR/ca-key.pem" \
    -out "$CERT_DIR/ca-cert.pem" \
    -subj "/CN=AkesoSIEM Test CA" 2>/dev/null

echo "==> Generating server key and CSR..."
openssl genrsa -out "$CERT_DIR/server-key.pem" 2048 2>/dev/null

# Create SAN config.
cat > "$CERT_DIR/san.cnf" << 'SANEOF'
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
SANEOF

openssl req -new -key "$CERT_DIR/server-key.pem" \
    -out "$CERT_DIR/server.csr" \
    -config "$CERT_DIR/san.cnf" 2>/dev/null

echo "==> Signing server certificate with CA..."
openssl x509 -req -days 365 \
    -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca-cert.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$CERT_DIR/server-cert.pem" \
    -extensions v3_req \
    -extfile "$CERT_DIR/san.cnf" 2>/dev/null

# Cleanup intermediate files.
rm -f "$CERT_DIR/server.csr" "$CERT_DIR/san.cnf" "$CERT_DIR/ca-cert.srl"

echo "==> Certificates generated in $CERT_DIR/"
echo "    CA cert:     $CERT_DIR/ca-cert.pem"
echo "    Server cert: $CERT_DIR/server-cert.pem"
echo "    Server key:  $CERT_DIR/server-key.pem"
