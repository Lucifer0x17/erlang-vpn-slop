#!/bin/bash
set -euo pipefail

# ErlVPN Certificate Generation Script
# Generates self-signed TLS certificates for QUIC transport

DOMAIN="${1:-localhost}"
CERT_DIR="${2:-certs}"
DAYS="${3:-365}"

log() { echo "[erlvpn-certs] $*"; }
err() { echo "[erlvpn-certs] ERROR: $*" >&2; exit 1; }

# Check openssl
if ! command -v openssl &>/dev/null; then
    err "openssl is required but not found in PATH"
fi

# Create cert directory
mkdir -p "$CERT_DIR"

log "Generating certificates for: $DOMAIN"
log "Output directory: $CERT_DIR"
log "Validity: $DAYS days"

# Generate CA key and certificate
log "Generating CA private key..."
openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/ca.key" 2>/dev/null

log "Generating CA certificate..."
openssl req -new -x509 \
    -key "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -days "$DAYS" \
    -subj "/C=XX/ST=VPN/L=ErlVPN/O=ErlVPN CA/CN=ErlVPN Root CA" \
    2>/dev/null

# Generate server key and certificate
log "Generating server private key..."
openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/server.key" 2>/dev/null

log "Generating server CSR..."
openssl req -new \
    -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -subj "/C=XX/ST=VPN/L=ErlVPN/O=ErlVPN/CN=$DOMAIN" \
    2>/dev/null

# Create SAN extension file
cat > "$CERT_DIR/server_ext.cnf" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = *.$DOMAIN
DNS.3 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
IP.3 = 10.8.0.1
EOF

log "Signing server certificate with CA..."
openssl x509 -req \
    -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/server.crt" \
    -days "$DAYS" \
    -extfile "$CERT_DIR/server_ext.cnf" \
    2>/dev/null

# Generate client key and certificate (for mutual TLS)
log "Generating client private key..."
openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/client.key" 2>/dev/null

log "Generating client CSR..."
openssl req -new \
    -key "$CERT_DIR/client.key" \
    -out "$CERT_DIR/client.csr" \
    -subj "/C=XX/ST=VPN/L=ErlVPN/O=ErlVPN Client/CN=erlvpn-client" \
    2>/dev/null

# Create client extension file
cat > "$CERT_DIR/client_ext.cnf" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
EOF

log "Signing client certificate with CA..."
openssl x509 -req \
    -in "$CERT_DIR/client.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/client.crt" \
    -days "$DAYS" \
    -extfile "$CERT_DIR/client_ext.cnf" \
    2>/dev/null

# Clean up CSRs and temp files
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.cnf "$CERT_DIR"/*.srl

# Set permissions
chmod 600 "$CERT_DIR"/*.key
chmod 644 "$CERT_DIR"/*.crt

log ""
log "Certificates generated successfully:"
log "  CA Certificate:     $CERT_DIR/ca.crt"
log "  CA Key:             $CERT_DIR/ca.key"
log "  Server Certificate: $CERT_DIR/server.crt"
log "  Server Key:         $CERT_DIR/server.key"
log "  Client Certificate: $CERT_DIR/client.crt"
log "  Client Key:         $CERT_DIR/client.key"
log ""
log "Server cert details:"
openssl x509 -in "$CERT_DIR/server.crt" -noout -subject -issuer -dates 2>/dev/null
log ""
log "To verify: openssl verify -CAfile $CERT_DIR/ca.crt $CERT_DIR/server.crt"
