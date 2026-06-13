#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CERTS_DIR="$BASE_DIR/certs"

mkdir -p "$CERTS_DIR"

openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "$CERTS_DIR/server.key" \
  -out "$CERTS_DIR/server.crt" \
  -days 365 \
  -subj "/C=PL/ST=Malopolskie/L=Krakow/O=PUS/OU=SecureBooking/CN=localhost" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

cp "$CERTS_DIR/server.crt" "$CERTS_DIR/ca.crt"

echo "Generated:"
echo "  $CERTS_DIR/server.crt"
echo "  $CERTS_DIR/server.key"
echo "  $CERTS_DIR/ca.crt"
