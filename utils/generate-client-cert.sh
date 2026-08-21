#!/bin/bash
# generate-client-cert.sh
# Generate a client certificate signed by the server's self-signed CA


# Usage: ./generate-client-cert.sh <uuid> <CN>
UUID="$1"
CN="$2"
if [ -z "$UUID" ]; then
	echo "Usage: $0 <uuid> <CN>"
	exit 1
fi
if [ -z "$CN" ]; then
	CN="$UUID"
fi

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="$PROJECT_ROOT/client-certs"
CA_CERT="$PROJECT_ROOT/certs/ca-cert.pem"
CA_KEY="$PROJECT_ROOT/certs/ca-key.pem"

CLIENT_KEY="$CERT_DIR/client-key-$UUID.pem"
CLIENT_CSR="$CERT_DIR/client-$UUID.csr"
CLIENT_CERT="$CERT_DIR/client-cert-$UUID.pem"
CLIENT_P12="$CERT_DIR/client-cert-$UUID.p12"
CLIENT_SUBJ="/CN=$CN"

# Generate client private key
# Generate certificate signing request (CSR)
echo "Generating client private key..."
openssl genrsa -out "$CLIENT_KEY" 2048

echo "Generating client CSR..."
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" -subj "$CLIENT_SUBJ"

# Use the shared client-ext.cnf from the utils folder
CLIENT_EXT="./utils/client-ext.cnf"

echo "Signing client certificate with CA (with clientAuth EKU)..."
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$CLIENT_CERT" -days 365 -sha256 -extfile "$CLIENT_EXT" -extensions v3_req

echo "Creating PKCS#12 file for browser import..."
openssl pkcs12 -export -out "$CLIENT_P12" -inkey "$CLIENT_KEY" -in "$CLIENT_CERT" -certfile "$CA_CERT" -password pass:

echo "Client certificate and key generated:"
echo "  $CLIENT_KEY (private key)"
echo "  $CLIENT_CERT (certificate)"
echo "  $CLIENT_P12 (for browser import)"
