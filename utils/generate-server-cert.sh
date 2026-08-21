#!/bin/bash
# generate-server-cert.sh
# Generate a server certificate signed by the CA

SERVER_KEY=server-key.pem
SERVER_CSR=server.csr
SERVER_CERT=server-cert.pem
SERVER_CNF=server.cnf
CA_KEY=ca-key.pem
CA_CERT=ca-cert.pem

# Generate server private key
openssl genrsa -out "$SERVER_KEY" 4096

# Generate server CSR
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" -config "$SERVER_CNF"

# Sign server CSR with CA
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$SERVER_CERT" -days 825 -sha256 -extfile "$SERVER_CNF" -extensions v3_req

echo "Server certificate and key generated:"
echo "  $SERVER_KEY (private key)"
echo "  $SERVER_CERT (certificate)"