#!/bin/bash
# generate-ca.sh
# Generate a CA certificate and key

CA_KEY=ca-key.pem
CA_CERT=ca-cert.pem
CA_CNF=ca.cnf

openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
  -keyout "$CA_KEY" -out "$CA_CERT" \
  -config "$CA_CNF" -extensions v3_ca

echo "CA certificate and key generated:"
echo "  $CA_KEY (private key)"
echo "  $CA_CERT (certificate)"