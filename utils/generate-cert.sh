# Generate a self-signed certificate and key for the server
# This script will create server-cert.pem and server-key.pem
#openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
#  -keyout server-key.pem -out server-cert.pem \
#  -subj "/CN=localhost"

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout server-key.pem -out server-cert.pem \
  -config ../utils/openssl-san.cnf -extensions v3_req