#!/bin/bash

# Default values
PATELA_CERTS_DIR="certs"

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -d|--dir) PATELA_CERTS_DIR="$2"; shift ;;
        *) CLIENT_NAME="$1" ;;
    esac
    shift
done

# Validate client name was provided
if [ -z "$CLIENT_NAME" ]; then
    echo "Usage: $0 [-d|--dir <certificate-directory>] <client-name>"
    echo "  -d, --dir    Specify certificates directory (default: certs)"
    exit 1
fi

# Generate client key and certificate signing request (CSR)
openssl req -newkey rsa:4096 -nodes \
    -keyout "$PATELA_CERTS_DIR/$CLIENT_NAME-key.pem" \
    -out "$PATELA_CERTS_DIR/$CLIENT_NAME-req.pem" \
    -subj "/CN=$CLIENT_NAME"

# Sign the client certificate with the CA
openssl x509 -req -days 365000 -set_serial 01 \
    -in "$PATELA_CERTS_DIR/$CLIENT_NAME-req.pem" \
    -out "$PATELA_CERTS_DIR/$CLIENT_NAME-cert.pem" \
    -CA "$PATELA_CERTS_DIR/ca-cert.pem" \
    -CAkey "$PATELA_CERTS_DIR/ca-key.pem"

rm "$PATELA_CERTS_DIR/$CLIENT_NAME-req.pem"

echo "Client certificate for $CLIENT_NAME created successfully:"
echo " - Private key: $PATELA_CERTS_DIR/$CLIENT_NAME-key.pem"
echo " - Certificate: $PATELA_CERTS_DIR/$CLIENT_NAME-cert.pem"
echo " - Verify if client cert is signed by the authority:"

openssl verify -CAfile "$PATELA_CERTS_DIR/ca-cert.pem" "$PATELA_CERTS_DIR/$CLIENT_NAME-cert.pem"


