#!/usr/bin/env bash
set -euo pipefail
mkdir -p labs/certs
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 14 \
  -keyout labs/certs/proxy.key -out labs/certs/proxy.crt \
  -subj "/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:TRUE"
chmod 600 labs/certs/proxy.key
echo "Created a short-lived lab-only certificate in labs/certs/."
