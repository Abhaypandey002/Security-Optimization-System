#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$(dirname "$0")/certs"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$(dirname "$0")/certs/dev.key" \
  -out "$(dirname "$0")/certs/dev.crt" \
  -subj "/C=US/ST=CA/L=Remote/O=SecureScope/OU=Dev/CN=securescope.local"
