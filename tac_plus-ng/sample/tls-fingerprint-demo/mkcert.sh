#!/bin/sh
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes -keyout server.selfsigned.key -out server.selfsigned.crt -subj "/CN=server.selfsigned" -addext "subjectAltName=DNS:server.selfsigned"
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes -keyout client.selfsigned.key -out client.selfsigned.crt -subj "/CN=client.selfsigned" -addext "subjectAltName=DNS:client.selfsigned"
openssl x509 -noout -fingerprint -sha256 -inform pem -in server.selfsigned.crt | sed 's/^.*=//' > server.selfsigned.fingerprint
openssl x509 -noout -fingerprint -sha256 -inform pem -in client.selfsigned.crt | sed 's/^.*=//' > client.selfsigned.fingerprint

