#!/bin/bash

set -e

mkdir -p /etc/ssl/private /etc/ssl/certs
mkdir -p /etc/ssl/exporter

chmod 755 /etc/ssl/private
chmod 755 /etc/ssl/certs

# CA certificate
openssl genrsa -out /etc/ssl/private/ca.key 4096
openssl req -new -x509 -key /etc/ssl/private/ca.key -out /etc/ssl/certs/ca.crt -days 365 -subj "/CN=Redis CA"

# Redis server certificate
openssl genrsa -out /etc/ssl/private/redis.key 2048
openssl req -new -key /etc/ssl/private/redis.key -out /tmp/redis.csr -subj "/CN=redis"
openssl x509 -req -in /tmp/redis.csr -CA /etc/ssl/certs/ca.crt -CAkey /etc/ssl/private/ca.key -CAcreateserial -out /etc/ssl/certs/redis.crt -days 365

# Client certificate for authentication (useful for tools and testing)
openssl genrsa -out /etc/ssl/private/client.key 2048
openssl req -new -key /etc/ssl/private/client.key -out /tmp/client.csr -subj "/CN=client"
openssl x509 -req -in /tmp/client.csr -CA /etc/ssl/certs/ca.crt -CAkey /etc/ssl/private/ca.key -CAcreateserial -out /etc/ssl/certs/client.crt -days 365

cp /etc/ssl/private/client.key /etc/ssl/exporter/
cp /etc/ssl/certs/client.crt /etc/ssl/exporter/
cp /etc/ssl/certs/ca.crt /etc/ssl/exporter

chmod 600 /etc/ssl/private/*.key
chmod 644 /etc/ssl/certs/*.crt

chmod 755 /etc/ssl/exporter
chmod 644 /etc/ssl/exporter/*

chmod -R a+r /etc/ssl/exporter

# Clean up CSR files
rm -f /tmp/*.csr

echo "TLS certificates generated successfully"