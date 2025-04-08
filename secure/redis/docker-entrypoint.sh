#!/bin/bash
set -e

# Run firewall setup first (only if root)
if [ $(id -u) -eq 0 ]; then
  echo "Running as root, applying firewall rules..."
  /usr/local/bin/setup-firewall.sh
else
  echo "Not running as root, skipping firewall setup"
fi

# Check if ACL file exists
if [ -f "/etc/redis/users.acl" ]; then
  echo "ACL file exists at /etc/redis/users.acl"
  ls -la /etc/redis/users.acl
else
  echo "WARNING: ACL file not found at /etc/redis/users.acl"
  echo "Creating default ACL file..."
  mkdir -p /etc/redis
  echo "user default on +@all -@dangerous ~* >${REDIS_PASSWORD}" > /etc/redis/users.acl
  cat /etc/redis/users.acl
fi

# Check SSL/TLS certificates
echo "Checking TLS certificates..."
if [ -f "/etc/ssl/certs/redis.crt" ] && [ -f "/etc/ssl/private/redis.key" ] && [ -f "/etc/ssl/certs/ca.crt" ]; then
  echo "TLS certificates found"
  ls -la /etc/ssl/certs/redis.crt /etc/ssl/private/redis.key /etc/ssl/certs/ca.crt
else
  echo "WARNING: TLS certificates not found"
  echo "Generating certificates..."
  /usr/local/bin/generate_certs.sh
fi

# Check Redis configuration
echo "Redis configuration file:"
grep -v "^#" /usr/local/etc/redis/redis.conf | grep -v "^$"

# Create log directory if it doesn't exist
mkdir -p /var/log/redis
touch /var/log/redis/redis.log
chown -R redis:redis /var/log/redis

# Start Redis directly in foreground with configuration
echo "Starting Redis server with configuration..."
exec redis-server /usr/local/etc/redis/redis.conf