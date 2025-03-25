#!/bin/bash
set -e

# Prepare users.acl.template with passwords from environment variables
# ACL template and destination
TEMPLATE_FILE="/usr/local/etc/redis/acl/users.acl.template"
ACL_FILE="/usr/local/etc/redis/acl/users.acl"

# Simply use envsubst to replace environment variables in the template
envsubst < $TEMPLATE_FILE > $ACL_FILE

# Set proper permissions for security
chmod 600 $ACL_FILE

echo "ACL file prepared with passwords from environment variables"

# Start Redis server in the background
redis-server /usr/local/etc/redis/redis.conf &

# Wait for Redis to start
sleep 2

# Run initialization script
python3 /usr/local/bin/populate.py

# Wait for Redis process
wait $!