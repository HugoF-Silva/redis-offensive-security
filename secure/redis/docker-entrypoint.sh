#!/bin/bash
set -e

# Function to print messages with timestamps
log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') [DEBUG] $1"
}

# Run firewall setup if root
if [ $(id -u) -eq 0 ]; then
  log "Running as root, applying firewall rules..."
  /usr/local/bin/setup-firewall.sh
else
  log "Not running as root, skipping firewall setup"
fi

# Ensure Redis data directory exists and has proper permissions
log "Setting up data directory..."
mkdir -p /data
chown -R redis:redis /data
chmod 755 /data

# Create and set permissions for log directory
log "Setting up log directory..."
mkdir -p /var/log/redis
touch /var/log/redis/redis.log
chown -R redis:redis /var/log/redis
chmod 755 /var/log/redis
chmod 644 /var/log/redis/redis.log

# Create and populate ACL file
log "Creating ACL file..."
mkdir -p /etc/redis
printf "user default on +@all -@dangerous ~* >$REDIS_PASSWORD" > /etc/redis/users.acl
chown redis:redis /etc/redis/users.acl
chmod 600 /etc/redis/users.acl
log "ACL file content:"
cat /etc/redis/users.acl

# Create minimal Redis config
log "Creating minimal Redis config..."
cat > /tmp/redis.conf << EOF
port 6379
bind 0.0.0.0
protected-mode yes
requirepass $REDIS_PASSWORD
maxmemory 500mb
maxmemory-policy volatile-lru
loglevel debug
logfile stdout
EOF

# Log minimal config
log "Minimal config content:"
cat /tmp/redis.conf

log "Starting Redis with minimal config for testing..."
log "If this works, we'll add more security features later"

# Switch to redis user for running the server
log "Switching to redis user..."
exec chroot --userspec=redis:redis / redis-server /tmp/redis.conf