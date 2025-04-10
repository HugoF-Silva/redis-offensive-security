#!/bin/bash
set -e

# Function to print messages with timestamps
log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') [DEBUG] $1"
}

# Skip firewall setup for troubleshooting
log "Skipping firewall setup for troubleshooting connectivity"

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
log "ACL file created with password"

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
logfile ""
daemonize no
EOF

# Log minimal config
log "Redis config created (password omitted for security)"

# Create a test script to verify Redis connectivity
cat > /tmp/test_redis.sh << EOF
#!/bin/bash
sleep 5
echo "Testing Redis connectivity..."
redis-cli -h localhost -a "$REDIS_PASSWORD" ping
echo "Testing network connectivity from inside container..."
ping -c 1 secure-redis-exporter || echo "Cannot ping exporter"
EOF
chmod +x /tmp/test_redis.sh

# Run test script in background
nohup /tmp/test_redis.sh > /tmp/test_output.log 2>&1 &

log "Starting Redis in background..."
su -s /bin/bash redis -c "redis-server /tmp/redis.conf" &

log "Waiting for Redis to be ready..."
sleep 5

log "Running data initialization..."
REDIS_PASSWORD=$REDIS_PASSWORD /usr/local/bin/init_data.sh || log "Failed to initialize Redis data"

wait
