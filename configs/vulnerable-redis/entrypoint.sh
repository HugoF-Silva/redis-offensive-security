#!/bin/bash
set -e

# Start Redis server in the background
redis-server /usr/local/etc/redis/redis.conf &

# Wait Redis start
sleep 2

# Run populate script
python3 /usr/local/bin/populate.py

# Wait for Redis process
wait $!