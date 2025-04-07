#!/bin/bash
set -e

until redis-cli -h localhost -a 123 ping &>/dev/null; do
    echo "Waiting for Redis to start..."
    sleep 1
done

echo "Initializing vulnerable Redis data..."

redis-cli -h localhost -a 123 HMSET "session:abc123" user_id "1001" token "eyJhbGciOiJIUzI1NiIsIn..." ip "192.168.1.10" device "Chrome - Windows"
redis-cli -h localhost -a 123 SET "auth_token:1001" "a78sd8f7a9s8df7a98sd7f"
redis-cli -h localhost -a 123 HMSET "user_profile:1001" name "John Doe" email "john.doe@example.com" role "admin" last_login_ip "192.168.1.10" last_login_time "2025-03-19T14:00:00Z"
redis-cli -h localhost -a 123 HMSET "failed_login:1001" attempts "3" last_attempt_ip "192.168.1.10" rate_limited "false"
redis-cli -h localhost -a 123 SET "otp:1001" "872346"
redis-cli -h localhost -a 123 HMSET "rate_limit:ip:192.168.1.10" attempts "50" action "blocked"
redis-cli -h localhost -a 123 HMSET "payment_session:txn_12345" user_id "10001" amount "1200.99" status "pending" transaction_id "txt_abc123"
redis-cli -h localhost -a 123 HMSET "api_key:1001" key "sk_live_abcdef123456" permissions "read,write"
redis-cli -h localhost -a 123 HMSET "security_log:1001" user_id "1001" event "multiple_failed_logins" timestamp "2025-03-19T12:50:00Z" details "User had multiple failed logins from 192.168.1.10"

echo "Vulnerable Redis data initialization complete!"