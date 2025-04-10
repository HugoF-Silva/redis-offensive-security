#!/bin/bash
set -e

encrypt_field() {
    echo "encrypted_$(echo $1 | sha256sum | cut -d' ' -f1)"
}

echo "Waiting for Redis to start..."
sleep 5

echo "Initializing secure Redis data with field-level encryption..."

ENCRYPTED_IP=$(encrypt_field "192.168.1.10")
ENCRYPTED_TOKEN=$(encrypt_field "a78sd8f7a9s8df7a98sd7f")
ENCRYPTED_API_KEY=$(encrypt_field "sk_live_abcdef123456")
ENCRYPTED_OTP=$(encrypt_field "872346")
ENCRYPTED_TRANSACTION_ID=$(encrypt_field "txn_abc123")

redis-cli -h localhost -a "${REDIS_PASSWORD}" HMSET "session:abc123" user_id "1001" token "eyJhbGciOiJIUzI1NiIsIn..." ip "${ENCRYPTED_IP}" device "Chrome - Windows"
redis-cli -h localhost -a "${REDIS_PASSWORD}" SET "auth_token:1001" "${ENCRYPTED_TOKEN}"
redis-cli -h localhost -a "${REDIS_PASSWORD}" HMSET "user_profile:1001" name "John Doe" email "john.doe@example.com" role "admin" last_login_ip "${ENCRYPTED_IP}" last_login_time "2025-03-19T14:00:00Z"
redis-cli -h localhost -a "${REDIS_PASSWORD}" HMSET "failed_login:1001" attempts "3" last_attempt_ip "${ENCRYPTED_IP}" rate_limited "false"
redis-cli -h localhost -a "${REDIS_PASSWORD}" SET "otp:1001" "${ENCRYPTED_OTP}"
redis-cli -h localhost -a "${REDIS_PASSWORD}" HMSET "rate_limit:ip:${ENCRYPTED_IP}" attempts "50" action "blocked"
redis-cli -h localhost -a "${REDIS_PASSWORD}" HMSET "payment_session:txn_12345" user_id "1001" amount "1200.99" status "pending" transaction_id "${ENCRYPTED_TRANSACTION_ID}"
redis-cli -h localhost -a "${REDIS_PASSWORD}" HMSET "api_key:1001" key "${ENCRYPTED_API_KEY}" permissions "read,write"
redis-cli -h localhost -a "${REDIS_PASSWORD}" HMSET "security_log:1001" user_id "1001" event "multiple_failed_logins" timestamp "2025-03-19T12:50:00Z" details "User had multiple failed logins from ${ENCRYPTED_IP}"

echo "Secure Redis data initialization complete!"