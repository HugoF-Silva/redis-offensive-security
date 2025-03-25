#!/bin/bash
# Launch Redis Security Simulation

set -e

# Help message
function show_help {
    echo "Redis Security Demonstration"
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  -h, --help      Show this help message"
    echo "  -d, --dev       Run in development mode (local only)"
    echo "  -p, --preprod   Run in pre-production mode (with domain setup and IP whitelisting)"
    echo "  -s, --stop      Stop all services"
    echo "  -c, --clean     Clean up all data and configurations"
    echo ""
}

# Parse command-line arguments
if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -d|--dev)
            MODE="dev"
            shift
            ;;
        -p|--preprod)
            MODE="preprod"
            shift
            ;;
        -s|--stop)
            echo "Stopping all services..."
            docker-compose down
            exit 0
            ;;
        -c|--clean)
            echo "Cleaning up all data and configurations..."
            docker-compose down -v
            rm -rf configs/secure-redis/tls/*.key configs/secure-redis/tls/*.crt
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done



if [ ! -f .env ]; then
    echo "Error: .env file not found. Please create one based on .env.template."
    exit 1
fi

source .env



echo "Generating TLS certificates..."
# bash scripts/generate_tls.sh
SECURE_DOMAIN=${SECURE_DOMAIN}
TLS_DIR="./configs/secure-redis/tls"

mkdir -p ${TLS_DIR}

echo "Generating TLS certificates for secure Redis..."

# Generate CA key and certificate
openssl genrsa -out ${TLS_DIR}/ca.key 4096
openssl req -x509 -new -nodes -sha256 \
            -key ${TLS_DIR}/ca.key \
            -days 3650 \
            -out ${TLS_DIR}/ca.crt \
            -subj "/C=US/ST=CA/L=Security Demo/O=Redis Security/CN=Redis Demo CA"

# Generate server key and certificate
openssl genrsa -out ${TLS_DIR}/server.key 2048
openssl req -new -key ${TLS_DIR}/server.key \
            -out ${TLS_DIR}/server.csr \
            -subj "/C=US/ST=CA/L=Security Demo/O=Redis Security/CN=${SECURE_DOMAIN}"

# Create TEMPORARY OpenSSL config file for SAN
cat > ${TLS_DIR}/server.cnf <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${SECURE_DOMAIN}
DNS.2 = secure-redis
DNS.3 = localhost
DNS.4 = ${SECURE_DOMAIN}.local
EOF

# Sign the server certificate
openssl x509 -req -sha256 -in ${TLS_DIR}/server.csr \
             -CA ${TLS_DIR}/ca.crt -CAkey ${TLS_DIR}/ca.key -CAcreateserial \
             -out ${TLS_DIR}/server.crt -days 365 \
             -extfile ${TLS_DIR}/server.cnf -extensions v3_req

# Generate client key and certificate
openssl genrsa -out ${TLS_DIR}/client.key 2048
openssl req -new -key ${TLS_DIR}/client.key \
        -out ${TLS_DIR}/client.csr \
        -subj "/C=US/ST=CA/L=Security Demo/O=Redis Security/CN=Redis Client"

# Create TEMPORARY OpenSSL config file for client
cat > ${TLS_DIR}/client.cnf <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
EOF

# Sign the client certificate
openssl x509 -req -sha256 -in ${TLS_DIR}/client.csr \
        -CA ${TLS_DIR}/ca.crt -CAkey ${TLS_DIR}/ca.key -CAcreateserial \
        -out ${TLS_DIR}/client.crt -days 365 \
        -extfile ${TLS_DIR}/client.cnf -extensions v3_req

# Set permissions
chmod 600 ${TLS_DIR}/*.key
chmod 644 ${TLS_DIR}/*.crt ${TLS_DIR}/*.cnf ${TLS_DIR}/*.csr

# Remove temporary files
rm -f ${TLS_DIR}/*.csr ${TLS_DIR}/*.cnf ${TLS_DIR}/*.srl

# Copy certificates to other directories that need them
mkdir -p ./configs/nginx/tls
cp ${TLS_DIR}/ca.crt configs/nginx/tls/
cp ${TLS_DIR}/server.crt configs/nginx/tls/
cp ${TLS_DIR}/server.key configs/nginx/tls/

echo "TLS certificates generated successfully."



if [ "$MODE" = "dev" ]; then
    echo "Starting in development mode (local only)..."

    vulnerable_password_found=false

    # Create temporary file
    temp_file=$(mktemp)
    # Process .env file line by line
    while IFS= read -r line; do
        if [[ "$line" =~ ^VULNERABLE_REDIS_PASSWORD= ]]; then
            echo "VULNERABLE_REDIS_PASSWORD=123" >> "$temp_file"
            key_found=true
        else
            echo "$line" >> "$temp_file"
        fi
    done < .env

    mv "$temp_file" .env

    docker-compose up -d

    echo "Development environment started successfully."
    echo "Vulnerable Redis: localhost:6379"
    echo "Secure Redis: localhost:6380"
    echo "Redis Proxy: localhost:6381"
    echo "Monitoring: http://localhost:3000 (Grafana)"

elif [ "$MODE" = "preprod" ]; then
    echo "Starting in pre-production mode (with domain setup and IP whitelisting)..."
    
    # Check if root (neededed for iptables)
    if [ "$EUID" -ne 0 ]; then
        echo "Pre-production mode requires root privileges for IP whitelisting."
        echo "Please run as root (if OS unix-like: \`sudo $0 -p\`)"
        exit 1
    fi
    
    # Setup pre-production environment
    if [ -z "$AWS_ATTACKER_IP" ]; then
        echo "ERROR: AWS attacker EC2 instance IP address not set."
        exit 1
    fi

    echo "Setting up iptables rules for IP whitelisting..."
    
    # Flush existing rules
    iptables -F

    # Set default policies
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT

    # Allow loopback traffic
    iptables -A INPUT -i lo -j ACCEPT

    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow SSH from anywhere (to avoid locking yourself out)
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT

    # Allow HTTP/HTTPS from anywhere (for web interface)
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT

    # Whitelist AWS attacker IP for Redis ports
    iptables -A INPUT -p tcp --dport 6379 -s $AWS_ATTACKER_IP -j ACCEPT
    iptables -A INPUT -p tcp --dport 6380 -s $AWS_ATTACKER_IP -j ACCEPT
    iptables -A INPUT -p tcp --dport 6381 -s $AWS_ATTACKER_IP -j ACCEPT

    # Block all other external access to Redis ports
    iptables -A INPUT -p tcp --dport 6379 -j DROP
    iptables -A INPUT -p tcp --dport 6380 -j DROP
    iptables -A INPUT -p tcp --dport 6381 -j DROP

    # Save iptables rules
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4
        echo "iptables rules saved to /etc/iptables/rules.v4"
    else
        echo "Warning: iptables-save not found, rules will not persist after reboot"
        echo "Consider installing iptables-persistent package"
    fi

    # Register AppArmor profile for secure Redis
    if command -v apparmor_parser >/dev/nul 2>&1; then
        echo "Registering AppArmor profile for secure Redis..."
        cp configs/apparmor/docker-secure-redis /etc/apparmor.d/
        apparmor_parser -r -W /etc/apparmor.d/docker-secure-redis
    else
        echo "Warning: AppArmor not found, skipping AppArmor profile registration"
    fi

    echo "Pre-prod environment setup copleted successfully."
    echo "IP whitelisting configured to allow only ${AWS_ATTACKER_IP} to access Redis ports."


    NEW_KEY=$(openssl rand -base64 32)
    NEW_SALT=$(openssl rand -base64 32)
    NEW_ADMIN_PASSWORD=$(openssl rand -base64 32)
    NEW_READONLY_PASSWORD=$(openssl rand -base64 32)
    NEW_WRITEONLY_PASSWORD=$(openssl rand -base64 32)
    NEW_EXPORTER_PASSWORD=$(openssl rand -base64 32)

    key_found=false
    salt_found=false
    admin_found=false
    readonly_found=false
    writeonly_found=false
    exporter_found=false

    # Create temporary file
    temp_file=$(mktemp)
    # Process .env file line by line
    while IFS= read -r line; do
        if [[ "$line" =~ ^ENCRYPTION_KEY= ]]; then
            echo "ENCRYPTION_KEY=$NEW_KEY" >> "$temp_file"
            key_found=true
        elif [[ "$line" =~ ^ENCRYPTION_SALT= ]]; then
            echo "ENCRYPTION_SALT=$NEW_SALT" >> "$temp_file"
            salt_found=true
        elif [[ "$line" =~ ^REDIS_ADMIN_PASSWORD= ]]; then
            echo "REDIS_ADMIN_PASSWORD=$NEW_ADMIN_PASSWORD" >> "$temp_file"
            admin_found=true
        elif [[ "$line" =~ ^REDIS_READONLY_PASSWORD= ]]; then
            echo "REDIS_READONLY_PASSWORD=$NEW_READONLY_PASSWORD" >> "$temp_file"
            readonly_found=true
        elif [[ "$line" =~ ^REDIS_WRITEONLY_PASSWORD= ]]; then
            echo "REDIS_WRITEONLY_PASSWORD=$NEW_WRITEONLY_PASSWORD" >> "$temp_file"
            writeonly_found=true
        elif [[ "$line" =~ ^REDIS_EXPORTER_PASSWORD= ]]; then
            echo "REDIS_EXPORTER_PASSWORD=$NEW_EXPORTER_PASSWORD" >> "$temp_file"
            exporter_found=true
        else
            echo "$line" >> "$temp_file"
        fi
    done < .env

    # Output messages for encryption keys
    echo "Define .env's Secure Encryption Key"
    if [ "$key_found" = false ]; then
        echo "ENCRYPTION_KEY=$NEW_KEY" >> "$temp_file"
        echo "Added new encryption key"
    else
        echo "Updated encryption key"
    fi
    echo ""

    echo "Define .env's Secure Encryption Salt"
    if [ "$salt_found" = false ]; then
        echo "ENCRYPTION_SALT=$NEW_SALT" >> "$temp_file"
        echo "Added new encryption salt"
    else
        echo "Updated encryption salt"
    fi
    echo ""

    # Add Redis passwords if not found
    if [ "$admin_found" = false ]; then
        echo "REDIS_ADMIN_PASSWORD=$NEW_ADMIN_PASSWORD" >> "$temp_file"
        echo "Added new Redis admin password"
    else
        echo "Updated Redis admin password"
    fi
    echo ""

    if [ "$readonly_found" = false ]; then
        echo "REDIS_READONLY_PASSWORD=$NEW_READONLY_PASSWORD" >> "$temp_file"
        echo "Added new Redis readonly password"
    else
        echo "Updated Redis readonly password"
    fi
    echo ""


    if [ "$writeonly_found" = false ]; then
        echo "REDIS_WRITEONLY_PASSWORD=$NEW_WRITEONLY_PASSWORD" >> "$temp_file"
        echo "Added new Redis writeonly password"
    else
        echo "Updated Redis writeonly password"
    fi
    echo ""

    if [ "$exporter_found" = false ]; then
        echo "REDIS_EXPORTER_PASSWORD=$NEW_EXPORTER_PASSWORD" >> "$temp_file"
        echo "Added new Redis exporter password"
    else
        echo "Updated Redis exporter password"
    fi
    echo ""

    # Replace original .env with updated version
    mv "$temp_file" .env

    # Start services with docker-compose
    docker-compose up -d

    echo "Pre-production environment started successfully."
    echo "Vulnerable Redis: ${VULNERABLE_DOMAIN}:${VULNERABLE_REDIS_PORT}"
    echo "Secure Redis: ${SECURE_DOMAIN}:${SECURE_REDIS_PORT}"
    echo "Redis Proxy: ${SECURE_DOMAIN}:${REDIS_PROXY_PORT}"
    echo "Monitoring: http://${MONITORING_DOMAIN}"
    echo ""
    echo "IP whitelisting is active. Only ${AWS_ATTACKER_IP} can access Redis ports."

else
    echo "No valid mode specified. Use -d for development or -p for pre-production"
    show_help
    exit 1
fi