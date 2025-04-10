FROM redis:6.2

# Install required utilities
RUN apt-get update && apt-get install -y \
    openssl \
    fail2ban \
    iptables \
    apparmor \
    gettext-base \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Create required directories
RUN mkdir -p /var/log/redis \
    /etc/ssl/private \
    /etc/ssl/certs \
    /etc/redis

# Copy configuration files
COPY redis.conf /usr/local/etc/redis/redis.conf
COPY init_data.sh /usr/local/bin/init_data.sh
COPY tls/generate_certs.sh /usr/local/bin/generate_certs.sh
COPY apparmor/redis-profile /etc/apparmor.d/usr.local.bin.redis-server
COPY fail2ban/redis.conf /etc/fail2ban/filter.d/redis.conf
COPY fail2ban/jail.local /etc/fail2ban/jail.local
COPY users.acl /etc/redis/users.acl

# Create SSL directories
RUN mkdir -p /etc/ssl/private /etc/ssl/certs

# Make scripts executable
RUN chmod +x /usr/local/bin/generate_certs.sh && \
    chmod +x /usr/local/bin/init_data.sh

# Generate TLS certificates
RUN /usr/local/bin/generate_certs.sh

# Set proper permissions (now that the files exist)
RUN find /etc/ssl/private -type f -exec chmod 600 {} \; && \
    find /etc/ssl/certs -type f -exec chmod 644 {} \;

# Configure fail2ban
RUN systemctl enable fail2ban || echo "Fail2ban service not started in container"

# Create firewall setup script
RUN printf '#!/bin/bash\nif [ $(id -u) -eq 0 ]; then\n  iptables -A INPUT -p tcp --dport 6379 -s 127.0.0.1 -j ACCEPT\n  iptables -A INPUT -p tcp --dport 6379 -j DROP\n  iptables -A INPUT -p tcp --dport 6380 -s 127.0.0.1 -j ACCEPT\n  iptables -A INPUT -p tcp --dport 6380 -j DROP\n  echo "Firewall rules applied"\nelse\n  echo "Not running as root, skipping firewall setup"\nfi\n' > /usr/local/bin/setup-firewall.sh && \
    chmod +x /usr/local/bin/setup-firewall.sh

# Create a non-root user for Redis (if it doesn't exist)
RUN (id -g redis &>/dev/null || groupadd -r redis) && \
    (id -u redis &>/dev/null || useradd -r -g redis redis)
RUN chown -R redis:redis /var/log/redis /data

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/init_data.sh

# Let's keep redis user for ownership but run as root for firewall
USER root

# Initialize data on startup using our entrypoint
CMD ["/usr/local/bin/docker-entrypoint.sh"]