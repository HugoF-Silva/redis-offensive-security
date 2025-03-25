FROM debian:bullseye-slim

RUN apt-get update && \
    apt-get install -y fail2ban iptables && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY jail.local /etc/fail2ban/jail.local
COPY filter.d/redis-auth.conf /etc/fail2ban/filter.d/redis-auth.conf

CMD ["fail2ban-client", "-f", "start"]