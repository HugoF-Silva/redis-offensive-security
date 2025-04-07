FROM redis:6.2

COPY redis.conf /usr/local/etc/redis/redis.conf
COPY init_data.sh /usr/local/bin/init_data.sh

RUN chmod +x /usr/local/bin/init_data.sh

CMD ["sh", "-c", "/usr/local/bin/init_data.sh && redis-server /usr/local/etc/redis/redis.conf"]