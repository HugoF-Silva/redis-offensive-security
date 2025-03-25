FROM redis:6.2

RUN apt-get update && \
    apt-get install -y python3 python3-pip python3-venv jq && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip
RUN pip3 install cryptography redis

RUN mkdir -p /usr/local/etc/redis/tls /usr/local/etc/redis/acl

COPY redis.conf /usr/local/etc/redis/redis.conf
COPY acl/users.acl.template /usr/local/etc/redis/acl/
COPY sample-data.json /usr/local/bin/
COPY encrypt.py /usr/local/bin/
COPY populate.py /usr/local/bin/
COPY entrypoint.sh /usr/local/bin/

RUN chmod +x /usr/local/bin/encrypt.py
RUN chmod +x /usr/local/bin/populate.py
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]