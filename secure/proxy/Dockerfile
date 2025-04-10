FROM nginx:alpine

COPY nginx.conf /etc/nginx/nginx.conf

RUN mkdir -p /docker-entrypoint.d

# Create custom entrypoint script that doesn't try to modify config files
RUN printf '#!/bin/sh\necho "Starting nginx..."\nnginx -g "daemon off;"\n' > /docker-entrypoint.sh && \
    chmod +x /docker-entrypoint.sh

# Create nginx user and update permissions
RUN touch /var/run/nginx.pid && \
    mkdir -p /var/cache/nginx && \
    chown -R nginx:nginx /var/run/nginx.pid && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /docker-entrypoint.sh && \
    chown -R nginx:nginx /docker-entrypoint.d

# Switch to non-root user
USER nginx

EXPOSE 8080

CMD ["/docker-entrypoint.sh"]