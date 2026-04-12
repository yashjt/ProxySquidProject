FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    squid \
    python3 \
    python3-pip \
    python3-psycopg2 \
    nginx \
    && rm -rf /var/lib/apt/lists/*

COPY squid.conf /etc/squid/squid.conf
COPY squid_helper.py /usr/local/bin/squid_helper.py
RUN chmod +x /usr/local/bin/squid_helper.py

RUN echo 'server { listen 8080; location / { root /var/www/pac; } }' \
    > /etc/nginx/sites-available/pac && \
    ln -sf /etc/nginx/sites-available/pac /etc/nginx/sites-enabled/pac && \
    rm -f /etc/nginx/sites-enabled/default

RUN mkdir -p /var/log/squid /var/spool/squid /var/www/pac \
    && chown -R proxy:proxy /var/log/squid /var/spool/squid

COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 3128 8080

CMD ["/start.sh"]