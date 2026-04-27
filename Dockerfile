FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    squid \
    python3 \
    python3-psycopg2 \
    nginx \
    && rm -rf /var/lib/apt/lists/*

RUN usermod -s /bin/bash proxy

COPY squid.conf /etc/squid/squid.conf
COPY squid_helper.py /usr/local/bin/squid_helper.py
COPY proxy.pac /var/www/pac/proxy.pac
COPY start.sh /start.sh
COPY web_classifier.py /usr/local/bin/web_classifier.py

RUN chmod 755 /usr/local/bin/squid_helper.py /start.sh && \
    chown proxy:proxy /usr/local/bin/squid_helper.py

RUN mkdir -p /var/log/squid /var/spool/squid /var/www/pac && \
    chown -R proxy:proxy /var/log/squid /var/spool/squid && \
    touch /var/log/squid/categorizer.log && \
    chmod 666 /var/log/squid/categorizer.log

RUN echo 'server { listen 8080; root /var/www/pac; }' > /etc/nginx/sites-enabled/default

CMD ["/start.sh"]