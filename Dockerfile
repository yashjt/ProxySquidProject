FROM ubuntu/squid:latest

COPY squid.conf /etc/squid/squid.conf

RUN mkdir -p /var/log/squid /var/spool/squid \
    && chown -R proxy:proxy /var/log/squid /var/spool/squid

EXPOSE 3128

CMD ["squid", "-N", "-d", "1"]