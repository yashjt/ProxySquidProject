#!/bin/bash

# Fix helper script permissions (volume mount overrides Dockerfile chmod)
chmod +x /usr/local/bin/squid_helper.py
chown proxy:proxy /usr/local/bin/squid_helper.py

# Initialize Squid cache directories
squid -z --foreground

# Start nginx for PAC file
nginx

# Start Squid in foreground
squid -N -d 1