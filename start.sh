#!/bin/bash
# Start nginx to serve PAC file, then start Squid in foreground
squid -z --foreground

nginx
squid -N -d 1
