#!/usr/bin/env python3

#  squid_helper.py  —  Squid External ACL Helper
#
#  PURPOSE:
#  This script is the decision engine of the proxy.
#  Squid spawns it as a child process when it starts up,
#  and communicates with it through stdin/stdout using a
#  simple text protocol:
#
#    Squid → helper (via stdin):   "facebook.com"
#    helper → Squid (via stdout):  "ERR"
#
#    Squid → helper (via stdin):   "bet365.com"
#    helper → Squid (via stdout):  "OK"
#
#  THE PROTOCOL (very important to understand):
#    OK  = "this ACL condition is TRUE"  = Squid will BLOCK the request
#    ERR = "this ACL condition is FALSE" = Squid will ALLOW the request
#
#  This is counterintuitive but it is the Squid standard.
#  In squid.conf we have: "http_access deny blocked_url"
#  blocked_url ACL fires when helper returns OK → request denied.
#
#  CRITICAL RULE:
#  NEVER print anything to stdout except "OK" or "ERR".
#  If any other text reaches stdout, Squid reads it as a malformed
#  response and kills the helper process. All debugging goes to
#  the log FILE instead.
#



import sys      # sys.stdin to read domains, sys.stderr for fallback logging
import os       # os.environ to read DB credentials
import logging  # write timestamped log messages to a file
import psycopg2 # PostgreSQL database driver
from datetime import datetime  # track time for periodic cache checks


#  Logging Setup 
# We MUST write logs to a file (not stdout) because stdout is reserved
# for communicating with Squid. Even a single extra character on stdout
# would corrupt the protocol and cause Squid to kill the helper.
#
# We try to open the log file first. If it fails (e.g. permissions issue),
# we fall back to stderr, which Docker captures in "docker compose logs squid".

log_file = '/var/log/squid/categorizer.log'
handlers = []

try:
    handlers.append(logging.FileHandler(log_file))
except Exception:
    # Could not open the log file — fall back to stderr
    handlers.append(logging.StreamHandler(sys.stderr))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=handlers
)
log = logging.getLogger(__name__)


#  Database Configuration 
# Credentials are passed as environment variables in docker-compose.yml.
# os.environ.get(key, default) reads the variable or uses the default
# if the variable is not set — useful for running locally without Docker.
DB_CONFIG = {
    'host':            os.environ.get('DB_HOST', 'postgres'),
    'dbname':          os.environ.get('DB_NAME', 'squid_categories'),
    'user':            os.environ.get('DB_USER', 'squid'),
    'password':        os.environ.get('DB_PASSWORD', 'squidpass'),
    'connect_timeout': 5,   # give up connecting after 5 seconds
}


#  In-Memory Cache 
# This is a simple Python dictionary that maps domain names to their
# Squid responses ('OK' or 'ERR').
#
# Example after processing a few requests:
#   _cache = {
#       'facebook.com': 'ERR',   # allowed (social_networks not blocked)
#       'bet365.com':   'OK',    # blocked (gambling)
#       'google.com':   'ERR',   # allowed (search_engine not blocked)
#   }
#
# Why use this?
# Without caching, every single HTTP request would cause a PostgreSQL
# query. A single page load can trigger 50-100 requests (for images,
# scripts, fonts, etc.). That is thousands of DB queries per minute.
# The cache reduces this to one query per unique domain.
#
# CACHE_MAX prevents the dict from growing forever in long-running sessions.
_cache = {}
CACHE_MAX = 10000

#  Cache Version Tracking 
# When a user toggles a category in the Flask UI, Flask increments the
# version number in the cache_version database table.
#
# This script reads that number every 30 seconds. If it changed,
# we clear _cache and reload blocked_categories from the DB.
# This ensures new blocking rules apply within 30 seconds.
#
# Without this mechanism, cached results would keep old rules
# indefinitely and category toggles would have no effect.
_known_cache_version = 0   # The last version number we read from the DB


#  Database Connection 
def get_db_connection():
    """Open and return a new connection to PostgreSQL."""
    return psycopg2.connect(**DB_CONFIG)


#  Load Blocked Categories 
def get_blocked_categories(conn):
    """
    Fetch all category names where enabled = TRUE from the DB.

    Example return value:
      {'gambling', 'adult', 'malware', 'phishing'}
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT category FROM blocked_categories WHERE enabled = TRUE"
        )
        # Build a set from the query results
        # cur.fetchall() returns: [('gambling',), ('adult',), ...]
        # row[0] extracts just the string from each tuple
        return {row[0] for row in cur.fetchall()}


#  Cache Version Check 
def get_cache_version(conn):
    """
    Read the current version number from the cache_version table.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT version FROM cache_version WHERE id = 1")
        row = cur.fetchone()
        return row[0] if row else 0


#  Domain Lookup 
def lookup_domain(conn, domain, blocked_cats):
    """
    Look up a domain in the url_categories table.

    SUBDOMAIN MATCHING:
    We don't just search for the exact domain. We also try progressively
    shorter versions by stripping subdomains one level at a time.

    Example for "mail.google.com":
      Attempt 1: query for "mail.google.com" → not found
      Attempt 2: query for "google.com" → found! category = search_engine

    This means adding "google.com" to the DB automatically covers
    maps.google.com, mail.google.com, drive.google.com, etc.

    Arguments:
      conn         - open database connection
      domain       - cleaned domain string, e.g. "mail.google.com"
      blocked_cats - set of currently blocked category names

    Returns:
      (action, category) where action is 'DENY' or 'ALLOW'
    """
    # Split domain into parts: "mail.google.com" → ["mail", "google", "com"]
    parts = domain.split('.')

    # Try each progressively shorter candidate
    # range(len(parts) - 1) stops before trying just "com" alone
    for i in range(len(parts) - 1):
        candidate = '.'.join(parts[i:])  # rejoin from position i onward

        with conn.cursor() as cur:
            cur.execute(
                "SELECT category FROM url_categories WHERE domain = %s LIMIT 1",
                (candidate,)
            )
            row = cur.fetchone()

            if row:
                category = row[0]
                # Check if this category is currently enabled for blocking
                action = 'DENY' if category in blocked_cats else 'ALLOW'
                return action, category

    # Domain was not found in the database at all
    return 'ALLOW', 'uncategorized'


#  Log Uncategorized Domains 
def log_uncategorized(conn, domain):
    """
    Record that we saw a domain not in our database.
    The Flask UI shows these in the "Uncategorized" page for manual review.

    Uses INSERT ON CONFLICT so we just increment the hit_count
    if we've seen this domain before, rather than inserting a duplicate.
    """
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO uncategorized_urls (domain, first_seen, last_seen, hit_count)
                VALUES (%s, NOW(), NOW(), 1)
                ON CONFLICT (domain)
                DO UPDATE SET
                    last_seen  = NOW(),
                    hit_count  = uncategorized_urls.hit_count + 1
            """, (domain,))
        conn.commit()
    except Exception as e:
        conn.rollback()
        log.warning(f"Could not log uncategorized domain {domain}: {e}")


#  Log Every Request 
def log_request(conn, domain, category, action):
    """
    Write a record to request_log for every request Squid processes.
    This powers the logs page and dashboard charts in the Flask UI.
    """
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO request_log (domain, category, action) VALUES (%s, %s, %s)",
                (domain, category, action)
            )
        conn.commit()
    except Exception as e:
        conn.rollback()
        log.warning(f"Could not write request log for {domain}: {e}")


#  Response Translation 
def squid_response(action):
    """
    Translate our internal 'DENY'/'ALLOW' decision into
    Squid's external ACL protocol response.

    In squid.conf:  "http_access deny blocked_url"
    The blocked_url ACL fires when this helper returns OK.
    So returning OK causes Squid to BLOCK the request.

    Returning ERR means "this ACL did not match" — Squid falls through
    to the next rule, which is "http_access allow all" → request allowed.

    DENY action  → return 'OK'  → Squid blocks  
    ALLOW action → return 'ERR' → Squid allows  
    """
    return 'OK' if action == 'DENY' else 'ERR'


# Main Processing Loop 
def main():
    """
    The main loop. Runs forever, reading one domain per line from stdin
    and writing one response per line to stdout.

    Squid keeps this process alive for the entire time it is running.
    If this process dies, Squid logs a warning and starts a new one.
    """
    # These are declared global so we can reassign them inside the loop
    global _cache, _known_cache_version

    conn = None           # database connection
    blocked_cats = set()  # set of currently blocked category names
    last_version_check = None  # timestamp of last cache_version DB check

    #  Connect to database on startup 
    try:
        conn = get_db_connection()
        blocked_cats = get_blocked_categories(conn)
        _known_cache_version = get_cache_version(conn)
        last_version_check = datetime.now()
        log.info(f"Connected to DB. Blocked categories: {blocked_cats}")
    except Exception as e:
        # DB unavailable — log the error and continue.
        # We will allow all traffic until DB is reachable (fail-open).
        log.error(f"DB connection failed: {e}. Defaulting to ALLOW for all.")

    #  Process one domain per line forever 
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue   # skip empty lines

        #  Clean the domain 
        # Squid sends things like "facebook.com:443" for HTTPS requests.
        # We need to strip the port number and lowercase everything.
        #
        # .split()[0]   → take only the first word (handles extra whitespace)
        # .split(':')[0] → take only the part before the colon (strips port)
        # .strip()       → remove any remaining whitespace
        domain = line.lower().split()[0].split(':')[0].strip()

        #  Periodic cache version check 
        # Every 30 seconds, query the DB to see if a category was toggled in the UI.
        # If the version number changed, clear _cache and reload blocked categories.
        # This is how category changes propagate to Squid within 30 seconds.
        if conn and last_version_check:
            seconds_since_check = (datetime.now() - last_version_check).total_seconds()

            if seconds_since_check > 30:
                try:
                    current_version = get_cache_version(conn)

                    if current_version != _known_cache_version:
                        # Version changed — a toggle was flipped in the UI
                        log.info(
                            f"Cache version changed "
                            f"({_known_cache_version} → {current_version}). "
                            f"Clearing cache and reloading blocked categories."
                        )
                        # Wipe entire cache so all domains are re-evaluated
                        _cache = {}
                        # Reload which categories are now blocked
                        blocked_cats = get_blocked_categories(conn)
                        _known_cache_version = current_version

                    last_version_check = datetime.now()

                except Exception as e:
                    log.warning(f"Could not check cache version: {e}")

        #  Check in-memory cache 
        # If we have already looked up this domain, return the cached result.
        # This avoids a DB round trip for frequently visited domains.
        if domain in _cache:
            print(_cache[domain], flush=True)   # flush=True ensures Squid gets it immediately
            continue

        #  Fail open if DB is unavailable 
        # If we cannot reach the database, allow all traffic rather than
        # blocking everything. "Fail open" is safer for a proxy —
        # blocking all traffic would completely break internet access.
        if not conn:
            print('ERR', flush=True)
            continue

        #  Normal lookup flow 
        try:
            # Reconnect if the connection dropped (DB restart, timeout, etc.)
            if conn.closed:
                conn = get_db_connection()

            # Query the DB for this domain's category
            action, category = lookup_domain(conn, domain, blocked_cats)

            # If not in our DB, record it for the uncategorized review page
            if category == 'uncategorized':
                log_uncategorized(conn, domain)

            # Write to request_log for the dashboard
            log_request(conn, domain, category, action)

            # Write to the categorizer log file for debugging
            log.info(f"{domain} → {category} → {action}")

            # Translate action to Squid's OK/ERR protocol
            response = squid_response(action)

            # Cache the result (but cap cache size to avoid memory exhaustion)
            if len(_cache) < CACHE_MAX:
                _cache[domain] = response

            # Send the response to Squid — this MUST be the only output to stdout
            print(response, flush=True)

        except Exception as e:
            log.error(f"Error processing {domain}: {e}")
            # Try to reconnect for the next request
            try:
                conn = get_db_connection()
            except Exception:
                conn = None
            # Fail open — allow this request rather than breaking browsing
            print('ERR', flush=True)


#  Entry Point 
# This block only runs when you execute the file directly.
# It does NOT run when the file is imported as a module.
if __name__ == '__main__':
    main()