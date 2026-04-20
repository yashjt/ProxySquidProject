#!/usr/bin/env python3

#  What this script does 
# Squid proxy calls this script for every domain a user tries to visit.
# We look the domain up in our database, decide DENY or ALLOW,
# then print a one-word response that Squid reads from stdout.
#
# How Squid talks to this script:
#   Squid writes a domain to our stdin  →  facebook.com:443
#   We print a response to stdout       →  OK  (block it)  or  ERR  (allow it)
#
# Why OK means block and ERR means allow (counter-intuitive but correct):
#   Squid has a rule called "blocked_url" that fires when this script says OK.
#   If the ACL fires → Squid blocks the request.
#   If we say ERR   → the ACL does not fire → Squid allows the request.

import sys       # sys.stdin  — read domains from Squid
                 # sys.stderr — fallback logging destination
import os        # os.environ — read DB credentials from environment variables
import logging   # write timestamped log messages to a file
import psycopg2  # PostgreSQL database driver
from datetime import datetime


#  LOGGING SETUP
#  Try to write logs to a file. If the file can't be created (e.g. wrong
#  permissions), fall back to stderr so we never crash on startup.


LOG_FILE_PATH = '/var/log/squid/categorizer.log'

log_handlers = []

try:
    # Try the log file first
    log_handlers.append(logging.FileHandler(LOG_FILE_PATH))
except Exception:
    # If that fails, write to stderr instead
    log_handlers.append(logging.StreamHandler(sys.stderr))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=log_handlers
)

# 'log' is the logger object we use throughout the file
log = logging.getLogger(__name__)


#  DATABASE CONFIGURATION
#  Credentials are read from environment variables set in docker-compose.yml.
#  The second argument to .get() is the fallback if the variable isn't set.


DB_CONFIG = {
    'host':            os.environ.get('DB_HOST',     'postgres'),
    'dbname':          os.environ.get('DB_NAME',     'squid_categories'),
    'user':            os.environ.get('DB_USER',     'squid'),
    'password':        os.environ.get('DB_PASSWORD', 'squidpass'),
    'connect_timeout': 5,   # give up after 5 seconds if DB is unreachable
}


#  IN-MEMORY CACHE
#  Squid may send thousands of requests per minute.
#  Hitting the database for every single one would be very slow.
#  Instead we remember results in a dictionary: { "facebook.com": "OK" }
#  and skip the DB lookup when we see the same domain again.
#  The cache is cleared automatically when an admin toggles a category
#  in the web UI (detected via the cache_version table).


domain_cache     = {}    # { domain_string: "OK" or "ERR" }
CACHE_SIZE_LIMIT = 10000  # stop caching after this many entries to save memory

# We check the database every 30 seconds to see if an admin changed any rules.
# This number tracks which version we last saw. If it changes, we clear the cache.
last_known_cache_version = 0

#  DATABASE HELPER FUNCTIONS

def open_db_connection():
    """
    Opens and returns a new PostgreSQL connection using DB_CONFIG.
    Called once at startup and again if the connection drops.
    """
    return psycopg2.connect(**DB_CONFIG)


def fetch_blocked_categories(conn):
    """
    Returns a Python set of category names that are currently set to block.
    Example return value: {"ads", "malware", "gambling"}

    A set is used (not a list) because checking "if category in blocked_cats"
    is much faster with a set than with a list.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT category FROM blocked_categories WHERE enabled = TRUE"
        )
        all_rows      = cur.fetchall()
        category_set  = {row[0] for row in all_rows}  # build a set from the results
        return category_set


def fetch_cache_version(conn):
    """
    Returns the current version number from the cache_version table.
    The Flask web UI increments this number every time an admin toggles a category.
    We compare this to last_known_cache_version to detect changes.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT version FROM cache_version WHERE id = 1")
        row = cur.fetchone()

        if row:
            return row[0]   # return the version number
        else:
            return 0        # table is empty — treat as version 0


def find_domain_in_db(conn, domain, blocked_categories):
    """
    Looks up a domain in the url_categories table and decides the action.

    We try the full domain first, then progressively strip subdomains:
      mail.google.com  → try this first
      google.com       → try this second
      (com is only one part, so we stop there)

    Returns a tuple: (action, category)
      action   — "DENY" or "ALLOW"
      category — e.g. "search_engines", or "uncategorized" if not found
    """
    # Split the domain into parts: "mail.google.com" → ["mail", "google", "com"]
    domain_parts = domain.split('.')

    # Try each progressively shorter version of the domain
    for i in range(len(domain_parts) - 1):

        # Rejoin from position i onward: i=0 → "mail.google.com", i=1 → "google.com"
        candidate_domain = '.'.join(domain_parts[i:])

        with conn.cursor() as cur:
            cur.execute(
                "SELECT category FROM url_categories WHERE domain = %s LIMIT 1",
                (candidate_domain,)
            )
            row = cur.fetchone()

        # If we found a match, decide the action based on the category
        if row:
            matched_category = row[0]

            if matched_category in blocked_categories:
                return 'DENY', matched_category   # category is on the block list
            else:
                return 'ALLOW', matched_category  # category exists but isn't blocked

    # Domain wasn't found in any form — return uncategorized
    return 'ALLOW', 'uncategorized'


def record_uncategorized_domain(conn, domain):
    """
    Records a domain we couldn't find in the database.
    If we've seen it before, just increment its hit counter and update last_seen.
    If it's brand new, insert a fresh row.
    This populates the "Uncategorized" page in the web UI.
    """
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO uncategorized_urls (domain, first_seen, last_seen, hit_count)
                VALUES (%s, NOW(), NOW(), 1)
                ON CONFLICT (domain)
                DO UPDATE SET
                    last_seen = NOW(),
                    hit_count = uncategorized_urls.hit_count + 1
            """, (domain,))
        conn.commit()

    except Exception as error:
        conn.rollback()   # undo the failed insert so the DB stays consistent
        log.warning('Could not record uncategorized domain ' + domain + ': ' + str(error))


def record_request_log(conn, domain, category, action):
    """
    Writes one row to the request_log table for every domain Squid processes.
    This is what powers the Dashboard charts and the Logs page.
    """
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO request_log (domain, category, action) VALUES (%s, %s, %s)",
                (domain, category, action)
            )
        conn.commit()

    except Exception as error:
        conn.rollback()
        log.warning('Could not write request log for ' + domain + ': ' + str(error))

#  SQUID PROTOCOL HELPER
def build_squid_response(action):
    """
    Converts our internal "DENY"/"ALLOW" decision into the word Squid expects.

    Squid's external ACL protocol:
      OK  → the ACL condition is TRUE  → Squid blocks the request
      ERR → the ACL condition is FALSE → Squid allows the request

    This seems backwards but it's just how Squid's ACL system works.
    """
    if action == 'DENY':
        return 'OK'   # Tell Squid: yes, this matches the block rule
    else:
        return 'ERR'  # Tell Squid: no match, let it through

#  MAIN LOOP
#  Squid keeps this script running as a long-lived process.
#  It sends one domain per line to stdin.
#  We print one response per line to stdout.

def main():
    # These are declared global so the helper loop below can modify them
    global domain_cache, last_known_cache_version

    #  Step 1: Connect to the database on startup 
    db_connection   = None
    blocked_cats    = set()          # set of category names to block
    last_check_time = None           # when we last checked for rule changes

    try:
        db_connection   = open_db_connection()
        blocked_cats    = fetch_blocked_categories(db_connection)
        last_known_cache_version = fetch_cache_version(db_connection)
        last_check_time = datetime.now()
        log.info('Connected to DB. Blocking categories: ' + str(blocked_cats))

    except Exception as error:
        # If the DB is down at startup, log the error and keep running.
        # We'll fail open (allow everything) until a connection is available.
        log.error('DB connection failed: ' + str(error) + '. Allowing all traffic by default.')


    #  Step 2: Process one domain per line from Squid 
    for raw_line in sys.stdin:

        # Clean up the line Squid sent
        line = raw_line.strip()
        if not line:
            continue  # skip empty lines

        # Squid may send "facebook.com:443" — we only need the hostname part
        raw_domain = line.lower().split()[0]          # take the first word
        domain     = raw_domain.split(':')[0].strip() # remove the port number


        #  Step 3: Check if admin changed any rules (every 30 seconds) 
        # We don't want to check the DB on every single request — that would
        # be too slow. Instead we check once every 30 seconds.
        if db_connection and last_check_time:

            seconds_elapsed = (datetime.now() - last_check_time).total_seconds()

            if seconds_elapsed > 30:
                try:
                    current_version = fetch_cache_version(db_connection)

                    if current_version != last_known_cache_version:
                        # The version number changed — an admin flipped a toggle
                        log.info(
                            'Rules changed (version ' +
                            str(last_known_cache_version) + ' → ' +
                            str(current_version) +
                            '). Clearing cache and reloading rules.'
                        )
                        domain_cache             = {}   # wipe the entire cache
                        blocked_cats             = fetch_blocked_categories(db_connection)
                        last_known_cache_version = current_version

                    last_check_time = datetime.now()

                except Exception as error:
                    log.warning('Could not check for rule changes: ' + str(error))


        #  Step 4: Return cached result if we've seen this domain before 
        if domain in domain_cache:
            print(domain_cache[domain], flush=True)
            continue  # skip everything below, go to next line


        #  Step 5: If DB is down, fail open (allow all) 
        if not db_connection:
            print('ERR', flush=True)
            continue


        #  Step 6: Look up the domain and send Squid a response 
        try:
            # Reconnect if the connection was lost
            if db_connection.closed:
                db_connection = open_db_connection()

            # Check the database for this domain
            action, category = find_domain_in_db(db_connection, domain, blocked_cats)

            # Record unknown domains so admins can review them in the UI
            if category == 'uncategorized':
                record_uncategorized_domain(db_connection, domain)

            # Write to the audit log (powers Dashboard + Logs page)
            record_request_log(db_connection, domain, category, action)

            log.info(domain + ' → ' + category + ' → ' + action)

            # Convert DENY/ALLOW to OK/ERR for Squid
            squid_word = build_squid_response(action)

            # Save to cache so we skip the DB next time this domain appears
            if len(domain_cache) < CACHE_SIZE_LIMIT:
                domain_cache[domain] = squid_word

            # Send the response to Squid (must flush immediately)
            print(squid_word, flush=True)

        except Exception as error:
            log.error('Error processing domain ' + domain + ': ' + str(error))

            # Try to reconnect to the DB for the next request
            try:
                db_connection = open_db_connection()
            except Exception:
                db_connection = None  # give up for now, try again next request

            # Fail open: allow the request so users aren't blocked by a DB error
            print('ERR', flush=True)


#  Entry point 
# Python runs this block when the script is executed directly.
if __name__ == '__main__':
    main()