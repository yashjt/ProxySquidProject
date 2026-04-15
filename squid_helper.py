#!/usr/bin/env python3

import sys
import os
import logging
import psycopg2
import psycopg2.extras
from datetime import datetime

# ── Logging (to file, not stdout — stdout is reserved for Squid responses) ──
log_file = '/var/log/squid/categorizer.log'
handlers = []

try:
    handlers.append(logging.FileHandler(log_file))
except Exception:
    handlers.append(logging.StreamHandler(sys.stderr))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=handlers
)
log = logging.getLogger(__name__)

# ── Database config from environment variables ──
DB_CONFIG = {
    'host':     os.environ.get('DB_HOST', 'postgres'),
    'dbname':   os.environ.get('DB_NAME', 'squid_categories'),
    'user':     os.environ.get('DB_USER', 'squid'),
    'password': os.environ.get('DB_PASSWORD', 'squidpass'),
    'connect_timeout': 5,
}

# ── In-memory cache to reduce DB hits (domain → squid response) ──
# IMPORTANT: cache stores the Squid protocol value:
#   'OK'  = ACL matched = Squid will BLOCK  (domain is in a blocked category)
#   'ERR' = ACL not matched = Squid will ALLOW (domain is safe)
_cache: dict[str, str] = {}
CACHE_MAX = 10000


def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)


def get_blocked_categories(conn) -> set:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT category FROM blocked_categories WHERE enabled = TRUE"
        )
        return {row[0] for row in cur.fetchall()}


def lookup_domain(conn, domain: str, blocked_cats: set) -> tuple[str, str]:
    """
    Tries exact match first, then strips subdomains one level at a time.
    e.g. mail.google.com → google.com
    Returns (action, category): action is 'DENY' or 'ALLOW'.
    """
    parts = domain.split('.')
    for i in range(len(parts) - 1):
        candidate = '.'.join(parts[i:])
        with conn.cursor() as cur:
            cur.execute(
                "SELECT category FROM url_categories WHERE domain = %s LIMIT 1",
                (candidate,)
            )
            row = cur.fetchone()
            if row:
                category = row[0]
                action = 'DENY' if category in blocked_cats else 'ALLOW'
                return action, category

    return 'ALLOW', 'uncategorized'


def log_uncategorized(conn, domain: str):
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


def log_request(conn, domain: str, category: str, action: str):
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


def squid_response(action: str) -> str:
    """
    Convert internal action to Squid external ACL protocol response.
    Squid's blocked_url ACL fires on OK, so:
      DENY  → OK  (ACL matches → Squid blocks)
      ALLOW → ERR (ACL doesn't match → Squid allows)
    """
    return 'OK' if action == 'DENY' else 'ERR'


def main():
    conn = None
    blocked_cats = set()
    blocked_cats_ts = None

    try:
        conn = get_db_connection()
        blocked_cats = get_blocked_categories(conn)
        blocked_cats_ts = datetime.now()
        log.info(f"Connected to DB. Blocked categories: {blocked_cats}")
    except Exception as e:
        log.error(f"DB connection failed: {e}. Defaulting to ALLOW for all.")

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue

        # Take first word only, strip port (e.g. "facebook.com:443" → "facebook.com")
        domain = line.lower().split()[0].split(':')[0].strip()

        # Refresh blocked categories every 5 minutes
        if conn and blocked_cats_ts:
            if (datetime.now() - blocked_cats_ts).total_seconds() > 300:
                try:
                    blocked_cats = get_blocked_categories(conn)
                    blocked_cats_ts = datetime.now()
                except Exception as e:
                    log.warning(f"Could not refresh blocked categories: {e}")

        # Check in-memory cache first
        if domain in _cache:
            print(_cache[domain], flush=True)
            continue

        # DB unavailable — fail open (allow everything)
        if not conn:
            print('ERR', flush=True)
            continue

        try:
            if conn.closed:
                conn = get_db_connection()

            action, category = lookup_domain(conn, domain, blocked_cats)

            if category == 'uncategorized':
                log_uncategorized(conn, domain)

            log_request(conn, domain, category, action)
            log.info(f"{domain} → {category} → {action}")

            response = squid_response(action)

            # Cache uses the same squid_response value
            if len(_cache) < CACHE_MAX:
                _cache[domain] = response

            print(response, flush=True)

        except Exception as e:
            log.error(f"Error processing domain {domain}: {e}")
            try:
                conn = get_db_connection()
            except Exception:
                conn = None
            print('ERR', flush=True)  # fail open on error


if __name__ == '__main__':
    main()