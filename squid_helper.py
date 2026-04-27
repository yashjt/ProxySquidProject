#!/usr/bin/env python3
# ============================================================
#  squid_helper.py  —  Squid External ACL Helper
#                      (with auto web classification)
#
#  NEW in this version:
#  When a domain is NOT in the url_categories database,
#  instead of just logging it as "uncategorized", we now:
#    1. Call web_classifier.classify_domain(domain)
#    2. Fetch the page, extract content, score against keywords
#    3. Get a category back (e.g. "news", "technology")
#    4. Save it to url_categories in PostgreSQL
#    5. Apply the category to the allow/block decision immediately
#
#  This runs in a background thread so it does NOT slow down
#  the Squid response. The first visit is decided as
#  "uncategorized → ALLOW", then classification runs async.
#  The SECOND visit uses the now-stored category.
# ============================================================

import sys
import os
import logging
import threading          # NEW: run classification in background thread
import psycopg2
from datetime import datetime

# Import our web classifier module (must be in the same folder)
try:
    from web_classifier import classify_domain
    CLASSIFIER_AVAILABLE = True
except ImportError:
    CLASSIFIER_AVAILABLE = False
    # If the module is missing, we just fall back to old behaviour


# ── Logging ────────────────────────────────────────────────────────────────────
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


# ── Database config ────────────────────────────────────────────────────────────
DB_CONFIG = {
    'host':            os.environ.get('DB_HOST', 'postgres'),
    'dbname':          os.environ.get('DB_NAME', 'squid_categories'),
    'user':            os.environ.get('DB_USER', 'squid'),
    'password':        os.environ.get('DB_PASSWORD', 'squidpass'),
    'connect_timeout': 5,
}

# In-memory cache: domain → Squid response ('OK' = block, 'ERR' = allow)
_cache = {}
CACHE_MAX = 10000

# Tracks cache version for real-time toggle updates
_known_cache_version = 0

# Set of domains currently being classified in background threads.
# Prevents launching multiple classification jobs for the same domain.
_classifying_in_progress = set()


# ── Database helpers ───────────────────────────────────────────────────────────

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)


def get_blocked_categories(conn):
    """Returns set of category names where enabled = TRUE."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT category FROM blocked_categories WHERE enabled = TRUE"
        )
        return {row[0] for row in cur.fetchall()}


def get_cache_version(conn):
    """Returns the current cache version number."""
    with conn.cursor() as cur:
        cur.execute("SELECT version FROM cache_version WHERE id = 1")
        row = cur.fetchone()
        return row[0] if row else 0


def lookup_domain(conn, domain, blocked_cats):
    """
    Tries exact match then progressive subdomain stripping.
    e.g. mail.google.com → google.com
    Returns (action, category).
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


def save_classification(domain, category):
    """
    Save a newly classified domain to url_categories.
    Called from the background classification thread.
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO url_categories (domain, category, source)
            VALUES (%s, %s, 'auto_classified')
            ON CONFLICT (domain)
            DO UPDATE SET
                category = EXCLUDED.category,
                source   = 'auto_classified'
        """, (domain, category))

        # Also update the uncategorized_urls record if it exists
        cur.execute("""
            UPDATE uncategorized_urls
            SET category = %s
            WHERE domain = %s
        """, (category, domain))

        conn.commit()
        conn.close()

        log.info(f"Auto-classified and saved: {domain} → {category}")

    except Exception as e:
        log.error(f"Could not save classification for {domain}: {e}")


def log_uncategorized(conn, domain):
    """Records an unknown domain in uncategorized_urls for review."""
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
        log.warning(f"Could not log uncategorized {domain}: {e}")


def log_request(conn, domain, category, action):
    """Writes every request to request_log for the dashboard."""
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


def squid_response(action):
    """
    Translates action to Squid protocol.
    DENY → OK  (blocked_url ACL matches → Squid blocks)
    ALLOW → ERR (ACL does not match → Squid allows)
    """
    return 'OK' if action == 'DENY' else 'ERR'


# ── Background classification ──────────────────────────────────────────────────

def classify_in_background(domain, blocked_cats):
    """
    Runs web_classifier in a background thread.

    WHY BACKGROUND?
    Fetching and analysing a webpage takes 1-3 seconds.
    Squid cannot wait that long — it would make the browser hang.

    So for the FIRST visit to an unknown domain:
      - We immediately return ALLOW (or DENY if uncategorized default is deny)
      - We start this background thread to classify the site
      - The result is saved to the database
      - The SECOND visit uses the stored category and is instant

    Arguments:
        domain       — the domain to classify
        blocked_cats — current set of blocked categories (to decide on next visit)
    """
    try:
        # Prevent duplicate classification jobs for the same domain
        if domain in _classifying_in_progress:
            return
        _classifying_in_progress.add(domain)

        log.info(f"Starting background classification for: {domain}")

        # Run the classifier (1-3 seconds)
        category = classify_domain(domain)

        # Save to database
        save_classification(domain, category)

        # Update the in-memory cache with the new result
        # So the very next request uses the real category
        action   = 'DENY' if category in blocked_cats else 'ALLOW'
        response = squid_response(action)
        if len(_cache) < CACHE_MAX:
            _cache[domain] = response

        log.info(f"Background classification done: {domain} → {category} → {action}")

    except Exception as e:
        log.error(f"Background classification failed for {domain}: {e}")

    finally:
        # Always remove from the in-progress set when done
        _classifying_in_progress.discard(domain)


# ── Main loop ──────────────────────────────────────────────────────────────────

def main():
    global _cache, _known_cache_version

    conn = None
    blocked_cats = set()
    last_version_check = None

    # Connect on startup
    try:
        conn = get_db_connection()
        blocked_cats = get_blocked_categories(conn)
        _known_cache_version = get_cache_version(conn)
        last_version_check = datetime.now()
        log.info(f"Connected to DB. Blocked: {blocked_cats}")
        log.info(f"Web classifier available: {CLASSIFIER_AVAILABLE}")
    except Exception as e:
        log.error(f"DB connection failed: {e}")

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue

        # Clean domain — strip port and whitespace
        domain = line.lower().split()[0].split(':')[0].strip()

        # ── Periodic cache version check ──────────────────────
        # If a toggle was flipped in the UI, clear cache and reload rules
        if conn and last_version_check:
            elapsed = (datetime.now() - last_version_check).total_seconds()
            if elapsed > 30:
                try:
                    current_version = get_cache_version(conn)
                    if current_version != _known_cache_version:
                        log.info(
                            f"Cache version changed "
                            f"({_known_cache_version} → {current_version}). "
                            f"Clearing cache."
                        )
                        _cache = {}
                        blocked_cats = get_blocked_categories(conn)
                        _known_cache_version = current_version
                    last_version_check = datetime.now()
                except Exception as e:
                    log.warning(f"Cache version check failed: {e}")

        # ── Return cached result if available ─────────────────
        if domain in _cache:
            print(_cache[domain], flush=True)
            continue

        # ── Fail open if DB is down ────────────────────────────
        if not conn:
            print('ERR', flush=True)
            continue

        # ── Normal lookup ──────────────────────────────────────
        try:
            if conn.closed:
                conn = get_db_connection()

            action, category = lookup_domain(conn, domain, blocked_cats)

            if category == 'uncategorized':
                # Log it to uncategorized_urls table for the UI
                log_uncategorized(conn, domain)

                # ── NEW: Launch background classification ──────
                # Only if the classifier is available and we are not
                # already classifying this domain
                if CLASSIFIER_AVAILABLE and domain not in _classifying_in_progress:
                    thread = threading.Thread(
                        target=classify_in_background,
                        args=(domain, blocked_cats),
                        daemon=True   # thread dies if main process dies
                    )
                    thread.start()
                    log.info(f"Background classification started for: {domain}")

            log_request(conn, domain, category, action)
            log.info(f"{domain} → {category} → {action}")

            response = squid_response(action)

            if len(_cache) < CACHE_MAX:
                _cache[domain] = response

            print(response, flush=True)

        except Exception as e:
            log.error(f"Error processing {domain}: {e}")
            try:
                conn = get_db_connection()
            except Exception:
                conn = None
            print('ERR', flush=True)


if __name__ == '__main__':
    main()