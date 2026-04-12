import os
import sys
import time
import tarfile  # open tar file
import logging
import requests # download file 
import psycopg2 # connect to postgresSql
import psycopg2.extras  
from io import BytesIO # hold download file in memeory 
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    stream=sys.stdout
)
log = logging.getLogger(__name__)


# config
DB_CONFIG = {
    'host':     os.environ.get('DB_HOST', 'postgres'),
    'dbname':   os.environ.get('DB_NAME', 'squid_categories'),
    'user':     os.environ.get('DB_USER', 'squid'),
    'password': os.environ.get('DB_PASSWORD', 'squidpass'),
}

# Categories downlead from UT1 url database 
CATEGORIES_TO_IMPORT = [
    'gambling',
    'adult',
    'malware',
    'phishing',
    'warez',
    'dating',
    'drugs',
    'hacking',
    'social_networks',
    'news',
    'shopping',
    'games',
    'finance',
    'education',
    'health',
    'government',
]
BATCH_SIZE = 1000 # Insert rows in batches for performance 


"""PostgreSQL takes a few seconds to start up. This function tries to connect every 3 seconds, up to 20 times. Without this, the script would crash immediately because it starts before Postgres is ready. """
def wait_for_db(max_retries-20, delay=3):
    for attempt in range(max_retries):
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            conn.close()
            log.info("Database is ready")
            return 
        except psycopg2.OperationalError:
            log.info(f"Waiting for databse to connect {attempt + 1} / {max_retries}")
            time.sleep(delay)
    log.error("Database never became ready")
    sys.exit(1)

"""This function check if a catageroy is already imported """
def already_imported(conn , category: str) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM url_categories WHERE category= %s LIMIT ", (category,)
        )
        return cur.fetchone()[0] > 0


def bulk_insert(conn , rows: list[tuple]):
    with conn.cursor() as cur:
        psycopg2.extras.execute.values(
            cur,
            """
            INSERT INTO url_categories (domain, category)
            VALUES %s
            ON CONFLICT (domain) DO NOTHING
            """,
            rows,
            template="(%s, %s)",
            page_size=BATCH_SIZE
        )
    conn.commit()


# UT1 downloader 
def download_category(category: str) -> list[str]:
    """
    Download a single UT1 category tar.gz and extract the domains file.
    Returns a list of domain strings.
    """
    url = f"{UT1_BASE_URL}/{category}.tar.gz"
    log.info(f"Downloading {category} from {url}")

    try:
        resp = requests.get(url, timeout=60)
        if resp.status_code == 404:
            log.warning(f"Category '{category}' not found on UT1 (404). Skipping.")
            return []
        resp.raise_for_status()
    except requests.RequestException as e:
        log.error(f"Failed to download {category}: {e}")
        return []

    domains = []
    try:
        with tarfile.open(fileobj=BytesIO(resp.content), mode='r:gz') as tar:
            for member in tar.getmembers():
                # Each category tar contains: category/domains and category/urls
                if member.name.endswith('/domains') or member.name == 'domains':
                    f = tar.extractfile(member)
                    if f:
                        content = f.read().decode('utf-8', errors='ignore')
                        for line in content.splitlines():
                            line = line.strip().lower()
                            # Skip empty lines, comments, IPs, wildcards
                            if line and not line.startswith('#') and '/' not in line:
                                domains.append(line)
    except Exception as e:
        log.error(f"Failed to parse tar for {category}: {e}")

    log.info(f"  → {len(domains):,} domains in '{category}'")
    return domains

def main():
    log.info("=" * 60)
    log.info("UT1 Blacklist Importer starting")
    log.info("=" * 60)

    wait_for_db()

    conn = psycopg2.connect(**DB_CONFIG)

    total_imported = 0

    for category in CATEGORIES_TO_IMPORT:
        if already_imported(conn, category):
            log.info(f"[SKIP] '{category}' already in database.")
            continue

        domains = download_category(category)
        if not domains:
            continue

        # Prepare rows as (domain, category) tuples
        rows = [(domain, category) for domain in domains]

        # Insert in batches
        inserted = 0
        for i in range(0, len(rows), BATCH_SIZE):
            batch = rows[i:i + BATCH_SIZE]
            bulk_insert(conn, batch)
            inserted += len(batch)

        log.info(f"[OK] Imported {inserted:,} domains for '{category}'")
        total_imported += inserted

    conn.close()

    log.info("=" * 60)
    log.info(f"Import complete. Total domains imported: {total_imported:,}")
    log.info("=" * 60)


if __name__ == '__main__':
    main()
