#  What this script does 
# Downloads domain blocklists from the UT1 Capitole blacklist project and
# saves them into our PostgreSQL database so Squid can use them for filtering.
#
# How it works, step by step:
#   1. Wait until the database is ready to accept connections
#   2. Loop through each category we want (e.g. "gambling", "malware")
#   3. Skip categories that are already in the database (avoid duplicates)
#   4. Download a .tar.gz archive for that category from the UT1 website
#   5. Extract the list of domains from inside the archive
#   6. Insert all domains into the url_categories table in batches


import os        # read environment variables (DB credentials)
import sys       # sys.exit() to stop the script, sys.stdout for logging
import time      # time.sleep() while waiting for the database
import tarfile   # open .tar.gz archive files without saving them to disk
import logging   # write timestamped status messages to the console
import requests  # download files from the internet over HTTP
import psycopg2  # PostgreSQL database driver
import psycopg2.extras  # batch insert helper (execute_values)
from io import BytesIO   # treat downloaded bytes as a file-like object


#  LOGGING SETUP
#  Writes timestamped messages to stdout so Docker can capture them.
#  Example output:  2024-01-15 10:23:01 INFO Downloading gambling from ...


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    stream=sys.stdout
)
log = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

# Database credentials — read from environment variables set in docker-compose.yml
DB_CONFIG = {
    'host':     os.environ.get('DB_HOST',     'postgres'),
    'dbname':   os.environ.get('DB_NAME',     'squid_categories'),
    'user':     os.environ.get('DB_USER',     'squid'),
    'password': os.environ.get('DB_PASSWORD', 'squidpass'),
}

# The list of categories we want to import from the UT1 blacklist project.
# Each name must match a folder name on the UT1 download server exactly.
CATEGORIES_TO_IMPORT = [
    'gambling', 'adult',    'malware',  'phishing',       'warez',
    'dating',   'drugs',    'hacking',  'social_networks', 'news',
    'shopping', 'games',    'finance',  'education',       'health',
    'government',
]

# Base URL of the UT1 Capitole blacklist server.
# Each category is downloaded as:  <BASE_URL>/<category>.tar.gz
# Example: https://dsi.ut-capitole.fr/blacklists/download/gambling.tar.gz
UT1_BASE_URL = "https://dsi.ut-capitole.fr/blacklists/download"

# How many rows to insert into the database at one time.
# Inserting in batches is much faster than one row at a time.
# 1000 is a safe balance between speed and memory usage.
BATCH_SIZE = 1000


#  HELPER FUNCTIONS

def wait_for_db(max_retries=20, delay_seconds=3):
    """
    Tries to connect to the database repeatedly until it succeeds.
    This is needed because Docker may start this script before the
    PostgreSQL container is fully ready to accept connections.

    If the database never becomes available after all retries, the
    script exits with an error rather than crashing unpredictably.
    """
    for attempt_number in range(max_retries):

        try:
            # Just open and immediately close a test connection
            test_connection = psycopg2.connect(**DB_CONFIG)
            test_connection.close()
            log.info("Database is ready.")
            return  # success — exit the function and continue the script

        except psycopg2.OperationalError:
            # Database isn't ready yet — wait and try again
            log.info(
                "Waiting for database... attempt "
                + str(attempt_number + 1)
                + " of "
                + str(max_retries)
            )
            time.sleep(delay_seconds)

    # If we get here, we ran out of retries
    log.error("Database never became ready. Exiting.")
    sys.exit(1)


def category_already_imported(conn, category_name):
    """
    Returns True if the database already has domains for this category.
    Used to skip re-downloading categories we imported in a previous run.

    Parameters:
      conn          — an open database connection
      category_name — e.g. "gambling" or "malware"
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM url_categories WHERE category = %s",
            (category_name,)
        )
        row_count = cur.fetchone()[0]  # fetchone() returns a tuple; [0] is the number
        return row_count > 0


def insert_domains_batch(conn, domain_rows):
    """
    Inserts a list of (domain, category) tuples into the url_categories table.

    Uses execute_values() which sends all rows in one SQL statement —
    much faster than calling INSERT once per domain.

    ON CONFLICT DO NOTHING means if a domain already exists in the table,
    it is silently skipped rather than throwing an error.

    Parameters:
      conn        — an open database connection
      domain_rows — list of tuples, e.g. [("facebook.com", "social_networks"), ...]
    """
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            """
            INSERT INTO url_categories (domain, category)
            VALUES %s
            ON CONFLICT (domain) DO NOTHING
            """,
            domain_rows,
            template="(%s, %s)",
            page_size=BATCH_SIZE
        )
    conn.commit()  # save the changes to the database


def download_and_extract_domains(category_name):
    """
    Downloads the .tar.gz archive for a category and extracts the domain list.

    The UT1 archives contain a file called "domains" (plain text, one domain per line).
    We download the archive into memory (no disk needed), open it, find that file,
    and return a list of clean domain strings.

    Returns a list of domain strings, or an empty list if anything goes wrong.

    Parameters:
      category_name — e.g. "gambling"
    """
    # Build the full download URL for this category
    download_url = UT1_BASE_URL + "/" + category_name + ".tar.gz"
    log.info("Downloading '" + category_name + "' from: " + download_url)

    #  Step 1: Download the archive 
    try:
        http_response = requests.get(download_url, timeout=60)

        # 404 means this category doesn't exist on the UT1 server
        if http_response.status_code == 404:
            log.warning("Category '" + category_name + "' not found on UT1 server (404). Skipping.")
            return []

        # Raise an exception for any other HTTP error (500, 403, etc.)
        http_response.raise_for_status()

    except requests.RequestException as error:
        log.error("Failed to download '" + category_name + "': " + str(error))
        return []

    #  Step 2: Extract the domain list from the archive 
    # BytesIO wraps the raw bytes so tarfile can read them like a file on disk.
    # mode='r:gz' tells tarfile this is a gzip-compressed archive.
    extracted_domains = []

    try:
        archive_bytes   = BytesIO(http_response.content)

        with tarfile.open(fileobj=archive_bytes, mode='r:gz') as tar_archive:

            for archive_member in tar_archive.getmembers():

                # We only care about the file named "domains" inside the archive
                # It may be at the top level or inside a subfolder
                is_domains_file = (
                    archive_member.name.endswith('/domains') or
                    archive_member.name == 'domains'
                )

                if is_domains_file:
                    # Extract the file contents as a readable object
                    domains_file = tar_archive.extractfile(archive_member)

                    if domains_file:
                        raw_content = domains_file.read().decode('utf-8', errors='ignore')

                        # Process each line in the file
                        for line in raw_content.splitlines():
                            clean_line = line.strip().lower()

                            # Skip blank lines, comment lines (#), and URLs with slashes
                            if not clean_line:
                                continue
                            if clean_line.startswith('#'):
                                continue
                            if '/' in clean_line:
                                continue

                            extracted_domains.append(clean_line)

    except Exception as error:
        log.error("Failed to read archive for '" + category_name + "': " + str(error))

    # Log how many domains were found (e.g. "→ 14,302 domains in 'gambling'")
    log.info("  → " + f"{len(extracted_domains):,}" + " domains found in '" + category_name + "'")

    return extracted_domains



#  MAIN — ties everything together

def main():
    log.info("=" * 60)
    log.info("UT1 Blacklist Importer — starting")
    log.info("=" * 60)

    #  Step 1: Wait for the database to be ready 
    wait_for_db()

    #  Step 2: Open one connection to reuse for the whole import 
    db_connection  = psycopg2.connect(**DB_CONFIG)
    total_imported = 0   # running total across all categories

    #  Step 3: Import each category one by one 
    for category_name in CATEGORIES_TO_IMPORT:

        # Skip if we already have data for this category
        if category_already_imported(db_connection, category_name):
            log.info("[SKIP] '" + category_name + "' is already in the database.")
            continue

        # Download and extract the domain list for this category
        domain_list = download_and_extract_domains(category_name)

        # If nothing was downloaded (error or 404), move on to the next category
        if not domain_list:
            continue

        #  Step 4: Insert domains in batches 
        # We split the full list into chunks of BATCH_SIZE to avoid sending
        # one enormous SQL statement that could time out or use too much memory.
        all_rows         = [(domain, category_name) for domain in domain_list]
        domains_inserted = 0

        for batch_start in range(0, len(all_rows), BATCH_SIZE):

            # Slice out the next batch of rows
            batch_end  = batch_start + BATCH_SIZE
            batch_rows = all_rows[batch_start:batch_end]

            insert_domains_batch(db_connection, batch_rows)
            domains_inserted += len(batch_rows)

        log.info("[OK] Imported " + f"{domains_inserted:,}" + " domains for '" + category_name + "'")
        total_imported += domains_inserted

    #  Step 5: Clean up and print final summary 
    db_connection.close()

    log.info("=" * 60)
    log.info("Import complete. Total domains imported: " + f"{total_imported:,}")
    log.info("=" * 60)


#  Entry point 
# Only runs when you execute this file directly (not when imported as a module)
if __name__ == '__main__':
    main()