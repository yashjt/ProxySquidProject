from flask import Flask, render_template, jsonify, request, Response, send_file
import psycopg2
import psycopg2.extras
import subprocess
import os
import time
import json
from datetime import datetime

app = Flask(__name__)

# Database connection details — read from docker-compose environment variables
DB_CONFIG = {
    'host':     os.environ.get('DB_HOST', 'postgres'),
    'dbname':   os.environ.get('DB_NAME', 'squid_categories'),
    'user':     os.environ.get('DB_USER', 'squid'),
    'password': os.environ.get('DB_PASSWORD', 'squidpass'),
}

# Folder where exported text files are saved inside the container
EXPORT_DIR = '/app/exports'


def get_db():
    # RealDictCursor lets us access columns by name: row['domain'] instead of row[0]
    return psycopg2.connect(**DB_CONFIG, cursor_factory=psycopg2.extras.RealDictCursor)


def increment_cache_version(cur):
    """
    Bump the cache version number so squid_helper.py knows to clear its
    in-memory cache on its next 30-second check.
    This is called every time a category is toggled or a domain is re-categorized.
    """
    cur.execute("UPDATE cache_version SET version = version + 1 WHERE id = 1")


def trigger_squid_reload():
    """
    Tell Squid to reload its config without a full restart.
    This clears Squid's own ACL cache (the ttl= setting in squid.conf).
    """
    try:
        subprocess.run(
            ['squid', '-k', 'reconfigure'],
            timeout=5,
            capture_output=True
        )
    except Exception as e:
        print(f"Squid reconfigure warning: {e}")


def make_file_header(title):
    """
    Returns a text header block to put at the top of each exported file.
    Example output:
      REQUEST LOGS
      Generated: 2026-04-20 14:30:00
    
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    header  = '=' * 60 + '\n'
    header += f'  {title}\n'
    header += f'  Generated: {now}\n'
    header += '=' * 60 + '\n\n'

    return header


# ==============================================================================
# Page routes — render HTML templates
# ==============================================================================

@app.route('/')
def dashboard():
    return render_template('dashboard.html')


@app.route('/logs')
def logs():
    return render_template('logs.html')


@app.route('/uncategorized')
def uncategorized():
    return render_template('uncategorized.html')


@app.route('/categories')
def categories():
    return render_template('categories.html')


@app.route('/export')
def export_page():
    # New export page — shows buttons to generate and download each file
    return render_template('export.html')


# ==============================================================================
# Stats API — dashboard data
# ==============================================================================

@app.route('/api/stats')
def api_stats():
    conn = get_db()
    cur = conn.cursor()

    # Total, blocked, and allowed requests in the last 24 hours
    cur.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN action = 'DENY'  THEN 1 ELSE 0 END) AS blocked,
            SUM(CASE WHEN action = 'ALLOW' THEN 1 ELSE 0 END) AS allowed
        FROM request_log
        WHERE logged_at > NOW() - INTERVAL '24 hours'
    """)
    totals = cur.fetchone()

    # Top 6 blocked categories today
    cur.execute("""
        SELECT category, COUNT(*) AS count
        FROM request_log
        WHERE action = 'DENY'
          AND logged_at > NOW() - INTERVAL '24 hours'
        GROUP BY category
        ORDER BY count DESC
        LIMIT 6
    """)
    top_blocked = cur.fetchall()

    # Top 8 most visited allowed domains today
    cur.execute("""
        SELECT domain, category, COUNT(*) AS count
        FROM request_log
        WHERE action = 'ALLOW'
          AND logged_at > NOW() - INTERVAL '24 hours'
        GROUP BY domain, category
        ORDER BY count DESC
        LIMIT 8
    """)
    top_domains = cur.fetchall()

    # Traffic per hour for the bar chart
    cur.execute("""
        SELECT
            DATE_TRUNC('hour', logged_at) AS hour,
            COUNT(*) AS total,
            SUM(CASE WHEN action = 'DENY' THEN 1 ELSE 0 END) AS blocked
        FROM request_log
        WHERE logged_at > NOW() - INTERVAL '24 hours'
        GROUP BY hour
        ORDER BY hour
    """)
    hourly = cur.fetchall()

    cur.execute("SELECT COUNT(*) AS count FROM url_categories")
    db_size = cur.fetchone()

    cur.execute("SELECT COUNT(*) AS count FROM uncategorized_urls WHERE category IS NULL")
    uncat_count = cur.fetchone()

    conn.close()

    return jsonify({
        'totals':      dict(totals),
        'top_blocked': [dict(r) for r in top_blocked],
        'top_domains': [dict(r) for r in top_domains],
        'hourly': [
            {
                'hour':    r['hour'].strftime('%H:%M'),
                'total':   r['total'],
                'blocked': r['blocked']
            }
            for r in hourly
        ],
        'db_size':     db_size['count'],
        'uncat_count': uncat_count['count'],
    })


# ==============================================================================
# Logs API — paginated, filterable request log
# ==============================================================================

@app.route('/api/logs')
def api_logs():
    page     = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    action   = request.args.get('action', '')
    search   = request.args.get('search', '')
    offset   = (page - 1) * per_page

    conn = get_db()
    cur = conn.cursor()

    where_parts = ["1=1"]
    params = []

    if action in ('ALLOW', 'DENY'):
        where_parts.append("rl.action = %s")
        params.append(action)

    if search:
        where_parts.append("rl.domain ILIKE %s")
        params.append(f'%{search}%')

    where_sql = ' AND '.join(where_parts)

    cur.execute(f"""
        SELECT
            rl.id,
            rl.domain,
            COALESCE(uc.category, rl.category) AS category,
            rl.action,
            rl.logged_at AT TIME ZONE 'UTC' AS logged_at
        FROM request_log rl
        LEFT JOIN url_categories uc ON uc.domain = rl.domain
        WHERE {where_sql}
        ORDER BY rl.logged_at DESC
        LIMIT %s OFFSET %s
    """, params + [per_page, offset])
    rows = cur.fetchall()

    cur.execute(f"""
        SELECT COUNT(*) AS count
        FROM request_log rl
        WHERE {where_sql}
    """, params)
    total = cur.fetchone()['count']

    conn.close()

    return jsonify({
        'rows': [
            {**dict(r), 'logged_at': r['logged_at'].strftime('%Y-%m-%d %H:%M:%S')}
            for r in rows
        ],
        'total': total,
        'page':  page,
        'pages': max(1, (total + per_page - 1) // per_page),
    })



@app.route('/api/uncategorized')
def api_uncategorized():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT domain, hit_count, first_seen, last_seen, category, notes
        FROM uncategorized_urls
        ORDER BY
            CASE WHEN category IS NULL THEN 0 ELSE 1 END,
            hit_count DESC
        LIMIT 200
    """)
    rows = cur.fetchall()
    conn.close()

    return jsonify([
        {
            **dict(r),
            'first_seen': r['first_seen'].strftime('%Y-%m-%d %H:%M'),
            'last_seen':  r['last_seen'].strftime('%Y-%m-%d %H:%M'),
        }
        for r in rows
    ])


@app.route('/api/uncategorized/<path:domain>/categorize', methods=['POST'])
def categorize_domain(domain):
    data = request.get_json()
    category = data.get('category', '').strip()

    if not category:
        return jsonify({'error': 'Category is required'}), 400

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO url_categories (domain, category, source)
            VALUES (%s, %s, 'manual')
            ON CONFLICT (domain)
            DO UPDATE SET category = %s, source = 'manual'
        """, (domain, category, category))

        cur.execute("""
            UPDATE uncategorized_urls
            SET category = %s
            WHERE domain = %s
        """, (category, domain))

        increment_cache_version(cur)
        conn.commit()
        conn.close()
        trigger_squid_reload()

        return jsonify({'success': True, 'domain': domain, 'category': category})

    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/uncategorized/<path:domain>/remove', methods=['POST'])
def remove_domain_category(domain):
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("DELETE FROM url_categories WHERE domain = %s AND source = 'manual'", (domain,))

        cur.execute("""
            UPDATE uncategorized_urls
            SET category = NULL
            WHERE domain = %s
        """, (domain,))

        increment_cache_version(cur)
        conn.commit()
        conn.close()
        trigger_squid_reload()

        return jsonify({'success': True, 'domain': domain})

    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/api/categories')
def api_categories():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            uc.category,
            bc.description,
            COALESCE(bc.enabled, FALSE) AS enabled,
            COUNT(uc.id) AS domain_count
        FROM url_categories uc
        LEFT JOIN blocked_categories bc ON bc.category = uc.category
        GROUP BY uc.category, bc.description, bc.enabled
        ORDER BY domain_count DESC
    """)
    rows = cur.fetchall()
    conn.close()

    return jsonify([dict(r) for r in rows])


@app.route('/api/categories', methods=['POST'])
def create_category():
    data = request.get_json()
    category    = data.get('category', '').strip().lower().replace(' ', '_')
    description = data.get('description', '').strip()

    if not category:
        return jsonify({'error': 'Category name is required'}), 400

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO blocked_categories (category, description, enabled)
            VALUES (%s, %s, TRUE)
            ON CONFLICT (category) DO NOTHING
            RETURNING category
        """, (category, description))

        result = cur.fetchone()
        conn.commit()
        conn.close()

        if result is None:
            return jsonify({'error': 'Category already exists'}), 409

        return jsonify({'success': True, 'category': category})

    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/categories/<category>/toggle', methods=['POST'])
def toggle_category(category):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO blocked_categories (category, enabled)
        VALUES (%s, TRUE)
        ON CONFLICT (category)
        DO UPDATE SET enabled = NOT blocked_categories.enabled
        RETURNING enabled
    """, (category,))

    result = cur.fetchone()
    increment_cache_version(cur)
    conn.commit()
    conn.close()
    trigger_squid_reload()

    return jsonify({'category': category, 'enabled': result['enabled']})


@app.route('/api/all_categories')
def api_all_categories():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT DISTINCT category
        FROM (
            SELECT category FROM blocked_categories
            UNION
            SELECT category FROM url_categories
        ) combined
        ORDER BY category
    """)
    rows = cur.fetchall()
    conn.close()

    return jsonify([r['category'] for r in rows])


@app.route('/api/live')
def api_live():
    def generate():
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT COALESCE(MAX(id), 0) AS max_id FROM request_log")
        last_id = cur.fetchone()['max_id']
        conn.close()

        while True:
            try:
                conn = get_db()
                cur = conn.cursor()

                cur.execute("""
                    SELECT
                        rl.id,
                        rl.domain,
                        COALESCE(uc.category, rl.category) AS category,
                        rl.action,
                        rl.logged_at AT TIME ZONE 'UTC' AS logged_at
                    FROM request_log rl
                    LEFT JOIN url_categories uc ON uc.domain = rl.domain
                    WHERE rl.id > %s
                    ORDER BY rl.id ASC
                    LIMIT 20
                """, (last_id,))

                rows = cur.fetchall()
                conn.close()

                for row in rows:
                    last_id = row['id']
                    data = json.dumps({
                        **dict(row),
                        'logged_at': row['logged_at'].strftime('%H:%M:%S')
                    })
                    yield f"data: {data}\n\n"

                time.sleep(2)

            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                time.sleep(5)

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


# ==============================================================================
# Export API — generate and download text files
# ==============================================================================

@app.route('/api/export/<export_type>', methods=['POST'])
def api_export(export_type):
    """
    Called when the user clicks an Export button in the UI.
    Generates a text file and saves it to EXPORT_DIR inside the container.
    Returns the number of rows written so the UI can show a confirmation.
    """
    # Create the exports folder if it doesn't exist yet
    os.makedirs(EXPORT_DIR, exist_ok=True)

    conn = get_db()

    try:
        # Call the correct export function based on the type
        if export_type == 'logs':
            row_count = export_logs(conn)

        elif export_type == 'categories':
            row_count = export_categories(conn)

        elif export_type == 'url_categories':
            row_count = export_url_categories(conn)

        elif export_type == 'uncategorized':
            row_count = export_uncategorized(conn)

        else:
            return jsonify({'error': 'Unknown export type'}), 400

        conn.close()
        return jsonify({'success': True, 'rows': row_count})

    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/download/<export_type>')
def api_download(export_type):
    """
    Sends the generated text file to the browser as a download.
    The file must be generated first by calling /api/export/<type>.
    """
    filepath = os.path.join(EXPORT_DIR, export_type + '.txt')

    # If the file doesn't exist, tell the user to export it first
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found. Click Export first.'}), 404

    # as_attachment=True triggers a download dialog in the browser
    return send_file(filepath, as_attachment=True, download_name=export_type + '.txt')


# ── Export helper functions ────────────────────────────────────────────────────

def export_logs(conn):
    """
    Writes the last 10,000 requests from request_log to logs.txt.
    Each line: timestamp | action | category | domain
    """
    cur = conn.cursor()

    # Get total count so we can show it in the file header
    cur.execute("SELECT COUNT(*) AS total FROM request_log")
    total_in_db = cur.fetchone()['total']

    # Fetch most recent 10,000 requests
    # LEFT JOIN so we always show the current category (not the one at time of request)
    cur.execute("""
        SELECT
            rl.logged_at AT TIME ZONE 'UTC' AS timestamp,
            rl.domain,
            COALESCE(uc.category, rl.category, 'uncategorized') AS category,
            rl.action
        FROM request_log rl
        LEFT JOIN url_categories uc ON uc.domain = rl.domain
        ORDER BY rl.logged_at DESC
        LIMIT 10000
    """)
    rows = cur.fetchall()

    filepath = os.path.join(EXPORT_DIR, 'logs.txt')

    with open(filepath, 'w') as f:

        # File header
        f.write(make_file_header('REQUEST LOGS'))

        # Summary
        f.write(f'Total records in database : {total_in_db:,}\n')
        f.write(f'Records in this file      : {len(rows):,} (most recent first)\n\n')

        # Column headers — fixed-width so columns line up neatly
        f.write(f'{"TIMESTAMP":<22} {"ACTION":<8} {"CATEGORY":<22} DOMAIN\n')
        f.write('-' * 80 + '\n')

        # One line per request
        for row in rows:
            timestamp = row['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            action    = row['action']
            category  = row['category']
            domain    = row['domain']

            f.write(f'{timestamp:<22} {action:<8} {category:<22} {domain}\n')

        f.write('\nEnd of logs.txt\n')

    return len(rows)


def export_categories(conn):
    """
    Writes all categories with their current block status to categories.txt.
    Split into two sections: BLOCKING and ALLOWED.
    """
    cur = conn.cursor()

    # Get all categories with enabled status and domain count
    cur.execute("""
        SELECT
            uc.category,
            COALESCE(bc.description, 'no description') AS description,
            COALESCE(bc.enabled, FALSE) AS is_blocking,
            COUNT(uc.id) AS domain_count
        FROM url_categories uc
        LEFT JOIN blocked_categories bc ON bc.category = uc.category
        GROUP BY uc.category, bc.description, bc.enabled
        ORDER BY domain_count DESC
    """)
    all_categories = cur.fetchall()

    # Separate into two lists for the two sections
    blocking_list = [c for c in all_categories if c['is_blocking']]
    allowed_list  = [c for c in all_categories if not c['is_blocking']]

    filepath = os.path.join(EXPORT_DIR, 'categories.txt')

    with open(filepath, 'w') as f:

        f.write(make_file_header('CATEGORY STATUS'))

        # Summary counts
        f.write(f'Total categories  : {len(all_categories)}\n')
        f.write(f'Currently blocking: {len(blocking_list)}\n')
        f.write(f'Currently allowed : {len(allowed_list)}\n\n')

        # Section 1 — blocking categories
        f.write('--- CURRENTLY BLOCKING TRAFFIC ---\n\n')
        f.write(f'{"CATEGORY":<25} {"DOMAINS":>12}   DESCRIPTION\n')
        f.write('-' * 65 + '\n')

        if blocking_list:
            for cat in blocking_list:
                f.write(f'{cat["category"]:<25} {cat["domain_count"]:>12,}   {cat["description"]}\n')
        else:
            f.write('  (nothing is currently blocking)\n')

        # Section 2 — allowed categories
        f.write('\n--- CURRENTLY ALLOWED ---\n\n')
        f.write(f'{"CATEGORY":<25} {"DOMAINS":>12}   DESCRIPTION\n')
        f.write('-' * 65 + '\n')

        for cat in allowed_list:
            f.write(f'{cat["category"]:<25} {cat["domain_count"]:>12,}   {cat["description"]}\n')

        f.write('\nEnd of categories.txt\n')

    return len(all_categories)


def export_url_categories(conn):
    """
    Writes a summary of domain counts per category and a full list
    of manually added/overridden domains to url_categories.txt.

    We don't export all 6M UT1 domains — just the count per category
    and the manual overrides (which are the ones you control).
    """
    cur = conn.cursor()

    # Count domains per category
    cur.execute("""
        SELECT category, COUNT(*) AS domain_count
        FROM url_categories
        GROUP BY category
        ORDER BY domain_count DESC
    """)
    category_summary = cur.fetchall()

    # Get all manually added/overridden domains
    cur.execute("""
        SELECT domain, category, created_at
        FROM url_categories
        WHERE source = 'manual'
        ORDER BY category, domain
    """)
    manual_domains = cur.fetchall()

    filepath = os.path.join(EXPORT_DIR, 'url_categories.txt')

    with open(filepath, 'w') as f:

        f.write(make_file_header('URL CATEGORIES'))

        # Total across all categories
        total = sum(row['domain_count'] for row in category_summary)
        f.write(f'Total domains in database: {total:,}\n\n')

        # Summary table
        f.write('--- DOMAIN COUNT PER CATEGORY ---\n\n')
        f.write(f'{"CATEGORY":<25} {"DOMAINS":>12}\n')
        f.write('-' * 40 + '\n')

        for row in category_summary:
            f.write(f'{row["category"]:<25} {row["domain_count"]:>12,}\n')

        # Manual overrides — these are the domains you assigned yourself
        f.write(f'\n\n--- MANUALLY ADDED DOMAINS ({len(manual_domains)} total) ---\n\n')
        f.write(f'{"DOMAIN":<40} {"CATEGORY":<25} DATE ADDED\n')
        f.write('-' * 80 + '\n')

        if manual_domains:
            for row in manual_domains:
                date_added = row['created_at'].strftime('%Y-%m-%d') if row['created_at'] else '—'
                f.write(f'{row["domain"]:<40} {row["category"]:<25} {date_added}\n')
        else:
            f.write('  (no manually added domains yet)\n')

        f.write('\nEnd of url_categories.txt\n')

    return len(category_summary)


def export_uncategorized(conn):
    """
    Writes all uncategorized domains to uncategorized.txt.
    Split into: PENDING (not yet reviewed) and REVIEWED (category assigned).
    """
    cur = conn.cursor()

    cur.execute("""
        SELECT domain, hit_count, first_seen, last_seen, category
        FROM uncategorized_urls
        ORDER BY
            CASE WHEN category IS NULL THEN 0 ELSE 1 END,
            hit_count DESC
    """)
    all_domains = cur.fetchall()

    # Split into two groups
    pending  = [d for d in all_domains if d['category'] is None]
    reviewed = [d for d in all_domains if d['category'] is not None]

    filepath = os.path.join(EXPORT_DIR, 'uncategorized.txt')

    with open(filepath, 'w') as f:

        f.write(make_file_header('UNCATEGORIZED DOMAINS'))

        f.write(f'Total seen     : {len(all_domains):,}\n')
        f.write(f'Pending review : {len(pending):,}\n')
        f.write(f'Reviewed       : {len(reviewed):,}\n\n')

        # Pending review — show hit count and when first/last seen
        f.write('--- PENDING REVIEW (no category assigned yet) ---\n\n')
        f.write(f'{"HITS":>6}  {"FIRST SEEN":<18} {"LAST SEEN":<18} DOMAIN\n')
        f.write('-' * 75 + '\n')

        if pending:
            for d in pending:
                first = d['first_seen'].strftime('%Y-%m-%d %H:%M')
                last  = d['last_seen'].strftime('%Y-%m-%d %H:%M')
                f.write(f'{d["hit_count"]:>6}  {first:<18} {last:<18} {d["domain"]}\n')
        else:
            f.write('  (all domains have been reviewed)\n')

        # Reviewed — show the category that was assigned
        f.write('\n--- REVIEWED (category assigned) ---\n\n')
        f.write(f'{"HITS":>6}  {"CATEGORY":<22} DOMAIN\n')
        f.write('-' * 60 + '\n')

        if reviewed:
            for d in reviewed:
                f.write(f'{d["hit_count"]:>6}  {d["category"]:<22} {d["domain"]}\n')
        else:
            f.write('  (no domains reviewed yet)\n')

        f.write('\nEnd of uncategorized.txt\n')

    return len(all_domains)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)