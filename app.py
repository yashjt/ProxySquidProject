
from flask import Flask, render_template, jsonify, request, Response

# psycopg2 — PostgreSQL database driver for Python
import psycopg2
import psycopg2.extras   # gives us RealDictCursor (columns by name, not index)

import os        # to read environment variables
import time      # for sleep() in the live feed loop
import json      # to serialize data as JSON strings
from datetime import datetime

# Create the Flask application object
app = Flask(__name__)


# ─ Database Configuration 
# These values are read from environment variables set in docker-compose.yml.
# If an env variable is missing, the second argument is the fallback default.
DB_CONFIG = {
    'host':     os.environ.get('DB_HOST',     'postgres'),
    'dbname':   os.environ.get('DB_NAME',     'squid_categories'),
    'user':     os.environ.get('DB_USER',     'squid'),
    'password': os.environ.get('DB_PASSWORD', 'squidpass'),
}


#  Database Helper 
def get_db():
    """
    Opens and returns a new database connection.
    RealDictCursor means every row comes back as a dictionary,
    so we can write row['domain'] instead of row[0].
    We open a fresh connection per request and close it when done.
    """
    connection = psycopg2.connect(**DB_CONFIG, cursor_factory=psycopg2.extras.RealDictCursor)
    return connection



#  PAGE ROUTES


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



#  API ROUTES
#  These routes return JSON data that the frontend JavaScript reads.
#  Every route follows the same pattern:
#    1. Open a DB connection
#    2. Run one or more SQL queries
#    3. Close the connection
#    4. Return the data as JSON

@app.route('/api/stats')
def api_stats():
    """
    Returns summary numbers for the dashboard:
      - Total / blocked / allowed request counts (last 24 hours)
      - Top blocked categories
      - Top visited allowed domains
      - Hourly traffic breakdown (for the bar chart)
      - Total domains in the database
      - Count of uncategorized domains
    """
    conn = get_db()
    cur  = conn.cursor()

    #  Query 1: Overall totals
    # CASE WHEN ... THEN 1 ELSE 0 END is like an if/else inside SQL.
    # SUM counts how many rows matched that condition.
    cur.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN action = 'DENY'  THEN 1 ELSE 0 END) AS blocked,
            SUM(CASE WHEN action = 'ALLOW' THEN 1 ELSE 0 END) AS allowed
        FROM request_log
        WHERE logged_at > NOW() - INTERVAL '24 hours'
    """)
    totals = cur.fetchone()   # fetchone() returns a single row (or None)

    #  Query 2: Top 6 most-blocked categories 
    cur.execute("""
        SELECT category, COUNT(*) AS count
        FROM request_log
        WHERE action = 'DENY'
          AND logged_at > NOW() - INTERVAL '24 hours'
        GROUP BY category
        ORDER BY count DESC
        LIMIT 6
    """)
    top_blocked = cur.fetchall()  # fetchall() returns a list of rows

    #  Query 3: Top 8 most-visited allowed domains 
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

    #  Query 4: Per-hour traffic breakdown 
    # DATE_TRUNC rounds each timestamp down to the nearest hour,
    # so all requests within the same hour get grouped together.
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
    hourly_rows = cur.fetchall()

    #  Query 5: Total domains stored in the database 
    cur.execute("SELECT COUNT(*) AS count FROM url_categories")
    db_size_row = cur.fetchone()

    #  Query 6: Count of domains Squid couldn't categorize 
    cur.execute("SELECT COUNT(*) AS count FROM uncategorized_urls")
    uncat_row = cur.fetchone()

    conn.close()

    #  Build the hourly list 
    # Convert each datetime object to a simple "HH:MM" string for the chart labels.
    hourly_list = []
    for row in hourly_rows:
        hourly_list.append({
            'hour':    row['hour'].strftime('%H:%M'),
            'total':   row['total'],
            'blocked': row['blocked'],
        })

    #  Return everything as a single JSON object 
    return jsonify({
        'totals':      dict(totals),
        'top_blocked': [dict(row) for row in top_blocked],
        'top_domains': [dict(row) for row in top_domains],
        'hourly':      hourly_list,
        'db_size':     db_size_row['count'],
        'uncat_count': uncat_row['count'],
    })


@app.route('/api/logs')
def api_logs():
    """
    Returns a paginated, filterable list of request log entries.

    URL parameters:
      page     — which page to show (default: 1)
      per_page — how many rows per page (default: 50)
      action   — filter by ALLOW or DENY (default: show all)
      search   — filter by domain name using a partial match
    """
    # Read filter values from the URL query string
    # e.g. /api/logs?page=2&action=DENY&search=facebook
    page     = int(request.args.get('page',     1))
    per_page = int(request.args.get('per_page', 50))
    action   = request.args.get('action', '')    # 'ALLOW', 'DENY', or '' for all
    search   = request.args.get('search', '')

    # Calculate how many rows to skip based on the current page number
    # Page 1 → skip 0 rows, page 2 → skip 50 rows, etc.
    offset = (page - 1) * per_page

    conn = get_db()
    cur  = conn.cursor()

    #  Build the WHERE clause dynamically 
    # We start with "1=1" (always true) so we can safely append AND conditions.
    # Using a list of parts + params list avoids SQL injection.
    where_parts = ["1=1"]
    params      = []

    if action in ('ALLOW', 'DENY'):
        where_parts.append("rl.action = %s")
        params.append(action)

    if search:
        # ILIKE is Postgres case-insensitive LIKE
        # The % wildcards mean "match anything before or after the search term"
        where_parts.append("rl.domain ILIKE %s")
        params.append('%' + search + '%')

    # Join all conditions with AND to form the complete WHERE clause
    where_sql = ' AND '.join(where_parts)

    #  Fetch the matching rows 
    # LEFT JOIN url_categories so category always reflects the current value,
    # not just what was saved at log time.
    # COALESCE(a, b) returns a if a is not NULL, otherwise returns b.
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

    #  Count total matching rows (for pagination) 
    cur.execute(f"""
        SELECT COUNT(*) AS count
        FROM request_log rl
        WHERE {where_sql}
    """, params)

    total_rows = cur.fetchone()['count']

    conn.close()

    #  Calculate total pages 
    # Example: 103 rows / 50 per page = 2.06 → ceil to 3 pages
    # The formula (total + per_page - 1) // per_page is integer ceiling division
    total_pages = max(1, (total_rows + per_page - 1) // per_page)

    # Format each row's timestamp as a readable string before sending
    formatted_rows = []
    for row in rows:
        row_dict = dict(row)
        row_dict['logged_at'] = row['logged_at'].strftime('%Y-%m-%d %H:%M:%S')
        formatted_rows.append(row_dict)

    return jsonify({
        'rows':  formatted_rows,
        'total': total_rows,
        'page':  page,
        'pages': total_pages,
    })


#  /api/uncategorized 
@app.route('/api/uncategorized')
def api_uncategorized():
    """
    Returns up to 200 domains that Squid saw but couldn't match in the database.
    Sorted by hit_count so the most-visited unknown domains appear first —
    those are the most useful ones to review and categorize.
    """
    conn = get_db()
    cur  = conn.cursor()

    cur.execute("""
        SELECT domain, hit_count, first_seen, last_seen, category, notes
        FROM uncategorized_urls
        ORDER BY hit_count DESC
        LIMIT 200
    """)
    rows = cur.fetchall()
    conn.close()

    # Format the two datetime columns as readable strings
    formatted_rows = []
    for row in rows:
        row_dict = dict(row)
        row_dict['first_seen'] = row['first_seen'].strftime('%Y-%m-%d %H:%M')
        row_dict['last_seen']  = row['last_seen'].strftime('%Y-%m-%d %H:%M')
        formatted_rows.append(row_dict)

    return jsonify(formatted_rows)


# ── /api/uncategorized/<domain>/categorize ──────────────────────────────────────
@app.route('/api/uncategorized/<path:domain>/categorize', methods=['POST'])
def categorize_domain(domain):
    """
    Assigns a category to a previously uncategorized domain.

    Step 1 — Add the domain to url_categories so Squid can find it next time.
    Step 2 — Update uncategorized_urls to mark this domain as reviewed.

    The <path:domain> part of the route allows dots and slashes in the domain name.
    """
    # Read the JSON body the browser sent (e.g. {"category": "social"})
    request_data = request.get_json()
    category     = request_data.get('category', '').strip()

    # Reject the request if no category was provided
    if not category:
        return jsonify({'error': 'Category is required'}), 400

    conn = get_db()
    cur  = conn.cursor()

    try:
        # Insert the domain into url_categories.
        # ON CONFLICT handles duplicates: if the domain already exists,
        # just update its category instead of throwing an error.
        cur.execute("""
            INSERT INTO url_categories (domain, category, source)
            VALUES (%s, %s, 'manual')
            ON CONFLICT (domain)
            DO UPDATE SET category = %s, source = 'manual'
        """, (domain, category, category))

        # Mark the domain as reviewed in uncategorized_urls
        cur.execute("""
            UPDATE uncategorized_urls
            SET category = %s
            WHERE domain = %s
        """, (category, domain))

        conn.commit()
        conn.close()

        return jsonify({'success': True, 'domain': domain, 'category': category})

    except Exception as error:
        # If anything went wrong, undo all changes and return the error message
        conn.rollback()
        conn.close()
        return jsonify({'error': str(error)}), 500


# ── /api/categories (GET) ───────────────────────────────────────────────────────
@app.route('/api/categories')
def api_categories():
    """
    Returns every category, along with:
      - Its description (if one exists)
      - Whether blocking is currently enabled
      - How many domains belong to it
    """
    conn = get_db()
    cur  = conn.cursor()

    # LEFT JOIN so categories that exist in url_categories but NOT in
    # blocked_categories still appear — they just get enabled=FALSE as default.
    # COALESCE(bc.enabled, FALSE) handles the case where bc row is missing.
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

    return jsonify([dict(row) for row in rows])


# ── /api/categories (POST) ──────────────────────────────────────────────────────
@app.route('/api/categories', methods=['POST'])
def create_category():
    """
    Creates a new custom category.
    Spaces in the name are replaced with underscores
    so "social media" becomes "social_media".
    New categories start with blocking enabled (enabled = TRUE).
    """
    request_data = request.get_json()

    # Normalize the name: lowercase, strip whitespace, replace spaces with underscores
    category_name = request_data.get('category',    '').strip().lower().replace(' ', '_')
    description   = request_data.get('description', '').strip()

    if not category_name:
        return jsonify({'error': 'Category name is required'}), 400

    conn = get_db()
    cur  = conn.cursor()

    try:
        # Try to insert the new category.
        # DO NOTHING means if it already exists, skip silently.
        # RETURNING category only returns a row if the INSERT actually happened.
        cur.execute("""
            INSERT INTO blocked_categories (category, description, enabled)
            VALUES (%s, %s, TRUE)
            ON CONFLICT (category) DO NOTHING
            RETURNING category
        """, (category_name, description))

        inserted_row = cur.fetchone()
        conn.commit()
        conn.close()

        # If fetchone() returned None, the category already existed
        if inserted_row is None:
            return jsonify({'error': 'Category already exists'}), 409

        return jsonify({'success': True, 'category': category_name})

    except Exception as error:
        conn.rollback()
        conn.close()
        return jsonify({'error': str(error)}), 500


# ── /api/categories/<category>/toggle ──────────────────────────────────────────
@app.route('/api/categories/<category>/toggle', methods=['POST'])
def toggle_category(category):
    """
    Flips the blocking state of a category ON → OFF or OFF → ON.

    Also increments the cache version number so squid_helper.py knows
    to clear its local cache and pick up the change.
    """
    conn = get_db()
    cur  = conn.cursor()

    # INSERT if the category is new, otherwise flip its enabled flag.
    # NOT blocked_categories.enabled flips TRUE → FALSE or FALSE → TRUE.
    # RETURNING enabled gives us back the new value after the flip.
    cur.execute("""
        INSERT INTO blocked_categories (category, enabled)
        VALUES (%s, TRUE)
        ON CONFLICT (category)
        DO UPDATE SET enabled = NOT blocked_categories.enabled
        RETURNING enabled
    """, (category,))

    result      = cur.fetchone()
    new_enabled = result['enabled']

    # Bump the cache version so Squid's helper script detects the change
    cur.execute("UPDATE cache_version SET version = version + 1 WHERE id = 1")

    conn.commit()
    conn.close()

    return jsonify({'category': category, 'enabled': new_enabled})


# ── /api/all_categories ─────────────────────────────────────────────────────────
@app.route('/api/all_categories')
def api_all_categories():
    """
    Returns a flat list of every unique category name from both tables.
    UNION automatically removes duplicates.
    Used to fill the dropdown on the uncategorized page.
    """
    conn = get_db()
    cur  = conn.cursor()

    cur.execute("""
        SELECT DISTINCT category
        FROM (
            SELECT category FROM blocked_categories
            UNION
            SELECT category FROM url_categories
        ) combined_categories
        ORDER BY category
    """)
    rows = cur.fetchall()
    conn.close()

    # Return a simple list of strings: ["ads", "malware", "social", ...]
    category_names = [row['category'] for row in rows]
    return jsonify(category_names)


# ── /api/live (Server-Sent Events) ─────────────────────────────────────────────
@app.route('/api/live')
def api_live():
    """
    Keeps a long-lived HTTP connection open and pushes new log rows
    to the browser every 2 seconds. This powers the Live Feed on the dashboard.

    SSE (Server-Sent Events) is a one-way stream: server → browser.
    The browser listens with: const source = new EventSource('/api/live')
    Each message must follow the format:  data: <json string>\\n\\n
    """

    def generate():
        # ── Step 1: Find the current latest row ID ───────────────────────────
        # We only want to stream NEW rows from this point forward,
        # not replay the entire history.
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("SELECT COALESCE(MAX(id), 0) AS max_id FROM request_log")
        last_seen_id = cur.fetchone()['max_id']
        conn.close()

        # ── Step 2: Poll for new rows every 2 seconds ────────────────────────
        while True:
            try:
                conn = get_db()
                cur  = conn.cursor()

                # Only fetch rows with an ID higher than the last one we sent
                cur.execute("""
                    SELECT id, domain, category, action,
                           logged_at AT TIME ZONE 'UTC' AS logged_at
                    FROM request_log
                    WHERE id > %s
                    ORDER BY id ASC
                    LIMIT 20
                """, (last_seen_id,))

                new_rows = cur.fetchall()
                conn.close()

                # Send each new row to the browser as an SSE message
                for row in new_rows:
                    last_seen_id = row['id']   # Advance the cursor

                    row_dict = dict(row)
                    row_dict['logged_at'] = row['logged_at'].strftime('%H:%M:%S')

                    # SSE format requires "data: " prefix and double newline at the end
                    json_string = json.dumps(row_dict)
                    yield f"data: {json_string}\n\n"

                # Wait 2 seconds before checking for more new rows
                time.sleep(2)

            except Exception as error:
                # If anything breaks, send the error to the browser and wait before retrying
                error_payload = json.dumps({'error': str(error)})
                yield f"data: {error_payload}\n\n"
                time.sleep(5)

    # Return the generator as a streaming HTTP response
    # Cache-Control and X-Accel-Buffering prevent proxies from buffering the stream
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control':    'no-cache',
            'X-Accel-Buffering': 'no',
        }
    )

# Entry Poin
# This block only runs when you execute "python app.py" directly.
# When deployed with gunicorn or Docker, this block is skipped.
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)