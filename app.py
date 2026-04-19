from flask import Flask, render_template, jsonify, request, Response
import psycopg2
import psycopg2.extras
import os
import time
import json
from datetime import datetime, timedelta

app = Flask(__name__)

DB_CONFIG = {
    'host':     os.environ.get('DB_HOST', 'postgres'),
    'dbname':   os.environ.get('DB_NAME', 'squid_categories'),
    'user':     os.environ.get('DB_USER', 'squid'),
    'password': os.environ.get('DB_PASSWORD', 'squidpass'),
}

def get_db():
    return psycopg2.connect(**DB_CONFIG, cursor_factory=psycopg2.extras.RealDictCursor)


# ── Pages ────────────────────────────────────────────────────────────────────

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


# ── API ──────────────────────────────────────────────────────────────────────

@app.route('/api/stats')
def api_stats():
    conn = get_db()
    cur = conn.cursor()

    # Total requests today
    cur.execute("""
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN action='DENY' THEN 1 ELSE 0 END) AS blocked,
               SUM(CASE WHEN action='ALLOW' THEN 1 ELSE 0 END) AS allowed
        FROM request_log
        WHERE logged_at > NOW() - INTERVAL '24 hours'
    """)
    totals = cur.fetchone()

    # Top blocked categories today
    cur.execute("""
        SELECT category, COUNT(*) AS count
        FROM request_log
        WHERE action = 'DENY' AND logged_at > NOW() - INTERVAL '24 hours'
        GROUP BY category
        ORDER BY count DESC
        LIMIT 6
    """)
    top_blocked = cur.fetchall()

    # Top visited domains today
    cur.execute("""
        SELECT domain, category, COUNT(*) AS count
        FROM request_log
        WHERE action = 'ALLOW' AND logged_at > NOW() - INTERVAL '24 hours'
        GROUP BY domain, category
        ORDER BY count DESC
        LIMIT 8
    """)
    top_domains = cur.fetchall()

    # Requests per hour (last 24h)
    cur.execute("""
        SELECT DATE_TRUNC('hour', logged_at) AS hour,
               COUNT(*) AS total,
               SUM(CASE WHEN action='DENY' THEN 1 ELSE 0 END) AS blocked
        FROM request_log
        WHERE logged_at > NOW() - INTERVAL '24 hours'
        GROUP BY hour
        ORDER BY hour
    """)
    hourly = cur.fetchall()

    # Total domains in DB
    cur.execute("SELECT COUNT(*) AS count FROM url_categories")
    db_size = cur.fetchone()

    # Uncategorized count
    cur.execute("SELECT COUNT(*) AS count FROM uncategorized_urls")
    uncat_count = cur.fetchone()

    conn.close()

    return jsonify({
        'totals': dict(totals),
        'top_blocked': [dict(r) for r in top_blocked],
        'top_domains': [dict(r) for r in top_domains],
        'hourly': [
            {
                'hour': r['hour'].strftime('%H:%M'),
                'total': r['total'],
                'blocked': r['blocked']
            } for r in hourly
        ],
        'db_size': db_size['count'],
        'uncat_count': uncat_count['count'],
    })


@app.route('/api/logs')
def api_logs():
    page     = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    action   = request.args.get('action', '')      # ALLOW / DENY / ''
    search   = request.args.get('search', '')
    offset   = (page - 1) * per_page

    conn = get_db()
    cur = conn.cursor()

    where = ["1=1"]
    params = []

    if action in ('ALLOW', 'DENY'):
        where.append("action = %s")
        params.append(action)
    if search:
        where.append("domain ILIKE %s")
        params.append(f'%{search}%')

    where_sql = ' AND '.join(where)

    cur.execute(f"""
        SELECT id, domain, category, action,
               logged_at AT TIME ZONE 'UTC' AS logged_at
        FROM request_log
        WHERE {where_sql}
        ORDER BY logged_at DESC
        LIMIT %s OFFSET %s
    """, params + [per_page, offset])
    rows = cur.fetchall()

    cur.execute(f"SELECT COUNT(*) AS count FROM request_log WHERE {where_sql}", params)
    total = cur.fetchone()['count']

    conn.close()
    return jsonify({
        'rows': [
            {**dict(r), 'logged_at': r['logged_at'].strftime('%Y-%m-%d %H:%M:%S')}
            for r in rows
        ],
        'total': total,
        'page': page,
        'pages': max(1, (total + per_page - 1) // per_page),
    })


@app.route('/api/uncategorized')
def api_uncategorized():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT domain, hit_count, first_seen, last_seen, category, notes
        FROM uncategorized_urls
        ORDER BY hit_count DESC
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


@app.route('/api/categories')
def api_categories():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT bc.category, bc.description, bc.enabled,
               COUNT(uc.id) AS domain_count
        FROM blocked_categories bc
        LEFT JOIN url_categories uc ON uc.category = bc.category
        GROUP BY bc.category, bc.description, bc.enabled
        ORDER BY domain_count DESC
    """)
    rows = cur.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/categories/<category>/toggle', methods=['POST'])
def toggle_category(category):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE blocked_categories
        SET enabled = NOT enabled
        WHERE category = %s
        RETURNING enabled
    """, (category,))
    result = cur.fetchone()
    conn.connection.commit()
    conn.close()
    return jsonify({'category': category, 'enabled': result['enabled']})


@app.route('/api/live')
def api_live():
    """Server-Sent Events — streams new log entries every 2 seconds."""
    def generate():
        last_id = 0
        # Get current max ID as starting point
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
                    SELECT id, domain, category, action,
                           logged_at AT TIME ZONE 'UTC' AS logged_at
                    FROM request_log
                    WHERE id > %s
                    ORDER BY id ASC
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

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
