-- ============================================================
--  Squid URL Categorization Database Schema
-- ============================================================

-- Main table: domain → category mappings
-- squid_helper.py queries this on every request
CREATE TABLE IF NOT EXISTS url_categories (
    id          SERIAL PRIMARY KEY,
    domain      VARCHAR(255) NOT NULL,
    category    VARCHAR(100) NOT NULL,
    source      VARCHAR(50)  DEFAULT 'ut1_blacklist',
    created_at  TIMESTAMP    DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_url_categories_domain
    ON url_categories(domain);

CREATE INDEX IF NOT EXISTS idx_url_categories_category
    ON url_categories(category);

-- Policy table: which categories are currently blocked
-- enabled = TRUE means all domains in that category are blocked
CREATE TABLE IF NOT EXISTS blocked_categories (
    id          SERIAL PRIMARY KEY,
    category    VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    enabled     BOOLEAN      DEFAULT TRUE,
    created_at  TIMESTAMP    DEFAULT NOW()
);

-- Default blocked categories — all enabled on first run
INSERT INTO blocked_categories (category, description) VALUES
    ('gambling',        'Online gambling, betting, casinos'),
    ('adult',           'Adult / explicit content'),
    ('malware',         'Malware distribution sites'),
    ('phishing',        'Phishing and fraudulent sites'),
    ('warez',           'Software piracy and illegal downloads'),
    ('dating',          'Dating and hook-up sites'),
    ('drugs',           'Drug-related content'),
    ('hacking',         'Hacking tools and exploits')
ON CONFLICT (category) DO NOTHING;

-- Allowed categories — present so they appear in dropdowns, but not blocking
INSERT INTO blocked_categories (category, description, enabled) VALUES
    ('social_networks', 'Social media platforms',         FALSE),
    ('video_streaming', 'Video streaming services',       FALSE),
    ('shopping',        'Online shopping and retail',     FALSE),
    ('news',            'News and media sites',           FALSE),
    ('education',       'Educational content',            FALSE),
    ('technology',      'Tech companies and services',    FALSE),
    ('finance',         'Banking and financial services', FALSE),
    ('search_engine',   'Search engines',                 FALSE),
    ('games',           'Gaming sites',                   FALSE)
ON CONFLICT (category) DO NOTHING;

-- Tracks unknown domains Squid has seen but that aren't in url_categories
-- The UI shows these for manual review and categorization
CREATE TABLE IF NOT EXISTS uncategorized_urls (
    id          SERIAL PRIMARY KEY,
    domain      VARCHAR(255) NOT NULL UNIQUE,
    hit_count   INTEGER      DEFAULT 1,
    first_seen  TIMESTAMP    DEFAULT NOW(),
    last_seen   TIMESTAMP    DEFAULT NOW(),
    category    VARCHAR(100) DEFAULT NULL,
    notes       TEXT         DEFAULT NULL
);

-- Request log: every request Squid processes
-- Used for the dashboard charts and the logs page
CREATE TABLE IF NOT EXISTS request_log (
    id          BIGSERIAL PRIMARY KEY,
    domain      VARCHAR(255),
    category    VARCHAR(100),
    action      VARCHAR(10),
    logged_at   TIMESTAMP    DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_request_log_domain    ON request_log(domain);
CREATE INDEX IF NOT EXISTS idx_request_log_logged_at ON request_log(logged_at);

-- Cache invalidation: single row whose version number increments
-- every time a category toggle is flipped in the UI.
-- squid_helper.py checks this every 30 seconds — if changed, it clears
-- its in-memory cache so new blocking rules apply immediately.
CREATE TABLE IF NOT EXISTS cache_version (
    id      INT PRIMARY KEY DEFAULT 1,
    version INT DEFAULT 1
);

INSERT INTO cache_version (id, version) VALUES (1, 1)
ON CONFLICT (id) DO NOTHING;