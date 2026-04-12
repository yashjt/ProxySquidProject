-- ============================================================
--  Squid URL Categorization Database Schema
-- ============================================================

-- Main table: stores domain → category mappings from UT1 blacklist
CREATE TABLE IF NOT EXISTS url_categories (
    id          SERIAL PRIMARY KEY,
    domain      VARCHAR(255) NOT NULL,
    category    VARCHAR(100) NOT NULL,
    source      VARCHAR(50)  DEFAULT 'ut1_blacklist',
    created_at  TIMESTAMP    DEFAULT NOW()
);

-- Index for fast domain lookups (Squid hits this on every request)
CREATE UNIQUE INDEX IF NOT EXISTS idx_url_categories_domain
    ON url_categories(domain);

CREATE INDEX IF NOT EXISTS idx_url_categories_category
    ON url_categories(category);

-- Blocked categories table: controls which categories Squid denies
CREATE TABLE IF NOT EXISTS blocked_categories (
    id          SERIAL PRIMARY KEY,
    category    VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    enabled     BOOLEAN      DEFAULT TRUE,
    created_at  TIMESTAMP    DEFAULT NOW()
);

-- Default blocked categories
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

-- Uncategorized URLs: domains Squid saw that weren't in the DB
-- Useful for reviewing and manually categorizing new sites
CREATE TABLE IF NOT EXISTS uncategorized_urls (
    id          SERIAL PRIMARY KEY,
    domain      VARCHAR(255) NOT NULL UNIQUE,
    hit_count   INTEGER      DEFAULT 1,
    first_seen  TIMESTAMP    DEFAULT NOW(),
    last_seen   TIMESTAMP    DEFAULT NOW(),
    category    VARCHAR(100) DEFAULT NULL,   -- filled in after manual review
    notes       TEXT         DEFAULT NULL
);

-- Request log: every request Squid processes (allowed + denied)
CREATE TABLE IF NOT EXISTS request_log (
    id          BIGSERIAL PRIMARY KEY,
    domain      VARCHAR(255),
    category    VARCHAR(100),
    action      VARCHAR(10),   -- 'ALLOW' or 'DENY'
    logged_at   TIMESTAMP      DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_request_log_domain   ON request_log(domain);
CREATE INDEX IF NOT EXISTS idx_request_log_logged_at ON request_log(logged_at);
