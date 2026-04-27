#!/usr/bin/env python3
# ============================================================
#  web_classifier.py  —  Content-Based Website Classifier
#
#  PURPOSE:
#  When squid_helper.py sees a domain that is NOT in the
#  url_categories database, instead of just logging it as
#  "uncategorized", it calls this module to:
#
#    1. Fetch the webpage (title, meta tags, headings, body text)
#    2. Score the content against keyword lists for each category
#    3. Pick the best matching category
#    4. Save the result to PostgreSQL so it is remembered
#
#  This means the proxy gets smarter over time — every new
#  website it sees gets automatically classified.
#
#  APPROACH — Keyword Scoring (no external libraries needed):
#  Each category has a list of strong keywords. We count how
#  many of those words appear in the page content, weighted
#  by where they appear (title > meta > heading > body).
#  The category with the highest score wins.
#
#  EXAMPLE:
#  wsj.com page has title "The Wall Street Journal"
#  meta: "breaking news, finance, markets, economy"
#  Score: news=14, finance=9, education=1
#  Winner: news
# ============================================================

import re
import time
import logging
import urllib.request
import urllib.error
from html.parser import HTMLParser

# We use only Python standard library — no pip installs needed.
# This keeps the Docker container lean and the startup fast.

log = logging.getLogger(__name__)


# ==============================================================================
#  CATEGORY DEFINITIONS
#  Each category has:
#    - keywords: words that strongly indicate this category
#    - title_weight: multiplier for matches found in the page title
#    - meta_weight:  multiplier for matches in meta tags
#    - body_weight:  multiplier for matches in body text
#
#  To add a new category: just add a new entry to this dictionary.
#  To remove one: delete the entry.
#  To tune accuracy: add more keywords or adjust weights.
# ==============================================================================

CATEGORIES = {

    'news': {
        'keywords': [
            'breaking news', 'headline', 'journalist', 'reporter', 'editorial',
            'press', 'correspondent', 'bulletin', 'broadcast', 'coverage',
            'article', 'story', 'update', 'latest news', 'top stories',
            'world news', 'politics', 'election', 'government', 'parliament',
            'crisis', 'conflict', 'report', 'investigation', 'exclusive',
            'reuters', 'associated press', 'ap news', 'bbc', 'cnn', 'guardian',
            'new york times', 'washington post', 'wall street journal',
        ],
        'title_weight': 4,
        'meta_weight':  3,
        'body_weight':  1,
    },

    'social_networks': {
        'keywords': [
            'social network', 'connect with friends', 'share with friends',
            'follow', 'followers', 'following', 'post', 'feed', 'timeline',
            'profile', 'friends list', 'newsfeed', 'like', 'comment', 'share',
            'retweet', 'hashtag', 'trending', 'stories', 'reels', 'status',
            'message', 'chat', 'community', 'groups', 'pages',
            'facebook', 'instagram', 'twitter', 'x.com', 'tiktok',
            'snapchat', 'linkedin', 'reddit', 'pinterest', 'tumblr',
        ],
        'title_weight': 4,
        'meta_weight':  3,
        'body_weight':  1,
    },

    'video_streaming': {
        'keywords': [
            'watch', 'video', 'stream', 'streaming', 'episode', 'series',
            'movie', 'film', 'documentary', 'subscribe', 'channel', 'playlist',
            'views', 'upload', 'creator', 'content creator', 'watch now',
            'play', 'pause', 'subtitles', 'quality', 'resolution', 'hd',
            'youtube', 'netflix', 'twitch', 'vimeo', 'dailymotion',
            'disney plus', 'prime video', 'hbo max', 'hulu',
        ],
        'title_weight': 4,
        'meta_weight':  3,
        'body_weight':  1,
    },

    'shopping': {
        'keywords': [
            'buy', 'shop', 'store', 'cart', 'add to cart', 'checkout',
            'price', 'discount', 'sale', 'offer', 'deal', 'coupon',
            'free shipping', 'order', 'delivery', 'return', 'refund',
            'product', 'item', 'brand', 'review', 'rating', 'wishlist',
            'amazon', 'ebay', 'etsy', 'shopify', 'walmart', 'bestbuy',
            'retail', 'e-commerce', 'online store', 'purchase',
        ],
        'title_weight': 4,
        'meta_weight':  3,
        'body_weight':  1,
    },

    'education': {
        'keywords': [
            'learn', 'course', 'tutorial', 'lesson', 'lecture', 'study',
            'student', 'teacher', 'professor', 'university', 'college',
            'school', 'curriculum', 'degree', 'certificate', 'academic',
            'research', 'science', 'mathematics', 'homework', 'exam',
            'quiz', 'knowledge', 'skill', 'training', 'e-learning',
            'wikipedia', 'khan academy', 'coursera', 'udemy', 'edx',
            'encyclopedia', 'definition', 'how to', 'explained',
        ],
        'title_weight': 4,
        'meta_weight':  3,
        'body_weight':  1,
    },

    'finance': {
        'keywords': [
            'stock', 'market', 'invest', 'investment', 'portfolio',
            'trading', 'shares', 'equity', 'bond', 'fund', 'etf',
            'crypto', 'bitcoin', 'blockchain', 'forex', 'currency',
            'bank', 'banking', 'loan', 'mortgage', 'credit', 'debit',
            'interest rate', 'dividend', 'earnings', 'revenue', 'profit',
            'nasdaq', 'dow jones', 's&p 500', 'bloomberg', 'financial times',
            'paypal', 'stripe', 'wallet', 'transfer', 'payment',
        ],
        'title_weight': 4,
        'meta_weight':  3,
        'body_weight':  1,
    },

    'technology': {
        'keywords': [
            'software', 'hardware', 'developer', 'programming', 'code',
            'api', 'framework', 'open source', 'github', 'repository',
            'cloud', 'server', 'database', 'artificial intelligence', 'ai',
            'machine learning', 'cybersecurity', 'network', 'firewall',
            'startup', 'tech', 'app', 'mobile app', 'ios', 'android',
            'apple', 'google', 'microsoft', 'amazon', 'meta', 'openai',
            'documentation', 'install', 'configuration', 'deployment',
        ],
        'title_weight': 4,
        'meta_weight':  3,
        'body_weight':  1,
    },

    'gaming': {
        'keywords': [
            'game', 'gaming', 'play', 'player', 'gamer', 'multiplayer',
            'single player', 'level', 'score', 'achievement', 'quest',
            'character', 'weapon', 'map', 'server', 'patch', 'update',
            'esports', 'tournament', 'steam', 'console', 'xbox', 'playstation',
            'nintendo', 'pc gaming', 'fps', 'rpg', 'mmorpg', 'battle royale',
            'minecraft', 'fortnite', 'roblox', 'twitch', 'speedrun',
        ],
        'title_weight': 4,
        'meta_weight':  3,
        'body_weight':  1,
    },

    'health': {
        'keywords': [
            'health', 'medical', 'medicine', 'doctor', 'hospital', 'clinic',
            'symptom', 'treatment', 'diagnosis', 'drug', 'medication',
            'therapy', 'mental health', 'fitness', 'nutrition', 'diet',
            'exercise', 'wellness', 'disease', 'condition', 'surgery',
            'patient', 'prescription', 'pharmacy', 'vaccine', 'allergy',
            'webmd', 'mayo clinic', 'nhs', 'who', 'cdc', 'healthcare',
        ],
        'title_weight': 4,
        'meta_weight':  3,
        'body_weight':  1,
    },

    'adult': {
        'keywords': [
            'adult', 'xxx', 'porn', 'explicit', 'nude', 'naked',
            'nsfw', 'erotic', 'sex', 'escort', 'cam', 'only fans',
            '18+', 'mature content', 'adult content', 'fetish',
        ],
        'title_weight': 5,
        'meta_weight':  4,
        'body_weight':  2,
    },

    'gambling': {
        'keywords': [
            'casino', 'poker', 'slots', 'bet', 'betting', 'wager',
            'odds', 'jackpot', 'roulette', 'blackjack', 'bingo',
            'lottery', 'sportsbook', 'bookmaker', 'punt', 'gamble',
            'free spins', 'bonus bet', 'live casino', 'play now',
        ],
        'title_weight': 5,
        'meta_weight':  4,
        'body_weight':  2,
    },

    'government': {
        'keywords': [
            'government', 'official', 'ministry', 'department', 'federal',
            'state', 'municipal', 'public service', 'policy', 'legislation',
            'regulation', 'law', 'act', 'bill', 'senate', 'congress',
            'parliament', 'council', 'agency', 'authority', 'bureau',
            '.gov', 'citizen', 'passport', 'tax', 'form', 'apply',
        ],
        'title_weight': 4,
        'meta_weight':  3,
        'body_weight':  1,
    },

}

# Minimum score required before we trust a classification.
# If no category reaches this threshold, we return 'uncategorized'.
MIN_CONFIDENCE_SCORE = 3


# ==============================================================================
#  HTML PARSER
#  Extracts the parts we care about from a raw HTML page.
#  We use Python's built-in HTMLParser — no BeautifulSoup needed.
# ==============================================================================

class PageContentParser(HTMLParser):
    """
    Walks through the HTML and pulls out:
    - Page title (from <title> tag)
    - Meta description and keywords (from <meta> tags)
    - Open Graph tags like og:title, og:description
    - Heading text (h1, h2, h3)
    - Body text (first ~2000 characters — enough for classification)

    We stop collecting body text after 2000 chars because:
    - Most classification signals are near the top of the page
    - Large pages would slow down the classifier
    - We want near-real-time response
    """

    def __init__(self):
        super().__init__()

        self.title       = ''           # text between <title> tags
        self.meta_text   = ''           # combined meta description + keywords
        self.headings    = []           # h1, h2, h3 text
        self.body_text   = ''           # main visible text

        # Internal state flags
        self._in_title   = False        # are we currently inside <title>?
        self._in_heading = False        # are we currently inside <h1/h2/h3>?
        self._in_script  = False        # are we inside <script>? (skip this)
        self._in_style   = False        # are we inside <style>? (skip this)
        self._body_chars = 0            # how many body chars collected so far

        self._BODY_LIMIT = 3000         # stop collecting after this many chars

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)        # convert list of tuples to dict

        if tag == 'title':
            self._in_title = True

        elif tag in ('h1', 'h2', 'h3'):
            self._in_heading = True

        elif tag in ('script', 'style'):
            # Mark these so we skip their content — we don't want
            # JavaScript code or CSS in our classification text
            if tag == 'script': self._in_script = True
            if tag == 'style':  self._in_style = True

        elif tag == 'meta':
            # Extract meta description and keywords
            name    = attrs_dict.get('name', '').lower()
            prop    = attrs_dict.get('property', '').lower()
            content = attrs_dict.get('content', '')

            if name in ('description', 'keywords') and content:
                self.meta_text += ' ' + content

            # Open Graph tags (used by most modern sites)
            # og:title and og:description often have the clearest summary
            if prop in ('og:title', 'og:description', 'og:type') and content:
                self.meta_text += ' ' + content

    def handle_endtag(self, tag):
        if tag == 'title':   self._in_title   = False
        if tag in ('h1','h2','h3'): self._in_heading = False
        if tag == 'script':  self._in_script  = False
        if tag == 'style':   self._in_style   = False

    def handle_data(self, data):
        # Skip script and style content
        if self._in_script or self._in_style:
            return

        text = data.strip()
        if not text:
            return

        if self._in_title:
            self.title += text

        elif self._in_heading:
            self.headings.append(text)

        elif self._body_chars < self._BODY_LIMIT:
            # Collect body text until we hit the limit
            self.body_text += ' ' + text
            self._body_chars += len(text)


# ==============================================================================
#  PAGE FETCHER
#  Downloads a webpage and returns its HTML as a string.
# ==============================================================================

def fetch_page(domain, timeout_seconds=5):
    """
    Downloads the HTML of a domain's homepage.

    We try HTTPS first, fall back to HTTP.
    A short timeout prevents slow sites from blocking the proxy.

    Returns the raw HTML string, or empty string if anything fails.
    """
    headers = {
        # Pretend to be a regular browser so sites do not block us
        'User-Agent': (
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36'
        ),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }

    # Try HTTPS first, then HTTP
    for scheme in ('https', 'http'):
        url = f'{scheme}://{domain}'
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
                # Read up to 500KB — enough for classification, not too slow
                raw = response.read(500_000)

                # Detect encoding from Content-Type header
                content_type = response.headers.get('Content-Type', '')
                encoding = 'utf-8'  # default
                if 'charset=' in content_type:
                    encoding = content_type.split('charset=')[-1].strip()

                # Decode bytes to string, ignore characters we cannot decode
                return raw.decode(encoding, errors='ignore')

        except Exception as e:
            # Log but do not crash — we will try the other scheme or give up
            log.debug(f"fetch_page {scheme}://{domain}: {e}")
            continue

    return ''   # both schemes failed


# ==============================================================================
#  CONTENT EXTRACTOR
#  Parses HTML and returns a structured dict of the useful parts.
# ==============================================================================

def extract_content(html):
    """
    Takes raw HTML and returns a dict with the important text parts:
    {
        'title':    'The Wall Street Journal',
        'meta':     'breaking news business finance markets',
        'headings': ['Markets', 'Economy', 'Tech'],
        'body':     'Today in markets... Federal Reserve...'
    }
    """
    if not html:
        return {'title': '', 'meta': '', 'headings': [], 'body': ''}

    parser = PageContentParser()

    try:
        parser.feed(html)
    except Exception as e:
        log.debug(f"HTML parse error: {e}")

    return {
        'title':    parser.title.strip(),
        'meta':     parser.meta_text.strip(),
        'headings': parser.headings[:10],   # first 10 headings is plenty
        'body':     parser.body_text.strip(),
    }


# ==============================================================================
#  KEYWORD SCORER
#  The core classification logic. Counts keyword matches per category.
# ==============================================================================

def score_content(content):
    """
    Scores the page content against every category's keyword list.

    HOW THE SCORING WORKS:
    Each keyword found in the content adds points. Points are multiplied
    by the weight of where the keyword was found:
      - Title match:   × 4  (most important — clearly describes the site)
      - Meta match:    × 3  (site's own description of itself)
      - Heading match: × 2  (section headers reveal content type)
      - Body match:    × 1  (general content — lower weight)

    Example for wsj.com:
      title = "The Wall Street Journal"
      → "wall street journal" matches 'news' keyword → 4 points
      meta = "breaking news, markets, business"
      → "breaking news" matches → 3 points
      → "markets" matches 'finance' → 3 points
      Total: news=7, finance=3 → classified as 'news'

    Returns a dict of {category: score} for all categories.
    """

    # Combine all text into one lowercase string per zone
    title_text    = content['title'].lower()
    meta_text     = content['meta'].lower()
    heading_text  = ' '.join(content['headings']).lower()
    body_text     = content['body'].lower()

    scores = {}

    for category, config in CATEGORIES.items():
        score = 0
        keywords = config['keywords']

        tw = config['title_weight']
        mw = config['meta_weight']
        bw = config['body_weight']
        hw = 2   # heading weight (same for all categories)

        for keyword in keywords:
            kw = keyword.lower()

            # Count how many times this keyword appears in each zone
            # and add weighted points
            if kw in title_text:
                score += tw * title_text.count(kw)

            if kw in meta_text:
                score += mw * meta_text.count(kw)

            if kw in heading_text:
                score += hw * heading_text.count(kw)

            if kw in body_text:
                score += bw * body_text.count(kw)

        scores[category] = score

    return scores


# ==============================================================================
#  MAIN CLASSIFY FUNCTION
#  Called by squid_helper.py for every uncategorized domain.
# ==============================================================================

def classify_domain(domain):
    """
    Main entry point. Takes a domain string and returns a category string.

    Process:
    1. Fetch the homepage HTML
    2. Extract title, meta, headings, body
    3. Score against all category keyword lists
    4. Return the winning category (or 'uncategorized' if confidence is low)

    This is designed to be fast enough for near-real-time use — typically
    1-3 seconds per domain. The result is cached in PostgreSQL so
    subsequent visits to the same domain are instant.

    Arguments:
        domain  — e.g. "wsj.com" or "youtube.com"

    Returns:
        category string — e.g. "news", "video_streaming", "uncategorized"
    """

    log.info(f"Classifying domain: {domain}")
    start_time = time.time()

    # Step 1: Fetch the page
    html = fetch_page(domain)

    if not html:
        log.warning(f"Could not fetch {domain} — returning uncategorized")
        return 'uncategorized'

    # Step 2: Extract meaningful content from HTML
    content = extract_content(html)

    log.debug(
        f"{domain} — title: '{content['title'][:60]}' | "
        f"meta: '{content['meta'][:80]}'"
    )

    # Step 3: Score content against all categories
    scores = score_content(content)

    # Step 4: Find the highest scoring category
    best_category = max(scores, key=scores.get)
    best_score    = scores[best_category]

    elapsed = round(time.time() - start_time, 2)

    # If the best score is too low, we are not confident enough to classify
    if best_score < MIN_CONFIDENCE_SCORE:
        log.info(
            f"{domain} → uncategorized "
            f"(best score was {best_score} for {best_category}, "
            f"below threshold {MIN_CONFIDENCE_SCORE}) [{elapsed}s]"
        )
        return 'uncategorized'

    log.info(
        f"{domain} → {best_category} "
        f"(score: {best_score}) [{elapsed}s]"
    )

    return best_category


# ==============================================================================
#  SCORE BREAKDOWN (for debugging / UI display)
# ==============================================================================

def classify_with_details(domain):
    """
    Same as classify_domain() but returns full scoring details.
    Useful for the Flask dashboard to show WHY a site was classified
    a certain way.

    Returns:
    {
        'domain':   'wsj.com',
        'category': 'news',
        'score':    14,
        'confidence': 'high',
        'all_scores': {'news': 14, 'finance': 6, 'education': 1, ...},
        'content': {
            'title':    'The Wall Street Journal',
            'meta':     'breaking news, markets...',
            'headings': ['Markets', 'Economy', ...]
        },
        'elapsed_seconds': 1.4
    }
    """
    start_time = time.time()

    html    = fetch_page(domain)
    content = extract_content(html) if html else {'title': '', 'meta': '', 'headings': [], 'body': ''}
    scores  = score_content(content)

    best_category = max(scores, key=scores.get)
    best_score    = scores[best_category]
    elapsed       = round(time.time() - start_time, 2)

    if best_score < MIN_CONFIDENCE_SCORE:
        best_category = 'uncategorized'

    # Sort scores highest first for display
    sorted_scores = dict(sorted(scores.items(), key=lambda x: x[1], reverse=True))

    # Confidence label based on score
    if best_score >= 20:    confidence = 'high'
    elif best_score >= 8:   confidence = 'medium'
    elif best_score >= 3:   confidence = 'low'
    else:                   confidence = 'none'

    return {
        'domain':          domain,
        'category':        best_category,
        'score':           best_score,
        'confidence':      confidence,
        'all_scores':      sorted_scores,
        'content': {
            'title':    content['title'],
            'meta':     content['meta'][:200],
            'headings': content['headings'][:5],
        },
        'elapsed_seconds': elapsed,
    }


# ==============================================================================
#  COMMAND LINE TESTING
#  Run this file directly to test classification:
#    python3 web_classifier.py wsj.com
#    python3 web_classifier.py youtube.com
#    python3 web_classifier.py bet365.com
# ==============================================================================

if __name__ == '__main__':
    import sys

    # Set up console logging for testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
        stream=sys.stdout
    )

    domains_to_test = sys.argv[1:] if len(sys.argv) > 1 else [
        'wsj.com',
        'youtube.com',
        'wikipedia.org',
        'bet365.com',
        'amazon.com',
        'github.com',
    ]

    print('\n' + '=' * 60)
    print('Web Classifier — Test Results')
    print('=' * 60 + '\n')

    for domain in domains_to_test:
        result = classify_with_details(domain)

        print(f"Domain    : {result['domain']}")
        print(f"Category  : {result['category'].upper()}")
        print(f"Confidence: {result['confidence']} (score: {result['score']})")
        print(f"Time      : {result['elapsed_seconds']}s")
        print(f"Title     : {result['content']['title']}")
        print(f"Top scores: ", end='')

        top5 = list(result['all_scores'].items())[:5]
        print(' | '.join(f"{k}:{v}" for k, v in top5))
        print()
