"""
fetch_feeds.py
Pulls known-phishing URLs from free public feeds and stores them in SQLite.

Sources:
  - OpenPhish community feed (no auth needed, rate-limited, plain text list)
  - PhishTank (needs a free API key - https://www.phishtank.com/api_register.php)
  - URLhaus (abuse.ch) - bonus source, mostly malware but useful overlap

Run:
    python src/fetch_feeds.py
"""

import os
import requests
import tldextract
import db

OPENPHISH_URL = "https://openphish.com/feed.txt"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text_recent/"

# Put your free PhishTank API key here, or leave blank to skip that source.
PHISHTANK_API_KEY = os.environ.get("PHISHTANK_API_KEY", "")
PHISHTANK_URL = "https://data.phishtank.com/data/{}/online-valid.json"


def domain_of(url: str) -> str:
    ext = tldextract.extract(url)
    return ".".join(part for part in [ext.domain, ext.suffix] if part)


def fetch_openphish():
    print("[*] Fetching OpenPhish feed...")
    try:
        resp = requests.get(OPENPHISH_URL, timeout=20)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] OpenPhish fetch failed: {e}")
        return 0

    urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
    count = 0
    for url in urls:
        db.insert_url(url, "openphish", domain_of(url))
        count += 1
    print(f"[+] OpenPhish: {count} URLs ingested")
    return count


def fetch_urlhaus():
    print("[*] Fetching URLhaus feed...")
    try:
        resp = requests.get(URLHAUS_URL, timeout=20)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] URLhaus fetch failed: {e}")
        return 0

    urls = [
        line.strip() for line in resp.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    count = 0
    for url in urls:
        db.insert_url(url, "urlhaus", domain_of(url))
        count += 1
    print(f"[+] URLhaus: {count} URLs ingested")
    return count


def fetch_phishtank():
    if not PHISHTANK_API_KEY:
        print("[*] Skipping PhishTank (no PHISHTANK_API_KEY set)")
        return 0

    print("[*] Fetching PhishTank feed...")
    try:
        resp = requests.get(PHISHTANK_URL.format(PHISHTANK_API_KEY), timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[!] PhishTank fetch failed: {e}")
        return 0

    count = 0
    for entry in data:
        url = entry.get("url")
        if url:
            db.insert_url(url, "phishtank", domain_of(url))
            count += 1
    print(f"[+] PhishTank: {count} URLs ingested")
    return count


if __name__ == "__main__":
    db.init_db()
    total = 0
    total += fetch_openphish()
    total += fetch_urlhaus()
    total += fetch_phishtank()
    print(f"\n[=] Total new URLs in DB (deduplicated): {total}")
