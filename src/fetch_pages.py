"""
fetch_pages.py
Safely downloads the raw HTML of pending phishing URLs for later fingerprinting.

!!! SAFETY NOTE !!!
These URLs are LIVE, confirmed-malicious phishing pages. Some redirect to
exploit kits or drive-by-download pages, not just credential-harvesting forms.
Run this script inside an isolated environment:
  - a disposable VM / container with no credentials or sensitive files, OR
  - a free-tier cloud VM (AWS/GCP/Oracle free tier)
Never run this against your main machine's browser, and never submit real
credentials into any form you find.

This script only performs a GET request and saves the raw response text -
it does not render JS or take screenshots (that's an optional later step
using headless Playwright, also to be run inside the same isolated box).

Run:
    python src/fetch_pages.py --limit 100
"""

import argparse
import os
import time
import requests
import db

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
}

PAGES_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "pages")


def fetch_one(url_row, timeout=10):
    url_id = url_row["id"]
    url = url_row["url"]
    try:
        resp = requests.get(
            url, headers=HEADERS, timeout=timeout,
            allow_redirects=True, verify=False  # phishing certs are often broken/self-signed
        )
        html_path = os.path.join(PAGES_DIR, f"{url_id}.html")
        os.makedirs(PAGES_DIR, exist_ok=True)
        with open(html_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(resp.text)

        db.insert_page(
            url_id=url_id,
            html_path=html_path,
            status_code=resp.status_code,
            final_url=resp.url,
        )
        db.mark_url_status(url_id, "fetched")
        return True, None
    except requests.RequestException as e:
        db.insert_page(url_id=url_id, html_path=None, status_code=None,
                        final_url=None, error=str(e))
        db.mark_url_status(url_id, "failed")
        return False, str(e)


def main(limit: int, delay: float):
    db.init_db()
    pending = db.get_pending_urls(limit=limit)
    print(f"[*] {len(pending)} pending URLs to fetch")

    ok, failed = 0, 0
    for i, row in enumerate(pending, 1):
        success, err = fetch_one(row)
        if success:
            ok += 1
        else:
            failed += 1
        print(f"[{i}/{len(pending)}] {row['url'][:70]:<70} "
              f"{'OK' if success else 'FAIL: ' + str(err)[:40]}")
        time.sleep(delay)  # be polite / avoid hammering sites

    print(f"\n[=] Done. Fetched OK: {ok}  Failed: {failed}")


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()  # phishing sites often have invalid TLS certs

    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=100, help="Max URLs to fetch this run")
    parser.add_argument("--delay", type=float, default=0.5, help="Seconds between requests")
    args = parser.parse_args()
    main(args.limit, args.delay)
