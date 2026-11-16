"""
main.py
Runs the full pipeline end to end:
  1. fetch_feeds  - pull phishing URLs from OpenPhish/URLhaus/PhishTank
  2. fetch_pages  - download the raw HTML of pending URLs
  3. fingerprint  - ssdeep hash + structural features for each page
  4. cluster      - group pages into phishing-kit clusters
  5. report       - print a human-readable summary and save a graph image

Run:
    python src/main.py --limit 100
"""

import argparse
import fetch_feeds
import fetch_pages
import fingerprint
import cluster
import report
import db


def main(limit: int, eps: float, min_samples: int, skip_feeds: bool):
    db.init_db()

    if not skip_feeds:
        print("\n===== STEP 1: Fetching feeds =====")
        fetch_feeds.fetch_openphish()
        fetch_feeds.fetch_urlhaus()
        fetch_feeds.fetch_phishtank()
    else:
        print("\n===== STEP 1: Skipped (--skip-feeds) =====")

    print("\n===== STEP 2: Fetching pages =====")
    fetch_pages.main(limit=limit, delay=0.5)

    print("\n===== STEP 3: Fingerprinting =====")
    fingerprint.process_all()

    print("\n===== STEP 4: Clustering =====")
    cluster.main(eps=eps, min_samples=min_samples)

    print("\n===== STEP 5: Report =====")
    report.generate()

    print("\n[=] Pipeline complete. See output/ for the report and graph.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=100,
                         help="Max pages to fetch+process this run")
    parser.add_argument("--eps", type=float, default=60,
                         help="DBSCAN distance threshold (lower = stricter clustering)")
    parser.add_argument("--min-samples", type=int, default=2)
    parser.add_argument("--skip-feeds", action="store_true",
                         help="Skip re-downloading feeds, just process what's already in the DB")
    args = parser.parse_args()
    main(args.limit, args.eps, args.min_samples, args.skip_feeds)
