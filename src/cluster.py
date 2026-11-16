"""
cluster.py
Groups fingerprinted phishing pages into "kits" - clusters of pages that
reuse the same underlying HTML/JS template, even if attackers tweaked
text, renamed variables, or changed the brand being impersonated.

Method:
  1. Pull all ssdeep hashes from the DB.
  2. Build a pairwise similarity matrix using ssdeep.compare() (0-100 score).
  3. Convert similarity -> distance (100 - score) and run DBSCAN with a
     precomputed distance metric (no need for a feature-vector embedding).
  4. Save cluster assignments back to the DB.

ssdeep.compare() is O(n^2), which is fine for a few thousand pages on a
low-spec machine, but if you scale past ~5000 pages you'll want to shard
by score pre-filtering (ssdeep's own chunking) or move to tlsh for speed.

Run:
    python src/cluster.py --eps 60 --min-samples 2
"""

import argparse
import numpy as np
import ppdeep
from sklearn.cluster import DBSCAN
import db


def build_distance_matrix(hashes: list[str]) -> np.ndarray:
    n = len(hashes)
    dist = np.zeros((n, n), dtype=float)
    for i in range(n):
        for j in range(i + 1, n):
            score = ppdeep.compare(hashes[i], hashes[j])  # 0-100 similarity
            d = 100 - score
            dist[i, j] = d
            dist[j, i] = d
    return dist


def main(eps: float, min_samples: int):
    db.init_db()
    rows = db.all_fingerprints()
    if len(rows) < 2:
        print("[!] Not enough fingerprints to cluster yet. Run fetch_feeds.py, "
              "fetch_pages.py, and fingerprint.py first.")
        return

    hashes = [r["ssdeep_hash"] for r in rows]
    fids = [r["id"] for r in rows]

    print(f"[*] Building {len(hashes)}x{len(hashes)} similarity matrix "
          f"(this is the slow step)...")
    dist_matrix = build_distance_matrix(hashes)

    print(f"[*] Running DBSCAN (eps={eps}, min_samples={min_samples})...")
    model = DBSCAN(eps=eps, min_samples=min_samples, metric="precomputed")
    labels = model.fit_predict(dist_matrix)

    clusters = {}
    for fid, label in zip(fids, labels):
        if label == -1:
            continue  # noise point, not part of any kit cluster
        clusters.setdefault(label, []).append(fid)

    print(f"[=] Found {len(clusters)} clusters "
          f"({sum(1 for l in labels if l == -1)} pages unclustered)")

    for label, members in clusters.items():
        db.save_cluster(int(label), members)
        # Show a quick summary: which domains/titles are in this kit
        sample = [r for r in rows if r["id"] in members][:5]
        titles = {r["title"] for r in sample if r["title"]}
        domains = {r["domain"] for r in sample if r["domain"]}
        print(f"  Cluster {label}: {len(members)} pages | "
              f"titles sample: {list(titles)[:3]} | domains sample: {list(domains)[:3]}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--eps", type=float, default=60,
                         help="Max distance (100 - similarity) to be same cluster. Lower = stricter.")
    parser.add_argument("--min-samples", type=int, default=2,
                         help="Min pages to form a cluster")
    args = parser.parse_args()
    main(args.eps, args.min_samples)
