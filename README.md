# Phishing Infrastructure Detector

A tool that fingerprints live phishing campaigns by clustering pages that
reuse the same underlying HTML/JS "kit" — even when attackers rename
variables, re-skin the brand, or make small text edits. Most beginner
projects *simulate* phishing; this one does original detection research
against real, currently-active phishing infrastructure.

## What it does

1. Pulls confirmed phishing URLs from free threat-intel feeds (OpenPhish,
   URLhaus, optionally PhishTank).
2. Safely downloads the raw HTML of each page.
3. Fingerprints each page: a fuzzy hash (ssdeep) of the whole page, plus
   structural features (form actions, script domains, password fields,
   suspicious JS obfuscation patterns).
4. Clusters pages by fingerprint similarity (DBSCAN) to find "kits" —
   groups of phishing pages that are really the same template reused
   across many domains.
5. Outputs a markdown report + a graph image showing which domains share
   infrastructure.

## !! Safety first — read this before running anything !!

The URLs you'll be fetching are **live, confirmed-malicious** phishing
pages. Some do more than show a fake login form — a few redirect to
exploit kits or drive-by malware. Rules for running this safely:

- **Run it inside an isolated environment.** A disposable VM, a Docker
  container with no mounted secrets, or a free-tier cloud VM (Oracle
  Cloud's free tier, AWS/GCP free tier). Do **not** run it on your main
  laptop with your real browser profile, saved passwords, or SSH keys
  anywhere nearby.
- **Never submit real data into any form you find**, even "just to see
  what happens."
- The scripts here only do a plain HTTP GET and save the response text —
  they do not execute any JavaScript from the page, so you're not
  running attacker code, just reading static text. Still, treat the
  isolation step as non-optional.
- Your 8GB RAM / i3 / 50GB storage machine is plenty for everything
  *except* this one step — do the fetching on a free cloud VM (even the
  smallest free tier works), then copy the `data/` folder back to your
  main machine for the fingerprinting/clustering/report steps, which are
  all safe, CPU-only, and lightweight.

## Prerequisites

- Python 3.10+
- That's it for fuzzy hashing — this project uses `ppdeep`, a pure-Python
  reimplementation of the ssdeep/spamsum algorithm, so there's no C
  library or compiler to install (the original `ssdeep` PyPI package
  needs `libfuzzy` + a build toolchain and fails to build on several
  newer Python versions; `ppdeep` avoids all of that).
- (Optional) a free PhishTank API key from
  https://www.phishtank.com/api_register.php if you want that feed too.
  OpenPhish and URLhaus need no signup and are enough to get started.

## Step-by-step setup

```bash
# 1. Unzip the project and enter it
cd phishing-detector

# 2. Create a virtual environment (keeps this isolated from system Python)
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) set your PhishTank key
export PHISHTANK_API_KEY="your_key_here"   # Windows: set PHISHTANK_API_KEY=...
```

## Step-by-step execution

Run the whole pipeline in one go:

```bash
cd src
python main.py --limit 100
```

This will, in order:
1. Download the latest feeds into `data/phishing.db`
2. Fetch the HTML of up to 100 pending URLs
3. Fingerprint each page (ssdeep + structural features)
4. Cluster pages into kits
5. Write `output/cluster_report.md` and `output/cluster_graph.png`

Or run each stage individually, which is useful while you're learning
what each part does:

```bash
cd src

# Stage 1: pull URLs from feeds
python fetch_feeds.py

# Stage 2: download HTML for up to 100 pending URLs (RUN THIS IN AN ISOLATED VM)
python fetch_pages.py --limit 100

# Stage 3: fingerprint every downloaded page
python fingerprint.py

# Stage 4: cluster fingerprints into kits
python cluster.py --eps 60 --min-samples 2

# Stage 5: generate the report + graph
python report.py
```

## Reading the output

Open `output/cluster_report.md` — each cluster is a distinct phishing
*kit* your tool discovered, with:
- which domains are using it right now
- what page titles / brands it's impersonating
- any suspicious JS obfuscation patterns it flagged
- how many login forms / password fields it typically has

`output/cluster_graph.png` visualizes this as a graph: domains connected
by an edge are using the same underlying kit, even though they're
hosted on completely different domains.

## Tuning the clustering

- `--eps` (DBSCAN distance threshold, 0-100): lower = stricter matching
  (only near-identical pages cluster together), higher = looser (catches
  kits with more variation between copies). Start at 60 and adjust based
  on your results — if everything ends up in one giant cluster, lower
  it; if nothing clusters, raise it.
- `--min-samples`: minimum number of pages needed to call something a
  "cluster" rather than noise. 2 is a reasonable starting point for a
  small dataset.

## Extending this project (good next steps for a writeup)

- **Visual similarity**: add headless-browser screenshots (Playwright)
  + perceptual hashing (`imagehash`) to catch kits that were re-skinned
  with different HTML but look visually identical.
- **Favicon hashing**: many phishing kits ship with the original brand's
  favicon untouched — hash it and use it as another clustering signal.
- **JS deobfuscation**: pipe flagged scripts through `box-js` to see
  what they're actually trying to do (usually credential exfil to a
  Telegram bot or a Discord webhook).
- **Takedown-readiness report**: cross-reference each cluster's domains
  against WHOIS/registrar data to show how fast-flux or disposable the
  infrastructure is — this is the kind of finding that makes a great
  writeup or blog post.
- **Historical tracking**: re-run the pipeline daily (cron) and track how
  long each kit stays online before it's taken down — real research
  value, not just a one-off scan.

## Why this project stands out

Most beginner offensive-security portfolios show "I ran tool X against
target Y." This project instead builds original detection tooling and
produces a dataset you can write about — e.g. "I found N phishing
campaigns reusing the same kit across M domains, and here's how long
they stayed live." That's the kind of finding a hiring manager actually
remembers.
