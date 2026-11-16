"""
fingerprint.py
Turns raw saved HTML into structured "fingerprints":
  - ssdeep fuzzy hash of the whole page (lets us cluster near-identical kits
    even when attackers rename variables / tweak text)
  - structural features: number of forms, password fields, form action
    domains, script src domains, page title
  - simple suspicious-JS pattern flags (eval-wrapped blobs, known obfuscator
    signatures, etc.)

Run:
    python src/fingerprint.py
"""

import os
import re
import ppdeep
import tldextract
from bs4 import BeautifulSoup
import db

PAGES_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "pages")

# Lightweight signatures for common phishing-kit JS obfuscation styles.
# Not exhaustive - meant to be extended as you study real kits.
JS_SUSPICION_PATTERNS = {
    "eval_wrapped": re.compile(r"eval\s*\(\s*function\s*\("),
    "unescape_heavy": re.compile(r"unescape\s*\(.{0,20}%"),
    "document_write_obf": re.compile(r"document\.write\s*\(\s*unescape"),
    "base64_blob": re.compile(r"atob\s*\(['\"][A-Za-z0-9+/=]{40,}['\"]\)"),
    "fromcharcode_chain": re.compile(r"String\.fromCharCode\(\d+(,\s*\d+){10,}"),
}


def domain_of(url: str) -> str:
    if not url:
        return ""
    ext = tldextract.extract(url)
    return ".".join(part for part in [ext.domain, ext.suffix] if part)


def extract_features(html: str, base_url: str = ""):
    soup = BeautifulSoup(html, "lxml")

    title = soup.title.string.strip() if soup.title and soup.title.string else ""

    forms = soup.find_all("form")
    num_forms = len(forms)
    num_pw_fields = len(soup.find_all("input", {"type": "password"}))

    form_domains = set()
    for form in forms:
        action = form.get("action", "")
        if action.startswith("http"):
            form_domains.add(domain_of(action))

    script_domains = set()
    for script in soup.find_all("script", src=True):
        src = script["src"]
        if src.startswith("http"):
            script_domains.add(domain_of(src))

    js_flags = []
    for script in soup.find_all("script"):
        code = script.string or ""
        for name, pattern in JS_SUSPICION_PATTERNS.items():
            if pattern.search(code):
                js_flags.append(name)
    js_flags = sorted(set(js_flags))

    return {
        "title": title,
        "num_forms": num_forms,
        "num_password_fields": num_pw_fields,
        "form_domains": ",".join(sorted(form_domains)),
        "script_domains": ",".join(sorted(script_domains)),
        "js_flags": ",".join(js_flags),
    }


def process_all():
    db.init_db()
    conn = db.get_conn()
    cur = conn.cursor()
    cur.execute(
        """SELECT p.id as page_id, p.html_path, p.final_url
           FROM pages p
           LEFT JOIN fingerprints f ON f.page_id = p.id
           WHERE p.html_path IS NOT NULL AND f.id IS NULL"""
    )
    pages = cur.fetchall()
    conn.close()

    print(f"[*] {len(pages)} pages to fingerprint")
    done = 0
    for page in pages:
        html_path = page["html_path"]
        if not html_path or not os.path.exists(html_path):
            continue

        with open(html_path, "r", encoding="utf-8", errors="ignore") as f:
            html = f.read()

        if not html.strip():
            continue

        fuzzy_hash = ppdeep.hash(html.encode("utf-8", errors="ignore"))
        features = extract_features(html, page["final_url"] or "")

        db.insert_fingerprint(
            page_id=page["page_id"],
            ssdeep_hash=fuzzy_hash,
            title=features["title"],
            form_domains=features["form_domains"],
            script_domains=features["script_domains"],
            num_forms=features["num_forms"],
            num_pw=features["num_password_fields"],
            favicon_hash="",  # placeholder: add favicon hashing later if desired
            js_flags=features["js_flags"],
        )
        done += 1
        if done % 25 == 0:
            print(f"[*] {done}/{len(pages)} fingerprinted...")

    print(f"[=] Done. Fingerprinted {done} pages.")


if __name__ == "__main__":
    process_all()
