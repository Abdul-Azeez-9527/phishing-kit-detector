"""
db.py
SQLite storage layer for the phishing infrastructure detector.

Keeps everything in one local file (data/phishing.db) - no server needed,
fits easily inside the storage budget on a low-spec machine.
"""

import sqlite3
import os
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "phishing.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE NOT NULL,
            source TEXT NOT NULL,          -- openphish / phishtank / urlhaus
            domain TEXT,
            first_seen TEXT NOT NULL,
            status TEXT DEFAULT 'pending'  -- pending / fetched / failed
        );

        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url_id INTEGER NOT NULL REFERENCES urls(id),
            html_path TEXT,                -- path to saved raw HTML on disk
            fetched_at TEXT NOT NULL,
            status_code INTEGER,
            final_url TEXT,                -- after redirects
            error TEXT
        );

        CREATE TABLE IF NOT EXISTS fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_id INTEGER NOT NULL REFERENCES pages(id),
            ssdeep_hash TEXT,
            title TEXT,
            form_action_domains TEXT,      -- comma separated
            script_src_domains TEXT,       -- comma separated
            num_forms INTEGER,
            num_password_fields INTEGER,
            favicon_hash TEXT,
            suspicious_js_flags TEXT        -- comma separated pattern names matched
        );

        CREATE TABLE IF NOT EXISTS clusters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cluster_label INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cluster_members (
            cluster_id INTEGER NOT NULL REFERENCES clusters(id),
            fingerprint_id INTEGER NOT NULL REFERENCES fingerprints(id),
            PRIMARY KEY (cluster_id, fingerprint_id)
        );
        """
    )
    conn.commit()
    conn.close()


def now():
    return datetime.now(timezone.utc).isoformat()


def insert_url(url: str, source: str, domain: str) -> int | None:
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO urls (url, source, domain, first_seen) VALUES (?, ?, ?, ?)",
            (url, source, domain, now()),
        )
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        # already have this URL
        cur.execute("SELECT id FROM urls WHERE url = ?", (url,))
        row = cur.fetchone()
        return row["id"] if row else None
    finally:
        conn.close()


def get_pending_urls(limit: int = 200):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM urls WHERE status = 'pending' LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows


def mark_url_status(url_id: int, status: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE urls SET status = ? WHERE id = ?", (status, url_id))
    conn.commit()
    conn.close()


def insert_page(url_id: int, html_path: str, status_code: int, final_url: str, error: str = None) -> int:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO pages (url_id, html_path, fetched_at, status_code, final_url, error)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (url_id, html_path, now(), status_code, final_url, error),
    )
    conn.commit()
    page_id = cur.lastrowid
    conn.close()
    return page_id


def insert_fingerprint(page_id: int, ssdeep_hash: str, title: str, form_domains: str,
                        script_domains: str, num_forms: int, num_pw: int,
                        favicon_hash: str, js_flags: str) -> int:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO fingerprints
           (page_id, ssdeep_hash, title, form_action_domains, script_src_domains,
            num_forms, num_password_fields, favicon_hash, suspicious_js_flags)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (page_id, ssdeep_hash, title, form_domains, script_domains, num_forms,
         num_pw, favicon_hash, js_flags),
    )
    conn.commit()
    fid = cur.lastrowid
    conn.close()
    return fid


def all_fingerprints():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """SELECT f.*, p.final_url, u.domain, u.source
           FROM fingerprints f
           JOIN pages p ON f.page_id = p.id
           JOIN urls u ON p.url_id = u.id
           WHERE f.ssdeep_hash IS NOT NULL"""
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def save_cluster(label: int, fingerprint_ids: list[int]) -> int:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO clusters (cluster_label, created_at) VALUES (?, ?)", (label, now()))
    cluster_id = cur.lastrowid
    cur.executemany(
        "INSERT OR IGNORE INTO cluster_members (cluster_id, fingerprint_id) VALUES (?, ?)",
        [(cluster_id, fid) for fid in fingerprint_ids],
    )
    conn.commit()
    conn.close()
    return cluster_id
