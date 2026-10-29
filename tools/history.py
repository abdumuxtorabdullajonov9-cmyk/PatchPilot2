import json
import os
import sqlite3
import time

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "history", "patchpilot.db"))


def _conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            repo_url TEXT,
            files_scanned INTEGER,
            total_findings INTEGER,
            semgrep_findings INTEGER,
            ai_findings INTEGER,
            fixed INTEGER,
            duration REAL,
            details TEXT
        )"""
    )
    return conn


def save_scan(rep: dict) -> int:
    details = []
    for fr in rep["files"]:
        for r in fr.get("results", []):
            details.append({
                "file": fr["rel_path"],
                "line": r["line"],
                "rule": r["check_id"],
                "severity": r["severity"],
                "source": "AI audit" if r["check_id"].startswith("ai.audit.") else "Semgrep rules",
                "status": r["status"],
                "method": r["method"],
                "note": r["note"],
                "explanation": r["explanation"],
                "snippet": r["snippet"],
                "diff": r["diff"],
            })
    fixed = sum(1 for d in details if d["status"] == "fixed")

    conn = _conn()
    try:
        cur = conn.execute(
            """INSERT INTO scans
               (ts, repo_url, files_scanned, total_findings, semgrep_findings, ai_findings, fixed, duration, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                time.strftime("%Y-%m-%d %H:%M:%S"),
                rep["repo_url"],
                len(rep["scan"]["scanned"]),
                rep["total_findings"],
                rep["semgrep_findings"],
                rep["ai_findings"],
                fixed,
                rep["duration"],
                json.dumps(details),
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_scans(limit: int = 200) -> list:
    conn = _conn()
    try:
        rows = conn.execute(
            """SELECT id, ts, repo_url, files_scanned, total_findings, semgrep_findings,
                      ai_findings, fixed, duration
               FROM scans ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    cols = ["id", "ts", "repo_url", "files_scanned", "total_findings",
            "semgrep_findings", "ai_findings", "fixed", "duration"]
    return [dict(zip(cols, r)) for r in rows]


def get_scan(scan_id: int) -> dict:
    conn = _conn()
    try:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return {}
    cols = ["id", "ts", "repo_url", "files_scanned", "total_findings", "semgrep_findings",
            "ai_findings", "fixed", "duration", "details"]
    d = dict(zip(cols, row))
    d["details"] = json.loads(d["details"] or "[]")
    return d