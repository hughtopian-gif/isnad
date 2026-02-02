"""
Simple SQLite-based analytics for Isnad.
"""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
import threading

DB_PATH = Path("/data/analytics.db") if Path("/data").exists() else Path("analytics.db")

_local = threading.local()


def get_db():
    """Get thread-local database connection."""
    if not hasattr(_local, 'conn'):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _local.conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
    return _local.conn


def init_db():
    """Initialize the database tables."""
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            client_ip TEXT,
            skill_url TEXT,
            findings_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
        CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans(risk_level);
    """)
    conn.commit()


def record_scan(scan_id: str, content_hash: str, risk_level: str,
                client_ip: Optional[str] = None, skill_url: Optional[str] = None,
                findings_count: int = 0):
    """Record a scan in the database."""
    conn = get_db()
    conn.execute(
        """INSERT INTO scans (scan_id, content_hash, risk_level, client_ip, skill_url, findings_count)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (scan_id, content_hash, risk_level, client_ip, skill_url, findings_count)
    )
    conn.commit()


def get_stats():
    """Get usage statistics."""
    conn = get_db()

    now = datetime.utcnow()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_ago = today - timedelta(days=7)
    month_ago = today - timedelta(days=30)

    total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    today_count = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE created_at >= ?", (today.isoformat(),)
    ).fetchone()[0]
    week_count = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE created_at >= ?", (week_ago.isoformat(),)
    ).fetchone()[0]
    month_count = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE created_at >= ?", (month_ago.isoformat(),)
    ).fetchone()[0]

    risk_breakdown = {}
    for row in conn.execute(
        "SELECT risk_level, COUNT(*) as count FROM scans GROUP BY risk_level"
    ):
        risk_breakdown[row['risk_level']] = row['count']

    unique_ips = conn.execute(
        "SELECT COUNT(DISTINCT client_ip) FROM scans WHERE client_ip IS NOT NULL"
    ).fetchone()[0]

    daily = []
    for i in range(7):
        day = today - timedelta(days=i)
        next_day = day + timedelta(days=1)
        count = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE created_at >= ? AND created_at < ?",
            (day.isoformat(), next_day.isoformat())
        ).fetchone()[0]
        daily.append({"date": day.strftime("%Y-%m-%d"), "count": count})

    threats = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE risk_level IN ('high', 'critical')"
    ).fetchone()[0]

    return {
        "total_scans": total,
        "today": today_count,
        "this_week": week_count,
        "this_month": month_count,
        "unique_users": unique_ips,
        "threats_detected": threats,
        "by_risk_level": risk_breakdown,
        "daily_last_7_days": list(reversed(daily)),
        "generated_at": now.isoformat()
    }
