"""
database.py — SQLite Analytics & Request Telemetry Store
OmniCache Gateway Observability Module

TECHNICAL EXPLANATION:
---------------------
To measure performance, an AI Gateway needs a persistent telemetry trail.
We track every request passing through the gateway:
- Was it a Cache HIT or a Cache MISS?
- What was the exact cosine similarity score?
- How many milliseconds of latency were saved?
- How many PII entities were redacted?
- How much money ($) was saved?

We use SQLite via Python's built-in `sqlite3` driver. This requires zero external
database setup, has zero cloud cost, and survives server restarts.
"""

import os
import sqlite3
import time
from typing import Dict, List, Any

DB_PATH = os.path.join(os.path.dirname(__file__), "omnicache.db")

def init_db():
    """Initializes the telemetry database and creates tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            client_ip TEXT,
            raw_prompt TEXT,
            sanitized_prompt TEXT,
            cache_status TEXT,
            similarity_score REAL,
            provider TEXT,
            latency_ms REAL,
            latency_saved_ms REAL,
            tokens_saved INTEGER,
            pii_count INTEGER
        )
    """)
    conn.commit()
    conn.close()

def log_request(
    client_ip: str,
    raw_prompt: str,
    sanitized_prompt: str,
    cache_status: str,
    similarity_score: float,
    provider: str,
    latency_ms: float,
    latency_saved_ms: float,
    tokens_saved: int,
    pii_count: int
):
    """Inserts a telemetry record into the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO request_logs (
            timestamp, client_ip, raw_prompt, sanitized_prompt,
            cache_status, similarity_score, provider, latency_ms,
            latency_saved_ms, tokens_saved, pii_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        time.time(), client_ip, raw_prompt, sanitized_prompt,
        cache_status, similarity_score, provider, latency_ms,
        latency_saved_ms, tokens_saved, pii_count
    ))
    conn.commit()
    conn.close()

def get_recent_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves the most recent telemetry logs in reverse chronological order."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM request_logs
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_metrics_summary() -> Dict[str, Any]:
    """Calculates real-time aggregate statistics for the dashboard."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM request_logs")
    total_requests = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM request_logs WHERE cache_status = 'HIT'")
    cache_hits = cursor.fetchone()[0]

    cache_misses = total_requests - cache_hits
    hit_ratio = (cache_hits / total_requests * 100.0) if total_requests > 0 else 0.0

    cursor.execute("SELECT SUM(tokens_saved), SUM(latency_saved_ms), SUM(pii_count) FROM request_logs")
    row = cursor.fetchone()
    total_tokens_saved = row[0] or 0
    total_latency_saved_ms = row[1] or 0.0
    total_pii_redacted = row[2] or 0

    conn.close()

    # Calculate dollar savings ($0.002 per 1k tokens)
    estimated_cost_saved_usd = (total_tokens_saved / 1000.0) * 0.002

    return {
        "total_requests": total_requests,
        "cache_hits": cache_hits,
        "cache_misses": cache_misses,
        "hit_ratio_percent": round(hit_ratio, 1),
        "total_tokens_saved": total_tokens_saved,
        "total_latency_saved_ms": round(total_latency_saved_ms, 1),
        "total_pii_redacted": total_pii_redacted,
        "estimated_cost_saved_usd": round(estimated_cost_saved_usd, 4)
    }

# Automatically initialize on module import
init_db()
