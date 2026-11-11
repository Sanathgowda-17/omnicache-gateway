"""
database.py — Persistent SQLite Store for Distributed Traces, Vector Index & Virtual Keys
OmniCache & Guard Enterprise Persistence Layer
"""

import os
import json
import time
import uuid
import sqlite3
import secrets
from typing import Dict, List, Any, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "omnicache.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes SQLite tables for traces, virtual API keys, and persistent vector cache."""
    conn = get_conn()
    cursor = conn.cursor()

    # 1. Distributed Trace Logs Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS request_traces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trace_id TEXT UNIQUE,
            timestamp REAL,
            client_ip TEXT,
            virtual_key_name TEXT,
            raw_prompt TEXT,
            sanitized_prompt TEXT,
            response_text TEXT,
            cache_status TEXT,
            similarity_score REAL,
            top_candidates_json TEXT,
            provider TEXT,
            latency_ms REAL,
            latency_saved_ms REAL,
            tokens_saved INTEGER,
            pii_count INTEGER,
            pii_audit_json TEXT,
            waf_violation_json TEXT
        )
    """)

    # 2. Virtual API Keys Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS virtual_keys (
            key_id TEXT PRIMARY KEY,
            key_secret TEXT UNIQUE,
            name TEXT,
            environment TEXT,
            rpm_limit INTEGER,
            requests_count INTEGER DEFAULT 0,
            tokens_used INTEGER DEFAULT 0,
            status TEXT DEFAULT 'ACTIVE',
            created_at REAL
        )
    """)

    # 3. Persistent Semantic Vector Entries Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vector_entries (
            entry_id TEXT PRIMARY KEY,
            prompt TEXT,
            sanitized_prompt TEXT,
            normalized_tokens TEXT,
            response TEXT,
            category TEXT,
            tokens_saved INTEGER,
            hit_count INTEGER DEFAULT 0,
            baseline_latency_ms REAL DEFAULT 850.0,
            created_at REAL,
            last_hit_at REAL
        )
    """)

    # Seed default Virtual API Keys if empty
    cursor.execute("SELECT COUNT(*) FROM virtual_keys")
    if cursor.fetchone()[0] == 0:
        default_keys = [
            ("vk_prod_01", "oc_live_9f8a7b6c5d4e3f2a1b0c9d8e", "Production Customer Support AI", "production", 60, 0, 0, "ACTIVE", time.time() - 86400 * 3),
            ("vk_rag_02", "oc_live_3c4d5e6f7a8b9c0d1e2f3a4b", "Internal Engineering Codebase RAG", "staging", 120, 0, 0, "ACTIVE", time.time() - 86400 * 1),
            ("vk_mob_03", "oc_test_7e6f5a4b3c2d1e0f9a8b7c6d", "Android Mobile Client Gateway", "development", 30, 0, 0, "ACTIVE", time.time() - 3600 * 5),
        ]
        cursor.executemany("""
            INSERT INTO virtual_keys (key_id, key_secret, name, environment, rpm_limit, requests_count, tokens_used, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, default_keys)

    conn.commit()
    conn.close()

# -----------------------------------------------------------------------------
# Trace Telemetry Operations
# -----------------------------------------------------------------------------
def log_trace(
    client_ip: str,
    virtual_key_name: str,
    raw_prompt: str,
    sanitized_prompt: str,
    response_text: str,
    cache_status: str,
    similarity_score: float,
    top_candidates: List[Dict[str, Any]],
    provider: str,
    latency_ms: float,
    latency_saved_ms: float,
    tokens_saved: int,
    pii_audit: List[Dict[str, Any]],
    waf_violation: Optional[Dict[str, Any]] = None
) -> str:
    trace_id = f"trc_{uuid.uuid4().hex[:12]}"
    pii_count = sum(item.get("count", 0) for item in pii_audit)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO request_traces (
            trace_id, timestamp, client_ip, virtual_key_name,
            raw_prompt, sanitized_prompt, response_text, cache_status,
            similarity_score, top_candidates_json, provider,
            latency_ms, latency_saved_ms, tokens_saved,
            pii_count, pii_audit_json, waf_violation_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        trace_id, time.time(), client_ip, virtual_key_name,
        raw_prompt, sanitized_prompt, response_text, cache_status,
        similarity_score, json.dumps(top_candidates), provider,
        latency_ms, latency_saved_ms, tokens_saved,
        pii_count, json.dumps(pii_audit),
        json.dumps(waf_violation) if waf_violation else None
    ))
    conn.commit()
    conn.close()
    return trace_id

def get_recent_logs(limit: int = 40) -> List[Dict[str, Any]]:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM request_traces
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        d = dict(r)
        d["top_candidates"] = json.loads(d["top_candidates_json"]) if d.get("top_candidates_json") else []
        d["pii_audit"] = json.loads(d["pii_audit_json"]) if d.get("pii_audit_json") else []
        d["waf_violation"] = json.loads(d["waf_violation_json"]) if d.get("waf_violation_json") else None
        results.append(d)
    return results

def get_trace_by_id(trace_id: str) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM request_traces WHERE trace_id = ?", (trace_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["top_candidates"] = json.loads(d["top_candidates_json"]) if d.get("top_candidates_json") else []
    d["pii_audit"] = json.loads(d["pii_audit_json"]) if d.get("pii_audit_json") else []
    d["waf_violation"] = json.loads(d["waf_violation_json"]) if d.get("waf_violation_json") else None
    return d

def get_metrics_summary() -> Dict[str, Any]:
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM request_traces")
    total_requests = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM request_traces WHERE cache_status = 'HIT'")
    cache_hits = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM request_traces WHERE cache_status = 'MISS'")
    cache_misses = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM request_traces WHERE cache_status = 'WAF_BLOCKED'")
    waf_blocked = cursor.fetchone()[0]

    valid_reqs = cache_hits + cache_misses
    hit_ratio = (cache_hits / valid_reqs * 100.0) if valid_reqs > 0 else 0.0

    cursor.execute("SELECT SUM(tokens_saved), SUM(latency_saved_ms), SUM(pii_count) FROM request_traces")
    row = cursor.fetchone()
    total_tokens_saved = row[0] or 0
    total_latency_saved_ms = row[1] or 0.0
    total_pii_redacted = row[2] or 0

    cursor.execute("SELECT AVG(latency_ms) FROM request_traces WHERE cache_status = 'HIT'")
    avg_hit_latency = cursor.fetchone()[0] or 1.4

    cursor.execute("SELECT AVG(latency_ms) FROM request_traces WHERE cache_status = 'MISS'")
    avg_miss_latency = cursor.fetchone()[0] or 580.0

    # Recent latency time-series (last 20 requests in chronological order)
    cursor.execute("""
        SELECT trace_id, cache_status, latency_ms, similarity_score, timestamp
        FROM request_traces
        ORDER BY id DESC
        LIMIT 20
    """)
    series_rows = [dict(r) for r in cursor.fetchall()][::-1]

    conn.close()

    estimated_cost_saved_usd = (total_tokens_saved / 1000.0) * 0.015  # Enterprise GPT-4o / Claude 3.5 benchmark rate
    speedup_multiplier = round(avg_miss_latency / max(avg_hit_latency, 0.2), 1)

    return {
        "total_requests": total_requests,
        "cache_hits": cache_hits,
        "cache_misses": cache_misses,
        "waf_blocked": waf_blocked,
        "hit_ratio_percent": round(hit_ratio, 1),
        "total_tokens_saved": total_tokens_saved,
        "total_latency_saved_ms": round(total_latency_saved_ms, 1),
        "avg_hit_latency_ms": round(avg_hit_latency, 2),
        "avg_miss_latency_ms": round(avg_miss_latency, 1),
        "speedup_multiplier": speedup_multiplier,
        "total_pii_redacted": total_pii_redacted,
        "estimated_cost_saved_usd": round(estimated_cost_saved_usd, 4),
        "latency_series": series_rows
    }

# -----------------------------------------------------------------------------
# Virtual API Keys Operations
# -----------------------------------------------------------------------------
def list_virtual_keys() -> List[Dict[str, Any]]:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM virtual_keys ORDER BY created_at DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def create_virtual_key(name: str, environment: str = "production", rpm_limit: int = 60) -> Dict[str, Any]:
    key_id = f"vk_{uuid.uuid4().hex[:8]}"
    prefix = "oc_live_" if environment == "production" else "oc_test_"
    key_secret = f"{prefix}{secrets.token_hex(12)}"
    now = time.time()

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO virtual_keys (key_id, key_secret, name, environment, rpm_limit, requests_count, tokens_used, status, created_at)
        VALUES (?, ?, ?, ?, ?, 0, 0, 'ACTIVE', ?)
    """, (key_id, key_secret, name, environment, rpm_limit, now))
    conn.commit()
    conn.close()

    return {
        "key_id": key_id,
        "key_secret": key_secret,
        "name": name,
        "environment": environment,
        "rpm_limit": rpm_limit,
        "requests_count": 0,
        "tokens_used": 0,
        "status": "ACTIVE",
        "created_at": now
    }

def delete_virtual_key(key_id: str) -> bool:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM virtual_keys WHERE key_id = ?", (key_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def validate_and_increment_key(key_secret: Optional[str], tokens_delta: int = 50) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    cursor = conn.cursor()
    if key_secret:
        cursor.execute("SELECT * FROM virtual_keys WHERE key_secret = ? AND status = 'ACTIVE'", (key_secret,))
        row = cursor.fetchone()
    else:
        cursor.execute("SELECT * FROM virtual_keys WHERE status = 'ACTIVE' ORDER BY created_at ASC LIMIT 1")
        row = cursor.fetchone()

    if not row:
        conn.close()
        return None

    key_data = dict(row)
    cursor.execute("""
        UPDATE virtual_keys
        SET requests_count = requests_count + 1,
            tokens_used = tokens_used + ?
        WHERE key_id = ?
    """, (tokens_delta, key_data["key_id"]))
    conn.commit()
    conn.close()
    return key_data

init_db()
