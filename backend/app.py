"""
app.py — OmniCache & Guard Enterprise AI Gateway & LLMOps Platform
High-Throughput Semantic Reverse Proxy, WAF/DLP Firewall, Vector Explorer & Trace Engine
"""

import os
import time
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from sanitizer import SecurityGuard
from cache_engine import SemanticCacheEngine, compute_vector_signature
from rate_limiter import RateLimiter
from provider_cascade import ProviderCascade
from database import (
    log_trace,
    get_recent_logs,
    get_trace_by_id,
    get_metrics_summary,
    list_virtual_keys,
    create_virtual_key,
    delete_virtual_key,
    validate_and_increment_key
)

app = FastAPI(
    title="OmniCache & Guard — Enterprise AI Gateway",
    description="Distributed Semantic Vector Cache, Prompt-Injection WAF, DLP Scrubber & OpenAI Proxy",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

# Core Singletons
security_guard = SecurityGuard()
cache_engine = SemanticCacheEngine(similarity_threshold=0.62)
rate_limiter = RateLimiter(default_capacity=50.0, default_refill_rate=5.0)
cascade = ProviderCascade()

# -----------------------------------------------------------------------------
# Request Models
# -----------------------------------------------------------------------------
class ChatRequest(BaseModel):
    prompt: str = Field(..., description="User prompt or query")
    bypass_cache: bool = Field(False, description="Force upstream LLM call")
    similarity_threshold: Optional[float] = Field(None, description="Cosine similarity threshold override")
    virtual_key: Optional[str] = Field(None, description="Virtual API Key (oc_live_...)")
    gemini_api_key: Optional[str] = Field(None, description="Optional live Gemini API key")

class VectorCreateRequest(BaseModel):
    prompt: str
    response: str
    category: str = "Custom Canonical"

class VectorSearchRequest(BaseModel):
    query: str
    top_k: int = 6

class KeyCreateRequest(BaseModel):
    name: str
    environment: str = "production"
    rpm_limit: int = 60

class PolicyToggleRequest(BaseModel):
    category: str  # "waf" or "dlp"
    rule_id: str
    enabled: bool

class OpenAIMessage(BaseModel):
    role: str
    content: str

class OpenAIChatCompletionRequest(BaseModel):
    messages: List[OpenAIMessage]
    model: Optional[str] = "gemini-2.0-flash"
    temperature: Optional[float] = 0.4

# -----------------------------------------------------------------------------
# Frontend Static Asset Serving
# -----------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    return FileResponse(index_file, headers={"Cache-Control": "no-store"})

@app.get("/style.css")
async def serve_css():
    css_file = os.path.join(FRONTEND_DIR, "style.css")
    return FileResponse(css_file, media_type="text/css", headers={"Cache-Control": "no-store"})

@app.get("/app.js")
async def serve_js():
    js_file = os.path.join(FRONTEND_DIR, "app.js")
    return FileResponse(js_file, media_type="application/javascript", headers={"Cache-Control": "no-store"})

# -----------------------------------------------------------------------------
# 1. Primary Gateway Inference Pipeline (/api/chat)
# -----------------------------------------------------------------------------
@app.post("/api/chat")
async def handle_chat(req: ChatRequest, request: Request):
    start_time = time.time()
    client_ip = request.client.host if request.client else "127.0.0.1"
    header_gemini_key = request.headers.get("x-gemini-key") or req.gemini_api_key
    header_virtual_key = request.headers.get("x-virtual-key") or req.virtual_key

    # Step 1: Virtual API Key & Token-Bucket Rate Limiting
    key_record = validate_and_increment_key(header_virtual_key, tokens_delta=45)
    key_name = key_record["name"] if key_record else "Default Gateway Key"
    rate_bucket_id = key_record["key_id"] if key_record else client_ip

    allowed, retry_after = rate_limiter.is_allowed(rate_bucket_id)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded for '{key_name}'. Retry in {retry_after:.1f}s."
        )

    # Step 2: Prompt Injection & Jailbreak WAF Inspection
    waf_violation = security_guard.inspect_waf(req.prompt)
    if waf_violation:
        total_latency_ms = (time.time() - start_time) * 1000.0
        block_msg = (
            f"🛑 WAF SECURITY BLOCK [{waf_violation['severity']}]: "
            f"Triggered rule '{waf_violation['rule_name']}' on payload `{waf_violation['matched_payload']}`."
        )
        trace_id = log_trace(
            client_ip=client_ip,
            virtual_key_name=key_name,
            raw_prompt=req.prompt,
            sanitized_prompt="[BLOCKED_BY_WAF]",
            response_text=block_msg,
            cache_status="WAF_BLOCKED",
            similarity_score=0.0,
            top_candidates=[],
            provider="OmniCache Edge WAF",
            latency_ms=total_latency_ms,
            latency_saved_ms=0.0,
            tokens_saved=0,
            pii_audit=[],
            waf_violation=waf_violation
        )
        return {
            "trace_id": trace_id,
            "response": block_msg,
            "cache_status": "WAF_BLOCKED",
            "similarity_score": 0.0,
            "top_candidates": [],
            "vector_preview": compute_vector_signature(req.prompt),
            "provider": "OmniCache Edge WAF (Request Terminated)",
            "latency_ms": round(total_latency_ms, 2),
            "latency_saved_ms": 0.0,
            "tokens_saved": 0,
            "pii_redacted": [],
            "waf_violation": waf_violation,
            "sanitized_prompt": "[BLOCKED_BY_WAF]",
            "virtual_key_name": key_name,
            "matched_prompt": None
        }

    # Step 3: DLP / PII Sanitization
    sanitized_prompt, pii_audit = security_guard.sanitize(req.prompt)

    if req.similarity_threshold is not None:
        cache_engine.threshold = req.similarity_threshold

    # Step 4: Hybrid Semantic Vector Cache Lookup
    cache_match = None
    similarity_score = 0.0
    top_candidates = []

    if not req.bypass_cache:
        cache_match, similarity_score, top_candidates = cache_engine.query(sanitized_prompt, top_k=4)
    else:
        _, similarity_score, top_candidates = cache_engine.query(sanitized_prompt, top_k=4)

    # Path A: Semantic Cache HIT
    if cache_match and not req.bypass_cache:
        total_latency_ms = (time.time() - start_time) * 1000.0
        baseline_latency = cache_match.get("baseline_latency_ms", 850.0)
        latency_saved_ms = max(0.0, baseline_latency - total_latency_ms)

        trace_id = log_trace(
            client_ip=client_ip,
            virtual_key_name=key_name,
            raw_prompt=req.prompt,
            sanitized_prompt=sanitized_prompt,
            response_text=cache_match["response"],
            cache_status="HIT",
            similarity_score=similarity_score,
            top_candidates=top_candidates,
            provider="OmniCache Vector Memory",
            latency_ms=total_latency_ms,
            latency_saved_ms=latency_saved_ms,
            tokens_saved=cache_match["tokens_saved"],
            pii_audit=pii_audit
        )

        return {
            "trace_id": trace_id,
            "response": cache_match["response"],
            "cache_status": "HIT",
            "similarity_score": round(similarity_score, 3),
            "top_candidates": top_candidates,
            "vector_preview": compute_vector_signature(sanitized_prompt),
            "provider": "OmniCache Vector Memory ($0.00 API Cost)",
            "latency_ms": round(total_latency_ms, 2),
            "latency_saved_ms": round(latency_saved_ms, 1),
            "tokens_saved": cache_match["tokens_saved"],
            "pii_redacted": pii_audit,
            "waf_violation": None,
            "sanitized_prompt": sanitized_prompt,
            "virtual_key_name": key_name,
            "matched_prompt": cache_match["prompt"]
        }

    # Path B: Semantic Cache MISS -> Route to Upstream Provider Cascade
    ai_response, provider_name, _ = cascade.generate(sanitized_prompt, custom_api_key=header_gemini_key)
    total_latency_ms = (time.time() - start_time) * 1000.0
    estimated_tokens = max(45, int(len(ai_response.split()) * 1.35))

    # Index newly generated completion into persistent vector memory
    cache_engine.add(
        raw_prompt=req.prompt,
        sanitized_prompt=sanitized_prompt,
        response=ai_response,
        tokens=estimated_tokens,
        baseline_latency_ms=total_latency_ms,
        category="Auto-Indexed"
    )

    trace_id = log_trace(
        client_ip=client_ip,
        virtual_key_name=key_name,
        raw_prompt=req.prompt,
        sanitized_prompt=sanitized_prompt,
        response_text=ai_response,
        cache_status="MISS",
        similarity_score=similarity_score,
        top_candidates=top_candidates,
        provider=provider_name,
        latency_ms=total_latency_ms,
        latency_saved_ms=0.0,
        tokens_saved=0,
        pii_audit=pii_audit
    )

    return {
        "trace_id": trace_id,
        "response": ai_response,
        "cache_status": "MISS",
        "similarity_score": round(similarity_score, 3),
        "top_candidates": top_candidates,
        "vector_preview": compute_vector_signature(sanitized_prompt),
        "provider": provider_name,
        "latency_ms": round(total_latency_ms, 1),
        "latency_saved_ms": 0.0,
        "tokens_saved": 0,
        "pii_redacted": pii_audit,
        "waf_violation": None,
        "sanitized_prompt": sanitized_prompt,
        "virtual_key_name": key_name,
        "matched_prompt": None
    }

# -----------------------------------------------------------------------------
# 2. Side-by-Side Speed Race Benchmark Endpoint (/api/race)
# -----------------------------------------------------------------------------
@app.post("/api/race")
async def run_side_by_side_race(req: ChatRequest, request: Request):
    """
    Executes a two-leg benchmark on the exact same prompt:
      Leg 1: Uncached Upstream LLM Call (Ensures vector is indexed)
      Leg 2: Warm OmniCache Vector Memory Lookup
    Returns exact timings and speedup ratio for the visual split-screen race UI.
    """
    sanitized_prompt, _ = security_guard.sanitize(req.prompt)
    header_gemini_key = request.headers.get("x-gemini-key") or req.gemini_api_key

    # Leg 1: Uncached Upstream Inference
    t0_miss = time.time()
    ai_res, provider_name, _ = cascade.generate(sanitized_prompt, custom_api_key=header_gemini_key)
    uncached_latency_ms = (time.time() - t0_miss) * 1000.0
    tokens = max(50, int(len(ai_res.split()) * 1.35))

    cache_engine.add(
        raw_prompt=req.prompt,
        sanitized_prompt=sanitized_prompt,
        response=ai_res,
        tokens=tokens,
        baseline_latency_ms=uncached_latency_ms,
        category="Race Benchmark"
    )

    # Leg 2: OmniCache Vector Memory Lookup
    t0_hit = time.time()
    matched, sim_score, candidates = cache_engine.query(sanitized_prompt, top_k=3)
    cached_latency_ms = max(0.35, (time.time() - t0_hit) * 1000.0)

    speedup = round(uncached_latency_ms / cached_latency_ms, 1)

    log_trace(
        client_ip="127.0.0.1",
        virtual_key_name="Benchmark Race Runner",
        raw_prompt=req.prompt,
        sanitized_prompt=sanitized_prompt,
        response_text=ai_res,
        cache_status="HIT",
        similarity_score=sim_score,
        top_candidates=candidates,
        provider="OmniCache Vector Memory",
        latency_ms=cached_latency_ms,
        latency_saved_ms=uncached_latency_ms - cached_latency_ms,
        tokens_saved=tokens,
        pii_audit=[]
    )

    return {
        "prompt": req.prompt,
        "uncached": {
            "latency_ms": round(uncached_latency_ms, 1),
            "provider": provider_name,
            "cost_usd": round((tokens / 1000.0) * 0.015, 5),
            "tokens": tokens
        },
        "cached": {
            "latency_ms": round(cached_latency_ms, 2),
            "provider": "OmniCache Vector Memory",
            "similarity_score": round(sim_score, 3),
            "cost_usd": 0.0
        },
        "speedup_multiplier": speedup,
        "latency_saved_ms": round(uncached_latency_ms - cached_latency_ms, 1),
        "response": ai_res
    }

# -----------------------------------------------------------------------------
# 3. OpenAI-Compatible Proxy Endpoint (/v1/chat/completions)
# -----------------------------------------------------------------------------
@app.post("/v1/chat/completions")
async def openai_compatible_chat(req: OpenAIChatCompletionRequest, request: Request):
    user_messages = [m.content for m in req.messages if m.role == "user"]
    last_prompt = user_messages[-1] if user_messages else "Hello"

    chat_req = ChatRequest(prompt=last_prompt)
    result = await handle_chat(chat_req, request)

    return {
        "id": result["trace_id"],
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": result["response"]},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": len(last_prompt.split()),
            "completion_tokens": len(result["response"].split()),
            "total_tokens": len(last_prompt.split()) + len(result["response"].split())
        },
        "omnicache": {
            "trace_id": result["trace_id"],
            "cache_status": result["cache_status"],
            "similarity_score": result["similarity_score"],
            "latency_ms": result["latency_ms"],
            "provider": result["provider"]
        }
    }

# -----------------------------------------------------------------------------
# 4. Observability, Vector Explorer, Virtual Keys & Security Policy Endpoints
# -----------------------------------------------------------------------------
@app.get("/api/metrics")
async def get_metrics():
    summary = get_metrics_summary()
    summary["circuit_breaker"] = cascade.circuit_breaker.status_dict()
    summary["indexed_vectors_count"] = len(cache_engine.entries)
    summary["similarity_threshold"] = cache_engine.threshold
    return summary

@app.get("/api/logs")
async def get_logs(limit: int = 35):
    return get_recent_logs(limit=limit)

@app.get("/api/logs/{trace_id}")
async def get_single_trace(trace_id: str):
    trace = get_trace_by_id(trace_id)
    if not trace:
        raise HTTPException(status_code=404, detail="Trace not found")
    return trace

@app.get("/api/vectors")
async def get_vectors():
    return cache_engine.list_entries()

@app.post("/api/vectors")
async def add_custom_vector(req: VectorCreateRequest):
    clean, _ = security_guard.sanitize(req.prompt)
    entry = cache_engine.add(
        raw_prompt=req.prompt,
        sanitized_prompt=clean,
        response=req.response,
        tokens=max(40, int(len(req.response.split()) * 1.35)),
        baseline_latency_ms=920.0,
        category=req.category
    )
    return entry

@app.delete("/api/vectors/{entry_id}")
async def remove_vector(entry_id: str):
    cache_engine.delete_entry(entry_id)
    return {"status": "deleted", "entry_id": entry_id}

@app.post("/api/vectors/search")
async def search_vectors(req: VectorSearchRequest):
    clean, _ = security_guard.sanitize(req.query)
    _, best_score, candidates = cache_engine.query(clean, top_k=req.top_k)
    return {
        "query": req.query,
        "normalized": clean,
        "best_score": round(best_score, 4),
        "threshold": cache_engine.threshold,
        "candidates": candidates
    }

@app.post("/api/cache/seed")
async def seed_cache():
    count = cache_engine.seed_defaults()
    return {"status": "success", "message": f"Indexed {count} canonical enterprise vectors."}

@app.post("/api/cache/clear")
async def clear_cache():
    cache_engine.clear()
    return {"status": "success", "message": "Vector index cleared."}

@app.get("/api/keys")
async def get_keys():
    return list_virtual_keys()

@app.post("/api/keys")
async def create_key(req: KeyCreateRequest):
    return create_virtual_key(req.name, req.environment, req.rpm_limit)

@app.delete("/api/keys/{key_id}")
async def revoke_key(key_id: str):
    delete_virtual_key(key_id)
    return {"status": "revoked", "key_id": key_id}

@app.get("/api/security/policies")
async def get_security_policies():
    return security_guard.get_policies()

@app.post("/api/security/policies")
async def update_security_policy(req: PolicyToggleRequest):
    ok = security_guard.update_policy(req.category, req.rule_id, req.enabled)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid policy ID")
    return security_guard.get_policies()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
