"""
app.py — OmniCache & Guard FastAPI Gateway
High-Throughput Semantic AI Reverse Proxy & Observability Service

TECHNICAL EXPLANATION:
---------------------
This is the core entry point of the gateway. It implements:
1. Traffic Rate Limiting (Token-Bucket per client IP).
2. PII Sanitization (Deterministic Regex Redaction).
3. Semantic Vector Caching (Cosine similarity search with sub-15ms hits).
4. Provider Cascade Fallback (Gemini Cloud -> Local Ollama -> Zero-Cost Synthetic).
5. OpenAI-Compatible REST Endpoints:
   - POST /v1/chat/completions (Drop-in replacement for OpenAI SDK / LangChain / curl)
   - POST /api/chat (Dashboard API)
   - GET /api/metrics (Observability Telemetry)
"""

import os
import time
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from sanitizer import PIISanitizer
from cache_engine import SemanticCacheEngine
from rate_limiter import RateLimiter
from provider_cascade import ProviderCascade
from database import log_request, get_recent_logs, get_metrics_summary

# -----------------------------------------------------------------------------
# App Initialization & Configuration
# -----------------------------------------------------------------------------
app = FastAPI(
    title="OmniCache & Guard Gateway",
    description="High-Throughput Semantic AI Reverse Proxy & Caching System",
    version="1.0.0"
)

# Enable CORS for cross-origin browser dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

# Core Engine Singletons
sanitizer = PIISanitizer(enabled=True)
cache_engine = SemanticCacheEngine(similarity_threshold=0.65)
rate_limiter = RateLimiter(default_capacity=40.0, default_refill_rate=5.0)
cascade = ProviderCascade()

# -----------------------------------------------------------------------------
# Request & Response Schemas
# -----------------------------------------------------------------------------
class ChatRequest(BaseModel):
    prompt: str = Field(..., description="The user question or system prompt")
    bypass_cache: bool = Field(False, description="Force fresh AI generation bypassing cache")
    similarity_threshold: Optional[float] = Field(None, description="Override similarity threshold (0.0 to 1.0)")

class OpenAIFormatMessage(BaseModel):
    role: str
    content: str

class OpenAIChatCompletionRequest(BaseModel):
    messages: List[OpenAIFormatMessage]
    model: Optional[str] = "gemini-1.5-flash"
    temperature: Optional[float] = 0.7

# -----------------------------------------------------------------------------
# Frontend Static Routes
# -----------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the real-time glassmorphic monitoring dashboard."""
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return HTMLResponse("<h1>OmniCache Gateway Active</h1><p>Frontend file missing.</p>")

@app.get("/style.css")
async def serve_css():
    css_file = os.path.join(FRONTEND_DIR, "style.css")
    return FileResponse(css_file, media_type="text/css")

@app.get("/app.js")
async def serve_js():
    js_file = os.path.join(FRONTEND_DIR, "app.js")
    return FileResponse(js_file, media_type="application/javascript")

# -----------------------------------------------------------------------------
# Core Gateway Endpoints
# -----------------------------------------------------------------------------
@app.post("/api/chat")
async def handle_chat(req: ChatRequest, request: Request):
    """
    Primary Gateway Processing Pipeline:
    1. Rate Limiting Check
    2. PII Sanitization
    3. Semantic Cache Lookup
    4. Provider Cascade Fallback
    5. Telemetry & Analytics Persistence
    """
    start_time = time.time()
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Step 1: Rate Limiter
    allowed, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Token bucket empty. Retry in {retry_after:.1f}s."
        )

    # Step 2: PII Sanitization
    sanitized_prompt, pii_audit = sanitizer.sanitize(req.prompt)
    pii_count = sum(item["count"] for item in pii_audit)

    # Apply temporary threshold if requested
    if req.similarity_threshold is not None:
        cache_engine.threshold = req.similarity_threshold

    # Step 3: Semantic Cache Lookup
    cache_match = None
    similarity_score = 0.0

    if not req.bypass_cache:
        cache_match, similarity_score = cache_engine.query(sanitized_prompt)

    # Path A: Cache HIT
    if cache_match:
        total_latency_ms = (time.time() - start_time) * 1000.0
        baseline_latency = cache_match.get("baseline_latency_ms", 1200.0)
        latency_saved_ms = max(0.0, baseline_latency - total_latency_ms)

        # Log to persistent database
        log_request(
            client_ip=client_ip,
            raw_prompt=req.prompt,
            sanitized_prompt=sanitized_prompt,
            cache_status="HIT",
            similarity_score=similarity_score,
            provider="OmniCache Semantic Memory",
            latency_ms=total_latency_ms,
            latency_saved_ms=latency_saved_ms,
            tokens_saved=cache_match["tokens_saved"],
            pii_count=pii_count
        )

        return {
            "response": cache_match["response"],
            "cache_status": "HIT",
            "similarity_score": round(similarity_score, 3),
            "provider": "OmniCache Semantic Memory (Zero API Cost)",
            "latency_ms": round(total_latency_ms, 1),
            "latency_saved_ms": round(latency_saved_ms, 1),
            "tokens_saved": cache_match["tokens_saved"],
            "pii_redacted": pii_audit,
            "matched_prompt": cache_match["prompt"]
        }

    # Path B: Cache MISS (Forward to AI Provider Cascade)
    ai_response, provider_name, provider_latency_ms = cascade.generate(sanitized_prompt)
    total_latency_ms = (time.time() - start_time) * 1000.0

    # Approximate token calculation: 1 word ~ 1.3 tokens
    estimated_tokens = int(len(ai_response.split()) * 1.3)

    # Save newly generated response into semantic cache
    cache_engine.add(
        raw_prompt=req.prompt,
        sanitized_prompt=sanitized_prompt,
        response=ai_response,
        tokens=estimated_tokens,
        baseline_latency_ms=total_latency_ms
    )

    # Log to persistent database
    log_request(
        client_ip=client_ip,
        raw_prompt=req.prompt,
        sanitized_prompt=sanitized_prompt,
        cache_status="MISS",
        similarity_score=similarity_score,
        provider=provider_name,
        latency_ms=total_latency_ms,
        latency_saved_ms=0.0,
        tokens_saved=0,
        pii_count=pii_count
    )

    return {
        "response": ai_response,
        "cache_status": "MISS",
        "similarity_score": round(similarity_score, 3),
        "provider": provider_name,
        "latency_ms": round(total_latency_ms, 1),
        "latency_saved_ms": 0.0,
        "tokens_saved": 0,
        "pii_redacted": pii_audit,
        "matched_prompt": None
    }

# -----------------------------------------------------------------------------
# OpenAI-Compatible Endpoint (/v1/chat/completions)
# -----------------------------------------------------------------------------
@app.post("/v1/chat/completions")
async def openai_compatible_chat(req: OpenAIChatCompletionRequest, request: Request):
    """
    OpenAI-Compatible endpoint. Allows any existing tool or LangChain script
    to point to OmniCache with zero code changes.
    """
    # Extract last user message
    user_messages = [m.content for m in req.messages if m.role == "user"]
    last_prompt = user_messages[-1] if user_messages else "Hello"

    chat_req = ChatRequest(prompt=last_prompt)
    result = await handle_chat(chat_req, request)

    return {
        "id": f"chatcmpl-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": result["response"]
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": len(last_prompt.split()),
            "completion_tokens": len(result["response"].split()),
            "total_tokens": len(last_prompt.split()) + len(result["response"].split())
        },
        "omnicache_metadata": {
            "cache_status": result["cache_status"],
            "similarity_score": result["similarity_score"],
            "latency_ms": result["latency_ms"],
            "provider": result["provider"]
        }
    }

# -----------------------------------------------------------------------------
# Telemetry & Admin Endpoints
# -----------------------------------------------------------------------------
@app.get("/api/metrics")
async def get_metrics():
    """Returns live analytics, savings, and cache hit ratio."""
    return get_metrics_summary()

@app.get("/api/logs")
async def get_logs(limit: int = 25):
    """Returns recent requests for the live stream log."""
    return get_recent_logs(limit=limit)

@app.post("/api/cache/clear")
async def clear_cache():
    """Clears in-memory semantic vector cache."""
    cache_engine.clear()
    return {"status": "success", "message": "Semantic cache memory cleared."}

@app.post("/api/cache/seed")
async def seed_cache():
    """Seeds the cache with 4 enterprise starter exemplars."""
    seeds = [
        ("How do I reset my account password?", "To reset your password, visit Settings > Security > Authentication. Select 'Change Password', verify your identity via two-factor authentication, and enter your new password."),
        ("What is the refund policy for enterprise plans?", "Enterprise plans are eligible for a 100% prorated refund within the first 30 days of contract execution. Submit a ticket to billing@company.com."),
        ("How do I deploy this service using Docker?", "Run 'docker build -t omnicache .' followed by 'docker run -d -p 8000:8000 omnicache'. The gateway will bind to port 8000 with auto-restart."),
        ("Explain how semantic caching saves API costs.", "Semantic caching converts user prompts into vector embeddings. When semantically identical questions are asked, it serves pre-computed completions in <15ms, eliminating redundant external LLM token fees.")
    ]
    for prompt, response in seeds:
        clean, _ = sanitizer.sanitize(prompt)
        cache_engine.add(prompt, clean, response, tokens=len(response.split()) * 2)

    return {"status": "success", "message": f"Seeded {len(seeds)} enterprise knowledge vectors."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
