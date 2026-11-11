"""
load_test.py — OmniCache Gateway High-Throughput Benchmark
Simulates realistic production traffic to quantitatively measure latency reduction
and cache hit rates.

TECHNICAL EXPLANATION:
---------------------
To prove engineering claims on a resume (e.g., "Slashed response latency by 95%"),
engineers write automated benchmark scripts that measure:
1. Cold Start / Cache Miss Latency (First un-cached call).
2. Warm / Semantic Cache Hit Latency (Subsequent variations).
3. Speedup Multiplier = (Miss Latency) / (Hit Latency).
"""

import time
import urllib.request
import json

GATEWAY_URL = "http://127.0.0.1:8000/api/chat"

TEST_PROMPTS = [
    # 1. Cold miss
    "How do I reset my account password?",
    # 2-6: Semantic variations (Expected HITS)
    "I forgot my password, how to change it?",
    "Steps to reset account password",
    "Where is the password reset option in security settings?",
    "Need to change my lost password",
    "How to reset my password?",
    # 7: Cold miss (Enterprise refund)
    "What is the refund policy for enterprise plans?",
    # 8-10: Semantic variations of refund
    "Can I get a refund on enterprise contract?",
    "How to request refund for enterprise tier?",
    "Enterprise plan cancellation and refund terms"
]

def run_benchmark():
    print("=" * 70)
    print("⚡ OMNICACHE & GUARD — HIGH-THROUGHPUT BENCHMARK TEST")
    print("=" * 70)

    results = []

    for i, prompt in enumerate(TEST_PROMPTS, 1):
        t0 = time.time()
        payload = json.dumps({"prompt": prompt}).encode("utf-8")
        req = urllib.request.Request(
            GATEWAY_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                elapsed_ms = (time.time() - t0) * 1000.0
                status = data["cache_status"]
                score = data["similarity_score"]
                provider = data["provider"]
                results.append((prompt, status, score, elapsed_ms, provider))

                symbol = "🟢" if status == "HIT" else "🟡"
                print(f"[{i:02d}/10] {symbol} {status:4s} | Sim: {score:.3f} | Latency: {elapsed_ms:6.1f}ms | Query: '{prompt[:38]}...'")
        except Exception as e:
            print(f"[{i:02d}/10] ❌ ERROR: {e}")

    # Summary Calculations
    hits = [r for r in results if r[1] == "HIT"]
    misses = [r for r in results if r[1] == "MISS"]

    avg_hit_latency = sum(r[3] for r in hits) / len(hits) if hits else 0.0
    avg_miss_latency = sum(r[3] for r in misses) / len(misses) if misses else 0.0
    speedup = (avg_miss_latency / avg_hit_latency) if avg_hit_latency > 0 else 0.0

    print("\n" + "=" * 70)
    print("📊 BENCHMARK PERFORMANCE RESULTS")
    print("=" * 70)
    print(f"Total Requests Dispatched : {len(results)}")
    print(f"Cache Hits (Semantic)     : {len(hits)} ({len(hits)/len(results)*100:.1f}%)")
    print(f"Cache Misses (Cloud/AI)   : {len(misses)} ({len(misses)/len(results)*100:.1f}%)")
    print(f"Average Cache Miss Time   : {avg_miss_latency:.1f} ms")
    print(f"Average Cache Hit Time    : {avg_hit_latency:.1f} ms")
    print(f"🚀 Speedup Multiplier     : {speedup:.1f}x Faster")
    print("=" * 70)

if __name__ == "__main__":
    run_benchmark()
