"""
rate_limiter.py — Token-Bucket High-Throughput Rate Limiter
OmniCache Gateway Core Traffic Control Module

TECHNICAL EXPLANATION:
---------------------
In production systems, unprotected AI endpoints are vulnerable to Denial of Service (DoS),
accidental infinite loops from client apps, and brute-force token exhaustion.

This module implements the industry-standard TOKEN-BUCKET ALGORITHM:
1. Each client (identified by IP or API Key) is allocated a virtual "bucket" with a maximum capacity (e.g. 20 tokens).
2. The bucket continuously refills at a fixed refill_rate (e.g. 5 tokens per second).
3. When a request arrives:
   - We calculate the time elapsed since the last request.
   - We add newly accrued tokens to the bucket up to the maximum capacity.
   - If the bucket has >= 1.0 token:
     -> Deduct 1 token and ALLOW the request (HTTP 200).
   - If the bucket has < 1.0 token:
     -> REJECT the request with HTTP 429 (Too Many Requests).
     -> Include a 'Retry-After' header indicating seconds until the next token refills.
"""

import time
from typing import Dict, Tuple

class TokenBucket:
    """A single token bucket for a specific client key."""
    def __init__(self, capacity: float, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()

    def consume(self, amount: float = 1.0) -> Tuple[bool, float]:
        """
        Attempts to consume tokens from the bucket.
        Returns:
            Tuple[bool, float]: (allowed, retry_after_seconds)
        """
        now = time.time()
        elapsed = now - self.last_refill
        self.last_refill = now

        # Add newly accrued tokens based on time passed
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)

        if self.tokens >= amount:
            self.tokens -= amount
            return True, 0.0
        else:
            # Calculate wait time needed for enough tokens to refill
            deficit = amount - self.tokens
            wait_time = deficit / self.refill_rate
            return False, wait_time

class RateLimiter:
    """
    Manages in-memory token buckets partitioned by client identifier (IP or API Key).
    """
    def __init__(self, default_capacity: float = 30.0, default_refill_rate: float = 5.0):
        self.default_capacity = default_capacity
        self.default_refill_rate = default_refill_rate
        self.buckets: Dict[str, TokenBucket] = {}

    def is_allowed(self, client_id: str, cost: float = 1.0) -> Tuple[bool, float]:
        """
        Checks if a client request should be allowed or throttled.

        Args:
            client_id (str): IP address or API key.
            cost (float): Number of tokens to consume (default 1.0).

        Returns:
            Tuple[bool, float]: (is_allowed, retry_after_seconds)
        """
        if client_id not in self.buckets:
            self.buckets[client_id] = TokenBucket(
                capacity=self.default_capacity,
                refill_rate=self.default_refill_rate
            )

        return self.buckets[client_id].consume(amount=cost)

    def get_client_status(self, client_id: str) -> Dict[str, float]:
        """Returns the current token balance for a client."""
        if client_id not in self.buckets:
            return {"tokens": self.default_capacity, "capacity": self.default_capacity}
        return {
            "tokens": round(self.buckets[client_id].tokens, 2),
            "capacity": self.default_capacity
        }

if __name__ == "__main__":
    # Self-test demonstration
    limiter = RateLimiter(default_capacity=3.0, default_refill_rate=1.0)
    client = "192.168.1.50"

    print("--- Simulating Burst of 5 Requests (Capacity is 3) ---")
    for i in range(1, 6):
        allowed, retry_after = limiter.is_allowed(client)
        status = "✅ ALLOWED" if allowed else f"🛑 THROTTLED (Retry after {retry_after:.2f}s)"
        print(f"Request {i}: {status}")

    print("\n--- Sleeping for 1.5 seconds (Refills ~1.5 tokens) ---")
    time.sleep(1.5)
    allowed, retry_after = limiter.is_allowed(client)
    status = "✅ ALLOWED" if allowed else f"🛑 THROTTLED (Retry after {retry_after:.2f}s)"
    print(f"Request 6: {status}")
