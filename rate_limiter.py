"""
In-memory sliding-window rate limiter for brute-force protection and abuse prevention.
Configurable per IP or per User. Returns 429 when limits are exceeded.
"""
import time
from collections import defaultdict
from fastapi import Request, HTTPException, status

class RateLimiter:
    def __init__(self):
        # ip_or_key -> list of float timestamps
        self.requests = defaultdict(list)

    def check(self, key: str, max_requests: int, window_seconds: int):
        now = time.time()
        # Clean older requests outside the window
        valid_window = now - window_seconds
        self.requests[key] = [t for t in self.requests[key] if t > valid_window]

        if len(self.requests[key]) >= max_requests:
            retry_after = int(self.requests[key][0] + window_seconds - now)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "RATE_LIMIT_EXCEEDED",
                    "message": f"Rate limit exceeded: maximum {max_requests} requests per {window_seconds}s. Try again in {max(1, retry_after)} seconds.",
                    "retry_after": max(1, retry_after)
                },
                headers={"Retry-After": str(max(1, retry_after))}
            )

        self.requests[key].append(now)

rate_limiter = RateLimiter()

def rate_limit(max_requests: int, window_seconds: int):
    """Dependency for endpoint rate limiting by client IP."""
    def dependency(request: Request):
        client_ip = request.client.host if request.client else "127.0.0.1"
        key = f"{request.url.path}:{client_ip}"
        rate_limiter.check(key, max_requests, window_seconds)
    return dependency
