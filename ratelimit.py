"""
Token-proof rate limiter using Starlette middleware.
Import this and add: app.add_middleware(RateLimitMiddleware)
"""
import time, threading
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 60, window: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window
        self.hits = {}
        self.lock = threading.Lock()
    
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)
        
        ip = (request.headers.get("X-Forwarded-For", "") or 
              request.headers.get("X-Real-IP", "") or
              (request.client.host if request.client else "127.0.0.1"))
        ip = ip.split(",")[0].strip()
        
        now = time.time()
        with self.lock:
            entry = self.hits.get(ip)
            if entry:
                if now - entry["start"] > self.window:
                    entry["start"] = now
                    entry["count"] = 1
                else:
                    entry["count"] += 1
                    if entry["count"] > self.max_requests:
                        from fastapi.responses import JSONResponse
                        return JSONResponse(
                            {"error": "Too many requests"}, status_code=429
                        )
            else:
                self.hits[ip] = {"start": now, "count": 1}
        
        return await call_next(request)
