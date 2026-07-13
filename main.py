"""
Domain WHOIS API
RDAP protocol (RFC 7480) — modern, JSON, free, no rate limits.
"""
import subprocess, json as _json, time, threading
from typing import Optional
from fastapi import Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from ratelimit import RateLimitMiddleware


app = FastAPI(title="Domain WHOIS API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.add_middleware(RateLimitMiddleware)


# RDAP servers for common TLDs
RDAP_SERVERS = {
    "com": "https://rdap.verisign.com/com/v1/domain/",
    "net": "https://rdap.verisign.com/net/v1/domain/",
    "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
    "info": "https://rdap.identitydigital.services/rdap/domain/",
    "io": "https://rdap.nic.io/domain/",
    "co": "https://rdap.nic.co/domain/",
    "app": "https://rdap.nic.google/domain/",
    "dev": "https://rdap.nic.google/domain/",
    "ai": "https://rdap.nic.ai/domain/",
    "me": "https://rdap.identitydigital.services/rdap/domain/",
    "de": "https://rdap.denic.de/domain/",
}

# In-memory cache (Render free tier — survives between requests on same instance)
_cache: dict = {}
_cache_lock = threading.Lock()
CACHE_TTL = 3600  # 1 hour


class WhoisResult(BaseModel):
    domain: str
    registrar: Optional[str] = None
    created_date: Optional[str] = None
    updated_date: Optional[str] = None
    expiration_date: Optional[str] = None
    name_servers: list[str] = []
    status: list[str] = []
    available: Optional[bool] = None
    error: Optional[str] = None


def curl_get(url: str, timeout: int = 6) -> dict:
    """curl with strict timeout. Returns {} on any failure."""
    cmd = [
        "curl", "-s", "-L",
        "--connect-timeout", str(timeout),
        "--max-time", str(timeout + 2),
        url
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 4)
    except subprocess.TimeoutExpired:
        return {}
    if result.returncode != 0 or not result.stdout.strip():
        return {}
    try:
        return _json.loads(result.stdout)
    except:
        return {}


def get_cached(key: str):
    with _cache_lock:
        entry = _cache.get(key)
        if entry and time.time() - entry["ts"] < CACHE_TTL:
            return entry["data"]
    return None


def set_cache(key: str, data):
    with _cache_lock:
        _cache[key] = {"data": data, "ts": time.time()}
        # Keep cache under 1000 entries
        if len(_cache) > 1000:
            oldest = min(_cache, key=lambda k: _cache[k]["ts"])
            del _cache[oldest]


def parse_rdap(domain: str, data: dict) -> WhoisResult:
    registrar = None
    for entity in data.get("entities", []):
        if "registrar" in str(entity.get("roles", [])):
            vcard = entity.get("vcardArray", [[], []])
            for item in vcard[1] if len(vcard) > 1 else []:
                if item[0] == "fn":
                    registrar = item[3]
                    break

    created, updated, expires = None, None, None
    for event in data.get("events", []):
        action = event.get("eventAction", "")
        date = event.get("eventDate", "")[:10]
        if action == "registration":
            created = date
        elif action == "last changed":
            updated = date
        elif action == "expiration":
            expires = date

    ns = [n.get("ldhName", "") for n in data.get("nameservers", []) if n.get("ldhName")]
    status = data.get("status", [])

    return WhoisResult(
        domain=domain,
        registrar=registrar,
        created_date=created,
        updated_date=updated,
        expiration_date=expires,
        name_servers=ns,
        status=status,
        available=False,
    )


def lookup_rdap(domain: str) -> WhoisResult:
    domain = domain.lower().strip()
    
    # Check cache first
    cached = get_cached(domain)
    if cached:
        return WhoisResult(**cached)

    tld = domain.split(".")[-1] if "." in domain else domain

    # Try specific RDAP server (fast path, many TLDs < 1s)
    rdap_url = RDAP_SERVERS.get(tld)
    if rdap_url:
        data = curl_get(rdap_url + domain, timeout=5)
        if data:
            if "ldhName" in data:
                result = parse_rdap(domain, data)
                set_cache(domain, result.model_dump())
                return result
            if "errorCode" in data and data.get("errorCode") == 404:
                result = WhoisResult(domain=domain, available=True)
                set_cache(domain, result.model_dump())
                return result

    # Fallback: rdap.org central (slower but covers more)
    data = curl_get(f"https://rdap.org/domain/{domain}", timeout=5)
    if data:
        if "ldhName" in data:
            result = parse_rdap(domain, data)
            set_cache(domain, result.model_dump())
            return result
        if "errorCode" in data and data.get("errorCode") == 404:
            result = WhoisResult(domain=domain, available=True)
            set_cache(domain, result.model_dump())
            return result

    # Both failed
    result = WhoisResult(domain=domain, error="RDAP lookup failed — domain may not exist or TLD not supported")
    # Don't cache failures
    return result


@app.api_route("/health", methods=["GET", "HEAD"])
async def health():
    return {"status": "ok", "protocol": "RDAP", "cache_size": len(_cache)}


@app.get("/")
async def root():
    return {"service": "Domain WHOIS API", "version": "2.0.0"}


@app.get("/lookup", response_model=WhoisResult)
async def lookup(domain: str = Query(..., description="Domain name, e.g. 'example.com'")):
    return lookup_rdap(domain)
