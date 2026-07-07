"""
Domain WHOIS API
RDAP protocol (RFC 7480) — modern, JSON, free, no rate limits.
Supports .com .net .org .info and many more.
"""

import subprocess, json as _json
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Domain WHOIS API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

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
}


class WhoisResult(BaseModel):
    domain: str
    registrar: Optional[str] = None
    created_date: Optional[str] = None
    updated_date: Optional[str] = None
    expiration_date: Optional[str] = None
    name_servers: list[str] = []
    status: list[str] = []
    raw_available: bool = False


def curl_get(url: str) -> dict:
    cmd = ["curl", "-s", "-L", "--connect-timeout", "8", "--max-time", "12", url]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0 or not result.stdout.strip():
        return {}
    try:
        return _json.loads(result.stdout)
    except:
        return {}


def lookup_rdap(domain: str) -> WhoisResult:
    """Query RDAP for a domain."""
    domain = domain.lower().strip()
    tld = domain.split(".")[-1] if "." in domain else domain

    # Try specific RDAP server first
    rdap_url = RDAP_SERVERS.get(tld)
    if rdap_url:
        data = curl_get(rdap_url + domain)
        if data and "ldhName" in data:
            return parse_rdap(domain, data)

    # Fallback: IANA bootstrap
    bootstrap = curl_get(f"https://rdap.iana.org/domain/{domain}")
    if bootstrap and "port43" in bootstrap:
        return WhoisResult(domain=domain, raw_available=True)

    # Try rdap.org central
    data = curl_get(f"https://rdap.org/domain/{domain}")
    if data and "ldhName" in data:
        return parse_rdap(domain, data)

    return WhoisResult(domain=domain, raw_available=True)


def parse_rdap(domain: str, data: dict) -> WhoisResult:
    """Parse RDAP JSON into WhoisResult."""
    # Registrar
    registrar = None
    for entity in data.get("entities", []):
        if "registrar" in str(entity.get("roles", [])):
            vcard = entity.get("vcardArray", [[], []])
            for item in vcard[1] if len(vcard) > 1 else []:
                if item[0] == "fn":
                    registrar = item[3]
                    break

    # Dates
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

    # Nameservers
    ns = [n.get("ldhName", "") for n in data.get("nameservers", []) if n.get("ldhName")]

    # Status
    status = data.get("status", [])

    return WhoisResult(
        domain=domain,
        registrar=registrar,
        created_date=created,
        updated_date=updated,
        expiration_date=expires,
        name_servers=ns,
        status=status,
    )


@app.get("/health")
async def health():
    return {"status": "ok", "protocol": "RDAP"}


@app.get("/")
async def root():
    return {"service": "Domain WHOIS API", "version": "1.0.0"}


@app.get("/lookup", response_model=WhoisResult)
async def lookup(domain: str = Query(..., description="Domain name, e.g. 'example.com', 'google.com'")):
    return lookup_rdap(domain)
