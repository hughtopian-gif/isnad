"""
Isnad API - Secured

Trust infrastructure for the agent internet.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Optional
import httpx
import hashlib
from datetime import datetime

from scanner.core import scan_skill
from api.security import SSRFProtection, RateLimiter

app = FastAPI(
    title="Isnad",
    description="Trust infrastructure for the agent internet.",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://isnad.dev",
        "https://www.isnad.dev",
        "https://moltbook.com",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

scan_cache: dict = {}
rate_limiter = RateLimiter()


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class ScanRequest(BaseModel):
    url: Optional[HttpUrl] = None
    content: Optional[str] = None


class ScanResponse(BaseModel):
    scan_id: str
    skill_url: Optional[str]
    content_hash: str
    risk_level: str
    findings: list
    permissions_inferred: dict
    urls_found: list
    scanned_at: str


@app.get("/")
async def root():
    return {
        "name": "Isnad",
        "tagline": "Trust infrastructure for the agent internet",
        "version": "0.2.0",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan(request: ScanRequest, req: Request):
    """Scan a skill for security issues."""
    
    client_ip = get_client_ip(req)
    allowed, info = rate_limiter.is_allowed(client_ip, 'scan')
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. {info['remaining']} of {info['limit']} remaining.",
        )
    
    if not request.url and not request.content:
        raise HTTPException(status_code=400, detail="Must provide 'url' or 'content'")
    
    content: str
    url: Optional[str] = None
    
    if request.url:
        url = str(request.url)
        
        is_safe, error = SSRFProtection.validate_url(url)
        if not is_safe:
            raise HTTPException(status_code=400, detail=f"URL blocked: {error}")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    timeout=10.0,
                    follow_redirects=False,
                )
                
                if response.is_redirect:
                    redirect_url = response.headers.get('location', '')
                    is_safe, error = SSRFProtection.validate_url(redirect_url)
                    if not is_safe:
                        raise HTTPException(status_code=400, detail=f"Redirect blocked: {error}")
                    response = await client.get(redirect_url, timeout=10.0)
                
                response.raise_for_status()
                
                if len(response.content) > 1_000_000:
                    raise HTTPException(status_code=400, detail="Content too large (max 1MB)")
                
                content = response.text
                
        except httpx.HTTPError as e:
            raise HTTPException(status_code=400, detail=f"Fetch failed: {str(e)}")
    else:
        content = request.content
        if len(content) > 1_000_000:
            raise HTTPException(status_code=400, detail="Content too large (max 1MB)")
    
    result = scan_skill(content, url)
    
    scan_id = hashlib.md5(
        f"{result['content_hash']}{datetime.utcnow().isoformat()}".encode()
    ).hexdigest()[:12]
    
    scan_cache[scan_id] = result
    scan_cache[result['content_hash']] = result
    
    return ScanResponse(
        scan_id=scan_id,
        skill_url=result["skill_url"],
        content_hash=result["content_hash"],
        risk_level=result["risk_level"],
        findings=result["findings"],
        permissions_inferred=result["permissions_inferred"],
        urls_found=result["urls_found"],
        scanned_at=datetime.utcnow().isoformat(),
    )


@app.get("/api/v1/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Get a previous scan result."""
    if scan_id not in scan_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_cache[scan_id]


@app.get("/api/v1/check/{content_hash}")
async def check_hash(content_hash: str):
    """Check if a skill has been scanned."""
    if content_hash in scan_cache:
        return {"scanned": True, "risk_level": scan_cache[content_hash]["risk_level"]}
    return {"scanned": False}


@app.get("/api/v1/registry")
async def registry(req: Request, limit: int = 50, risk_level: Optional[str] = None):
    """Get recently scanned skills."""
    client_ip = get_client_ip(req)
    allowed, _ = rate_limiter.is_allowed(client_ip, 'registry')
    if not allowed:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    results = list(scan_cache.values())
    
    if risk_level:
        results = [r for r in results if r.get("risk_level") == risk_level]
    
    return {"skills": results[:limit], "total": len(results)}
