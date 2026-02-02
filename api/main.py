"""
Isnad API - Trust infrastructure for the agent internet.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl
from typing import Optional
import httpx
import hashlib
import os
from datetime import datetime

from scanner.core import scan_skill
from api.security import SSRFProtection, RateLimiter
from api.analytics import init_db, record_scan, get_stats

app = FastAPI(
    title="Isnad",
    description="Trust infrastructure for the agent internet.",
    version="0.2.0",
    docs_url="/docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://isnad.dev", "https://www.isnad.dev", "https://moltbook.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

scan_cache: dict = {}
rate_limiter = RateLimiter()

# Initialize analytics database
init_db()


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


@app.get("/", response_class=FileResponse)
async def landing():
    """Serve landing page."""
    if os.path.exists("web/index.html"):
        return FileResponse("web/index.html")
    return {"name": "Isnad", "tagline": "Trust infrastructure for the agent internet", "docs": "/docs"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/badge/{content_hash}.svg")
async def badge(content_hash: str):
    """Generate SVG trust badge."""
    if content_hash in scan_cache:
        risk = scan_cache[content_hash]["risk_level"]
        colors = {"clean": "#4c1", "low": "#97ca00", "medium": "#dfb317", "high": "#fe7d37", "critical": "#e05d44"}
        color = colors.get(risk, "#9f9f9f")
        text = risk
    else:
        color = "#9f9f9f"
        text = "unknown"
    
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="90" height="20">
      <rect width="90" height="20" rx="3" fill="#555"/>
      <rect x="40" width="50" height="20" rx="3" fill="{color}"/>
      <rect x="40" width="4" height="20" fill="{color}"/>
      <g fill="#fff" font-family="Verdana,sans-serif" font-size="11">
        <text x="6" y="14">isnad</text>
        <text x="46" y="14">{text}</text>
      </g>
    </svg>'''
    return Response(content=svg, media_type="image/svg+xml", headers={"Cache-Control": "no-cache"})


@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan(request: ScanRequest, req: Request):
    """Scan a skill for security issues."""
    client_ip = get_client_ip(req)
    allowed, info = rate_limiter.is_allowed(client_ip, 'scan')
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded. Resets in {info['limit']} seconds.")
    
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
                response = await client.get(url, timeout=10.0, follow_redirects=False)
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
    scan_id = hashlib.md5(f"{result['content_hash']}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:12]
    
    scan_cache[scan_id] = result
    scan_cache[result['content_hash']] = result
    
    return ScanResponse(
        scan_id=scan_id, skill_url=result["skill_url"], content_hash=result["content_hash"],
        risk_level=result["risk_level"], findings=result["findings"],
        permissions_inferred=result["permissions_inferred"], urls_found=result["urls_found"],
        scanned_at=datetime.utcnow().isoformat(),
    )


@app.get("/api/v1/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scan_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_cache[scan_id]


@app.get("/api/v1/check/{content_hash}")
async def check_hash(content_hash: str):
    if content_hash in scan_cache:
        return {"scanned": True, "risk_level": scan_cache[content_hash]["risk_level"]}
    return {"scanned": False}


@app.get("/api/v1/registry")
async def registry(req: Request, limit: int = 50, risk_level: Optional[str] = None):
    client_ip = get_client_ip(req)
    allowed, _ = rate_limiter.is_allowed(client_ip, 'registry')
    if not allowed:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    results = list(scan_cache.values())
    if risk_level:
        results = [r for r in results if r.get("risk_level") == risk_level]
    return {"skills": results[:limit], "total": len(results)}
