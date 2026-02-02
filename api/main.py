"""
Isnad API

FastAPI application for the Isnad skill scanning service.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Optional
import httpx
import hashlib
from datetime import datetime

from scanner.core import SkillScanner, scan_skill


app = FastAPI(
    title="Isnad",
    description="Trust infrastructure for the agent internet. Scan agent skills for security issues.",
    version="0.1.0",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory cache (replace with Redis/PostgreSQL in production)
scan_cache: dict = {}


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
        "version": "0.1.0",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    """
    Scan a skill for security issues.
    
    Provide either a URL to fetch, or raw content to scan.
    """
    if not request.url and not request.content:
        raise HTTPException(
            status_code=400,
            detail="Must provide either 'url' or 'content'"
        )
    
    content: str
    url: Optional[str] = None
    
    if request.url:
        url = str(request.url)
        # Fetch the skill
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=30.0, follow_redirects=True)
                response.raise_for_status()
                content = response.text
        except httpx.HTTPError as e:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to fetch URL: {str(e)}"
            )
    else:
        content = request.content
    
    # Scan
    result = scan_skill(content, url)
    
    # Generate scan ID
    scan_id = hashlib.md5(
        f"{result['content_hash']}{datetime.utcnow().isoformat()}".encode()
    ).hexdigest()[:12]
    
    # Cache result
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
    """Get a previous scan result by ID."""
    if scan_id not in scan_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_cache[scan_id]


@app.get("/api/v1/check/{content_hash}")
async def check_hash(content_hash: str):
    """Check if a skill has been scanned before (by content hash)."""
    if content_hash in scan_cache:
        return {
            "scanned": True,
            "risk_level": scan_cache[content_hash]["risk_level"],
        }
    return {"scanned": False}


@app.get("/api/v1/registry")
async def registry(limit: int = 50, risk_level: Optional[str] = None):
    """Get recently scanned skills."""
    results = list(scan_cache.values())
    
    if risk_level:
        results = [r for r in results if r.get("risk_level") == risk_level]
    
    return {
        "skills": results[:limit],
        "total": len(results),
    }


# Run with: uvicorn api.main:app --reload
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
