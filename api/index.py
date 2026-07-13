"""
api/index.py — ZeroContext FastAPI backend for Vercel serverless deployment.

Vercel routes /api/* → this file via vercel.json rewrites.
All routes are declared with the /api/ prefix so the ASGI app matches correctly.
"""

import sys
import os

# Ensure backend package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from backend.models.classifier import analyze as run_analysis
from backend.schemas.request import AnalyzeRequest, AIAnalysisResult

import json

# ── Rate limiter ────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])

# ── App ─────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="ZeroContext AI Backend",
    description="AI-powered threat analysis — no untrusted payloads stored",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS — allow Vercel deployment origins + localhost dev
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
    # Vercel deployment URLs — set VERCEL_URL env var or wildcard
    os.getenv("FRONTEND_ORIGIN", "https://zerocontext.vercel.app"),
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    allow_credentials=False,
)

# ── Routes (with /api prefix — Vercel passes full path) ─────────────────────

@app.get("/api/health")
async def health():
    return JSONResponse({"status": "ok", "service": "ZeroContext AI Backend"})


@app.post("/api/analyze")
@limiter.limit("10/minute")
async def analyze_payload(request: Request, body: AnalyzeRequest):
    """
    AI analysis endpoint.
    SECURITY: Receives already-normalized text, not raw HTML.
    No user payloads are logged or stored.
    """
    result = run_analysis(body.text)
    return JSONResponse(content=result)


@app.get("/api/rules/version")
async def rules_version():
    # Path relative to project root
    rules_path = os.path.join(
        os.path.dirname(__file__), "..", "public", "rules", "rules.json"
    )
    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return JSONResponse({
            "version": data.get("version", "unknown"),
            "totalRules": data.get("totalRules", 0),
            "generatedAt": data.get("generatedAt", ""),
        })
    except Exception as e:
        return JSONResponse({"error": "Rules file unavailable"}, status_code=500)


# ── Vercel ASGI handler ──────────────────────────────────────────────────────
# Vercel's Python runtime looks for `app` as the ASGI handler.
# No extra wrapper needed — FastAPI is natively ASGI.
