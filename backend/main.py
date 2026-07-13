"""
ZeroContext Python AI Backend
FastAPI server providing AI-powered threat analysis.

Endpoints:
  GET  /health        — Liveness probe
  POST /analyze       — Full AI analysis
  GET  /rules/version — Rules version info
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from .routers import health, analyze, rules

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="ZeroContext AI Backend",
    description="AI-powered threat analysis — no untrusted payloads stored",
    version="1.0.0",
    docs_url=None,   # Disable Swagger UI in production
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS — only allow the frontend origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    allow_credentials=False,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1"],
)

# Routers
app.include_router(health.router)
app.include_router(analyze.router)
app.include_router(rules.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True, log_level="info")
