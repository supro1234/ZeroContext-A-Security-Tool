"""analyze router"""
import time
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

from ..schemas.request import AnalyzeRequest, AIAnalysisResult
from ..models.classifier import analyze as run_analysis

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.post("/analyze", response_model=AIAnalysisResult)
@limiter.limit("10/minute")
async def analyze_payload(request: Request, body: AnalyzeRequest):
    """
    AI analysis endpoint.
    SECURITY: Receives already-normalized text, not raw HTML.
    No user payloads are logged or stored.
    """
    result = run_analysis(body.text)
    return JSONResponse(content=result)
