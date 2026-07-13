from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()

@router.get("/health")
async def health():
    return JSONResponse({"status": "ok", "service": "ZeroContext AI Backend"})
