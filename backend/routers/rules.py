"""rules router"""
import json
import os
from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()

RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "public", "rules", "rules.json")


@router.get("/rules/version")
async def rules_version():
    try:
        with open(RULES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return JSONResponse({
            "version": data.get("version", "unknown"),
            "totalRules": data.get("totalRules", 0),
            "generatedAt": data.get("generatedAt", ""),
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
