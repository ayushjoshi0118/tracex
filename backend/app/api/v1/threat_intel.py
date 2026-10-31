from fastapi import APIRouter, Query, HTTPException, status
from pydantic import BaseModel
from typing import List
from backend.app.schemas.forensics import ThreatIntelReport
from backend.app.services.threat_intel import query_threat_intelligence

router = APIRouter(prefix="/intel", tags=["Threat Intelligence"])

class BatchLookupRequest(BaseModel):
    indicators: List[str]

@router.get("/lookup", response_model=ThreatIntelReport)
def lookup_single_indicator(ioc: str = Query(..., min_length=1, description="IP, Domain, URL, or File Hash")):
    """
    Investigate an indicator of compromise (IOC) across configured threat feeds and heuristic rules.
    Always includes provenance timestamp and provider source.
    """
    try:
        report = query_threat_intelligence(ioc)
        return report
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Intelligence query failed: {str(e)}"
        )

@router.post("/batch", response_model=List[ThreatIntelReport])
def lookup_batch_indicators(payload: BatchLookupRequest):
    """
    Investigate multiple indicators in a single batch operation.
    """
    results = []
    # Limit batch to 25 items for safety
    for item in payload.indicators[:25]:
        if item.strip():
            results.append(query_threat_intelligence(item.strip()))
    return results
