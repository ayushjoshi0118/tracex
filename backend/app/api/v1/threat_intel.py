from fastapi import APIRouter, Query, HTTPException, status
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from backend.app.schemas.forensics import ThreatIntelReport, IOCCorrelationResponse
from backend.app.services.threat_intel import query_threat_intelligence, correlate_indicators

router = APIRouter(prefix="/intel", tags=["Threat Intelligence"])

class BatchLookupRequest(BaseModel):
    indicators: List[str]

class CorrelationItemRequest(BaseModel):
    value: str
    source: Optional[str] = "Manual Observation"
    type: Optional[str] = None

class CorrelateIndicatorsRequest(BaseModel):
    indicators: List[CorrelationItemRequest]

@router.get("/lookup", response_model=ThreatIntelReport)
def lookup_single_indicator(ioc: str = Query(..., min_length=1, description="IP, Domain, URL, or File Hash")):
    """
    Investigate an indicator of compromise (IOC) across configured threat feeds and heuristic rules.
    Always includes provenance timestamp, provider source, and technical limitations.
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

@router.post("/correlate", response_model=IOCCorrelationResponse)
def correlate_investigation_indicators(payload: CorrelateIndicatorsRequest):
    """
    Multi-stage correlation engine linking indicators across files, emails, and PCAP streams.
    Calculates weighted confidence based on multi-source corroboration and separates
    verified observed evidence from external threat feeds and heuristic observations.
    """
    try:
        raw_list = [item.model_dump() for item in payload.indicators[:50]]
        response = correlate_indicators(raw_list)
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Correlation engine failure: {str(e)}"
        )
