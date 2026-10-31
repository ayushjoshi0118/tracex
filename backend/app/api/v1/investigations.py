import uuid
from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.investigation import Investigation
from backend.app.models.ioc import InvestigationIOC
from backend.app.models.timeline import TimelineEvent
from backend.app.models.note import InvestigationNote
from backend.app.schemas.entities import (
    InvestigationCreate,
    InvestigationUpdate,
    InvestigationDetailResponse,
    InvestigationSummaryResponse,
    IOCCreate,
    IOCResponse,
    TimelineEventCreate,
    TimelineEventResponse,
    InvestigationNoteCreate,
    InvestigationNoteResponse
)
from backend.app.services.graph_service import (
    generate_investigation_relationship_graph,
    InvestigationGraphResponse
)

router = APIRouter(prefix="/investigations", tags=["Investigations Workspace"])

@router.post("/", response_model=InvestigationDetailResponse)
def create_investigation(payload: InvestigationCreate, db: Session = Depends(get_db)):
    """Create a new digital forensics investigation case."""
    inv_id = f"INV-{datetime.now().year}-{uuid.uuid4().hex[:6].upper()}"
    inv = Investigation(
        id=inv_id,
        title=payload.title,
        description=payload.description,
        priority=payload.priority,
        lead_analyst=payload.lead_analyst
    )
    db.add(inv)
    
    # Add initial case creation timeline event
    init_event = TimelineEvent(
        investigation_id=inv_id,
        title="Investigation Initialized",
        description=f"Case opened by {payload.lead_analyst}: {payload.title}",
        category="system",
        severity="info",
        source="TRACEX Platform"
    )
    db.add(init_event)
    db.commit()
    db.refresh(inv)
    return inv

@router.get("/", response_model=List[InvestigationSummaryResponse])
def list_investigations(db: Session = Depends(get_db)):
    """List all digital forensics investigations with artifact counts."""
    invs = db.query(Investigation).order_by(Investigation.created_at.desc()).all()
    summaries = []
    for inv in invs:
        summaries.append(InvestigationSummaryResponse(
            id=inv.id,
            title=inv.title,
            description=inv.description,
            status=inv.status,
            priority=inv.priority,
            lead_analyst=inv.lead_analyst,
            created_at=inv.created_at,
            updated_at=inv.updated_at,
            evidence_count=len(inv.evidence_items),
            ioc_count=len(inv.iocs),
            timeline_event_count=len(inv.timeline_events)
        ))
    return summaries

@router.get("/{inv_id}", response_model=InvestigationDetailResponse)
def get_investigation_detail(inv_id: str, db: Session = Depends(get_db)):
    """Get full investigation workspace state including evidence, timeline, and findings."""
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{inv_id}' not found"
        )
    return inv

@router.patch("/{inv_id}", response_model=InvestigationDetailResponse)
def update_investigation(inv_id: str, payload: InvestigationUpdate, db: Session = Depends(get_db)):
    """Update case status, priority, or analyst assignment."""
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{inv_id}' not found"
        )
    
    if payload.title is not None:
        inv.title = payload.title
    if payload.description is not None:
        inv.description = payload.description
    if payload.status is not None:
        inv.status = payload.status
    if payload.priority is not None:
        inv.priority = payload.priority
    if payload.lead_analyst is not None:
        inv.lead_analyst = payload.lead_analyst

    db.commit()
    db.refresh(inv)
    return inv

@router.post("/{inv_id}/timeline", response_model=TimelineEventResponse)
def add_timeline_event(inv_id: str, payload: TimelineEventCreate, db: Session = Depends(get_db)):
    """Add a timestamped event to the investigation timeline."""
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    evt = TimelineEvent(
        investigation_id=inv_id,
        timestamp=payload.timestamp or datetime.now(timezone.utc),
        title=payload.title,
        description=payload.description,
        category=payload.category,
        severity=payload.severity,
        source=payload.source,
        raw_reference=payload.raw_reference
    )
    db.add(evt)
    db.commit()
    db.refresh(evt)
    return evt

@router.post("/{inv_id}/iocs", response_model=IOCResponse)
def associate_ioc(inv_id: str, payload: IOCCreate, db: Session = Depends(get_db)):
    """Associate an indicator of compromise with the investigation."""
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    ioc = InvestigationIOC(
        investigation_id=inv_id,
        ioc_type=payload.ioc_type,
        value=payload.value,
        category=payload.category,
        threat_score=payload.threat_score,
        classification=payload.classification,
        attribution_source=payload.attribution_source,
        notes=payload.notes
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return ioc

@router.post("/{inv_id}/notes", response_model=InvestigationNoteResponse)
def add_investigation_note(inv_id: str, payload: InvestigationNoteCreate, db: Session = Depends(get_db)):
    """
    Add a case finding. Explicitly specifies whether the note is an observed verified fact
    or an analyst hypothesis/interpretation.
    """
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    note = InvestigationNote(
        investigation_id=inv_id,
        author=payload.author,
        badge_number=payload.badge_number,
        content=payload.content,
        is_finding=payload.is_finding
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return note

@router.get("/{inv_id}/graph", response_model=InvestigationGraphResponse)
def get_investigation_graph_endpoint(inv_id: str, db: Session = Depends(get_db)):
    """
    Returns an interactive relationship graph connecting cases, evidence, IOCs, and milestones.
    """
    return generate_investigation_relationship_graph(db, inv_id)

