from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from backend.app.models.investigation import Investigation

class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # case, evidence, ioc_ip, ioc_domain, ioc_hash, ioc_url, milestone
    group: str
    data: Dict[str, Any]
    severity: Optional[str] = "info"

class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    relation: str  # contains, correlates, generated_by, referenced_in, communicates_with
    confidence: float

class InvestigationGraphResponse(BaseModel):
    investigation_id: str
    title: str
    total_nodes: int
    total_edges: int
    nodes: List[GraphNode]
    edges: List[GraphEdge]

def generate_investigation_relationship_graph(db: Session, inv_id: str) -> InvestigationGraphResponse:
    """
    Builds a forensic relationship graph mapping correlations between
    Investigations, Quarantined Evidence Artifacts, Threat Indicators of Compromise,
    and Timeline Milestones.
    """
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{inv_id}' not found"
        )

    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []
    edge_idx = 1

    # 1. Root Investigation Node
    case_node_id = f"case_{inv.id}"
    nodes.append(GraphNode(
        id=case_node_id,
        label=inv.id,
        type="case",
        group="investigation",
        severity=inv.priority,
        data={
            "title": inv.title,
            "status": inv.status,
            "priority": inv.priority,
            "lead_analyst": inv.lead_analyst,
            "created_at": inv.created_at.isoformat() if inv.created_at else None
        }
    ))

    # 2. Evidence Artifact Nodes
    for ev in inv.evidence_items:
        ev_node_id = f"evd_{ev.id}"
        nodes.append(GraphNode(
            id=ev_node_id,
            label=ev.name,
            type="evidence",
            group="evidence",
            severity="critical" if ev.integrity_status == "compromised" else "info",
            data={
                "id": ev.id,
                "original_filename": ev.original_filename,
                "file_size": ev.file_size_bytes,
                "sha256": ev.sha256,
                "file_type": ev.magic_signature or ev.mime_type,
                "integrity_status": ev.integrity_status,
                "acquired_by": ev.acquired_by,
                "badge_number": ev.badge_number,
                "source_description": ev.source_description
            }
        ))

        # Edge from Case to Evidence
        edges.append(GraphEdge(
            id=f"e_{edge_idx}",
            source=case_node_id,
            target=ev_node_id,
            label="Contains Evidence",
            relation="contains_evidence",
            confidence=1.0
        ))
        edge_idx += 1

    # 3. Threat IOC Nodes
    for ioc in inv.iocs:
        ioc_type_clean = f"ioc_{ioc.ioc_type}"
        ioc_node_id = f"ioc_{ioc.id}"
        
        nodes.append(GraphNode(
            id=ioc_node_id,
            label=ioc.value,
            type=ioc_type_clean,
            group="threat_ioc",
            severity=ioc.classification,
            data={
                "id": ioc.id,
                "ioc_type": ioc.ioc_type,
                "value": ioc.value,
                "category": ioc.category,
                "threat_score": ioc.threat_score,
                "classification": ioc.classification,
                "source": ioc.attribution_source,
                "notes": ioc.notes
            }
        ))

        # Edge from Case to IOC
        edges.append(GraphEdge(
            id=f"e_{edge_idx}",
            source=case_node_id,
            target=ioc_node_id,
            label="Monitored IOC",
            relation="monitored_ioc",
            confidence=0.9
        ))
        edge_idx += 1

        # Check for Evidence <-> IOC correlation:
        # e.g., if evidence filename or notes contain ioc or if hash matches
        for ev in inv.evidence_items:
            ev_node_id = f"evd_{ev.id}"
            ev_text = f"{ev.name} {ev.original_filename} {ev.notes or ''} {ev.source_description or ''} {ev.sha256}".lower()
            if ioc.value.lower() in ev_text or (ioc.ioc_type == "hash" and ioc.value.lower() == ev.sha256.lower()):
                edges.append(GraphEdge(
                    id=f"e_{edge_idx}",
                    source=ev_node_id,
                    target=ioc_node_id,
                    label="Correlated Indicator",
                    relation="extracted_or_matched",
                    confidence=0.98
                ))
                edge_idx += 1

    # 4. Timeline Milestone Nodes
    for evt in inv.timeline_events:
        evt_node_id = f"timeline_{evt.id}"
        nodes.append(GraphNode(
            id=evt_node_id,
            label=evt.title,
            type="milestone",
            group="timeline",
            severity=evt.severity,
            data={
                "id": evt.id,
                "title": evt.title,
                "description": evt.description,
                "category": evt.category,
                "severity": evt.severity,
                "source": evt.source,
                "timestamp": evt.timestamp.isoformat() if evt.timestamp else None,
                "raw_reference": evt.raw_reference
            }
        ))

        # Edge from Case to Timeline
        edges.append(GraphEdge(
            id=f"e_{edge_idx}",
            source=case_node_id,
            target=evt_node_id,
            label="Case Milestone",
            relation="has_milestone",
            confidence=1.0
        ))
        edge_idx += 1

        # If milestone has raw_reference linking to evidence id, hash, or ioc
        if evt.raw_reference:
            for ev in inv.evidence_items:
                if evt.raw_reference in [ev.id, ev.sha256, ev.original_filename]:
                    edges.append(GraphEdge(
                        id=f"e_{edge_idx}",
                        source=evt_node_id,
                        target=f"evd_{ev.id}",
                        label="Witnesses Artifact",
                        relation="referenced_artifact",
                        confidence=1.0
                    ))
                    edge_idx += 1

            for ioc in inv.iocs:
                if evt.raw_reference.lower() == ioc.value.lower():
                    edges.append(GraphEdge(
                        id=f"e_{edge_idx}",
                        source=evt_node_id,
                        target=f"ioc_{ioc.id}",
                        label="Witnesses IOC",
                        relation="referenced_ioc",
                        confidence=1.0
                    ))
                    edge_idx += 1

    return InvestigationGraphResponse(
        investigation_id=inv.id,
        title=inv.title,
        total_nodes=len(nodes),
        total_edges=len(edges),
        nodes=nodes,
        edges=edges
    )
