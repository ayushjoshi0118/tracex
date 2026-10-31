from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.investigation import Investigation
from backend.app.schemas.entities import ReportExportRequest
from backend.app.services.reporting_service import (
    generate_json_investigation_report,
    generate_pdf_investigation_report
)

router = APIRouter(prefix="/reports", tags=["Report Generation"])

@router.post("/{inv_id}/export")
def export_investigation_report(
    inv_id: str,
    payload: ReportExportRequest,
    db: Session = Depends(get_db)
):
    """
    Generate professional forensic PDF and structured JSON reports.
    Includes case evidence, hashes, timeline, and strictly separates observed facts from analyst interpretations.
    """
    inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{inv_id}' not found"
        )

    if payload.format.lower() == "pdf":
        try:
            pdf_bytes = generate_pdf_investigation_report(inv, payload)
            filename = f"TRACEX_Forensic_Report_{inv.id}.pdf"
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f"attachment; filename={filename}"
                }
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"PDF generation failed: {str(e)}"
            )
    else:
        # JSON export
        report_data = generate_json_investigation_report(inv)
        return JSONResponse(content=report_data)
