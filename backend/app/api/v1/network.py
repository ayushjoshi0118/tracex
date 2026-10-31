from fastapi import APIRouter, UploadFile, File, HTTPException, status
from backend.app.config import settings
from backend.app.schemas.forensics import NetworkForensicsResponse
from backend.app.services.network_forensics import analyze_pcap_forensics
from backend.app.utils.security import generate_quarantine_path, enforce_safe_file_permissions

router = APIRouter(prefix="/network", tags=["Network Forensics"])

@router.post("/analyze", response_model=NetworkForensicsResponse)
async def analyze_uploaded_pcap(file: UploadFile = File(...)):
    """
    Performs offline packet inspection on uploaded PCAP/PCAPNG packet traces.
    Extracts protocols, DNS queries, HTTP metadata, talkers, and anomalies without active scanning.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must have a valid filename"
        )

    target_path, _ = generate_quarantine_path(settings.QUARANTINE_DIR, file.filename)

    total_written = 0
    with open(target_path, "wb") as buffer:
        while chunk := await file.read(64 * 1024):
            total_written += len(chunk)
            if total_written > settings.MAX_UPLOAD_SIZE_BYTES:
                buffer.close()
                if target_path.exists():
                    target_path.unlink()
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"PCAP exceeds size limit ({settings.MAX_UPLOAD_SIZE_BYTES // (1024*1024)} MB)"
                )
            buffer.write(chunk)

    enforce_safe_file_permissions(target_path)

    try:
        results = analyze_pcap_forensics(target_path)
        return results
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Network forensics PCAP parsing failed: {str(e)}"
        )
