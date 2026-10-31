import shutil
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException, status
from backend.app.config import settings
from backend.app.schemas.forensics import FileForensicsResponse
from backend.app.services.file_forensics import analyze_file_forensics
from backend.app.utils.security import generate_quarantine_path, enforce_safe_file_permissions

router = APIRouter(prefix="/files", tags=["File Forensics"])

@router.post("/analyze", response_model=FileForensicsResponse)
async def upload_and_analyze_file(file: UploadFile = File(...)):
    """
    Safely uploads a file to isolated quarantine outside the public web root
    and performs deep static forensic analysis without executing the file.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must have a valid filename"
        )

    # Isolated storage destination
    target_path, stored_filename = generate_quarantine_path(settings.QUARANTINE_DIR, file.filename)

    # Stream file to disk and monitor file size limit
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
                    detail=f"File exceeds maximum allowed upload size ({settings.MAX_UPLOAD_SIZE_BYTES // (1024*1024)} MB)"
                )
            buffer.write(chunk)

    enforce_safe_file_permissions(target_path)

    try:
        # Run isolated forensic examination
        analysis_result = analyze_file_forensics(target_path, file.filename)
        return analysis_result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Forensic parsing failed: {str(e)}"
        )
