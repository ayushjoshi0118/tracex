from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status
from typing import Optional
from backend.app.config import settings
from backend.app.schemas.forensics import EmailForensicsResponse
from backend.app.services.email_forensics import analyze_email_forensics
from backend.app.utils.security import generate_quarantine_path

router = APIRouter(prefix="/email", tags=["Email Forensics"])

@router.post("/analyze", response_model=EmailForensicsResponse)
async def analyze_uploaded_email(
    file: Optional[UploadFile] = File(None),
    raw_content: Optional[str] = Form(None)
):
    """
    Analyzes an RFC 822 / MIME .eml file or raw email message headers and body.
    Extracts hops, SPF/DKIM/DMARC status, sender spoofing indicators, and phishing risk scores.
    """
    target_path = None
    if file and file.filename:
        target_path, _ = generate_quarantine_path(settings.QUARANTINE_DIR, file.filename)
        with open(target_path, "wb") as buffer:
            while chunk := await file.read(64 * 1024):
                buffer.write(chunk)
    elif raw_content:
        target_path, _ = generate_quarantine_path(settings.QUARANTINE_DIR, "pasted_message.eml")
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(raw_content)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either an .eml file upload or raw_content text must be provided"
        )

    try:
        results = analyze_email_forensics(target_path)
        return results
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Email forensics parsing error: {str(e)}"
        )
