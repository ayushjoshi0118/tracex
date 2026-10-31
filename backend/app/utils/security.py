import math
import os
import re
import uuid
from pathlib import Path
from typing import Tuple
from fastapi import HTTPException, status

def sanitize_filename(filename: str) -> str:
    """
    Remove potentially dangerous characters and path traversal attempts.
    """
    if not filename:
        return f"unnamed_artifact_{uuid.uuid4().hex[:8]}"
    
    # Strip any directory path components
    basename = os.path.basename(filename)
    # Remove null bytes and non-printable characters
    cleaned = re.sub(r'[\x00-\x1f\x7f]', '', basename)
    # Allow alphanumeric, dots, underscores, dashes
    cleaned = re.sub(r'[^A-Za-z0-9._-]', '_', cleaned)
    # Disallow starting with dot (hidden files / relative)
    if cleaned.startswith('.'):
        cleaned = f"file_{cleaned}"
    if not cleaned:
        cleaned = f"artifact_{uuid.uuid4().hex[:8]}"
    return cleaned

def generate_quarantine_path(quarantine_dir: Path, original_filename: str) -> Tuple[Path, str]:
    """
    Generate an isolated, non-executable storage path outside web root.
    """
    clean_name = sanitize_filename(original_filename)
    unique_prefix = uuid.uuid4().hex[:12]
    stored_filename = f"{unique_prefix}_{clean_name}"
    
    target_path = quarantine_dir / stored_filename
    # Prevent traversal check
    resolved_path = target_path.resolve()
    resolved_quarantine = quarantine_dir.resolve()
    
    try:
        resolved_path.relative_to(resolved_quarantine)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Path traversal attempt detected in filename"
        )
        
    return resolved_path, stored_filename

def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of byte sequence.
    Returns value between 0.0 (uniform) and 8.0 (completely random / encrypted / compressed).
    High entropy (> 7.2) is a strong indicator of packing, encryption, or compression.
    """
    if not data:
        return 0.0
    
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
        
    entropy = 0.0
    length = len(data)
    for count in byte_counts:
        if count > 0:
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
            
    return round(entropy, 4)

def extract_ascii_and_unicode_strings(data: bytes, min_length: int = 4, max_strings: int = 100) -> list[str]:
    """
    Safely extract ASCII and UTF-16 strings without executing or interpreting content.
    """
    found_strings = []
    
    # ASCII strings regex
    ascii_pattern = re.compile(rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}')
    for match in ascii_pattern.finditer(data):
        try:
            s = match.group().decode('latin-1').strip()
            if s and len(s) >= min_length:
                found_strings.append(s)
                if len(found_strings) >= max_strings:
                    return found_strings
        except Exception:
            continue
            
    return found_strings
