import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from backend.app.models.evidence import Evidence
from backend.app.services.file_forensics import (
    calculate_file_hashes,
    detect_file_signature,
    format_human_bytes
)
from backend.app.utils.security import (
    calculate_shannon_entropy,
    extract_ascii_and_unicode_strings
)

class HashComparisonDetail(BaseModel):
    algorithm: str
    hash_a: str
    hash_b: str
    is_match: bool

class EvidenceComparisonResponse(BaseModel):
    item_a_id: str
    item_a_name: str
    item_b_id: str
    item_b_name: str
    
    # Hash Comparisons
    hashes: List[HashComparisonDetail]
    exact_hash_match: bool
    
    # Size Comparison
    size_a_bytes: int
    size_b_bytes: int
    size_a_human: str
    size_b_human: str
    size_delta_bytes: int
    size_ratio_percentage: float
    
    # Entropy Comparison
    entropy_a: float
    entropy_b: float
    entropy_delta: float
    entropy_a_level: str
    entropy_b_level: str
    
    # File Signature & Format
    signature_a: str
    signature_b: str
    is_same_file_type: bool
    
    # String Overlap Analysis
    shared_strings_count: int
    unique_to_a_count: int
    unique_to_b_count: int
    shared_strings_sample: List[str]
    unique_to_a_sample: List[str]
    unique_to_b_sample: List[str]
    
    # Binary Hex Header Comparison
    header_a_hex: str
    header_b_hex: str
    header_bytes_match: bool
    
    forensic_conclusions: List[str]

def compare_evidence_artifacts(db: Session, id_a: str, id_b: str) -> EvidenceComparisonResponse:
    """
    Performs forensic side-by-side comparison between two registered evidence artifacts.
    Evaluates cryptographic fingerprints, size divergence, entropy variance,
    shared string heuristics, and binary header alignment.
    """
    ev_a = db.query(Evidence).filter(Evidence.id == id_a).first()
    ev_b = db.query(Evidence).filter(Evidence.id == id_b).first()

    if not ev_a or not ev_b:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="One or both evidence artifacts could not be found for comparison"
        )

    path_a = Path(ev_a.file_path)
    path_b = Path(ev_b.file_path)

    if not path_a.exists() or not path_b.exists():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="One or both artifact files are missing from quarantine storage"
        )

    # 1. Hashes comparison
    hashes_a = calculate_file_hashes(path_a)
    hashes_b = calculate_file_hashes(path_b)

    hash_comparisons = [
        HashComparisonDetail(
            algorithm="SHA-256 (Forensic Baseline)",
            hash_a=hashes_a.sha256,
            hash_b=hashes_b.sha256,
            is_match=(hashes_a.sha256.lower() == hashes_b.sha256.lower())
        ),
        HashComparisonDetail(
            algorithm="SHA-512 (High Security)",
            hash_a=hashes_a.sha512,
            hash_b=hashes_b.sha512,
            is_match=(hashes_a.sha512.lower() == hashes_b.sha512.lower())
        ),
        HashComparisonDetail(
            algorithm="MD5",
            hash_a=hashes_a.md5,
            hash_b=hashes_b.md5,
            is_match=(hashes_a.md5.lower() == hashes_b.md5.lower())
        ),
        HashComparisonDetail(
            algorithm="SHA-1",
            hash_a=hashes_a.sha1,
            hash_b=hashes_b.sha1,
            is_match=(hashes_a.sha1.lower() == hashes_b.sha1.lower())
        )
    ]
    exact_match = hashes_a.sha256.lower() == hashes_b.sha256.lower()

    # 2. File size comparison
    size_a = os.path.getsize(path_a)
    size_b = os.path.getsize(path_b)
    size_delta = abs(size_a - size_b)
    ratio = round((min(size_a, size_b) / max(size_a, size_b, 1)) * 100, 2)

    # 3. Read sample bytes for headers, entropy, strings
    with open(path_a, "rb") as fa:
        sample_a = fa.read(64 * 1024)
    with open(path_b, "rb") as fb:
        sample_b = fb.read(64 * 1024)

    entropy_a = calculate_shannon_entropy(sample_a)
    entropy_b = calculate_shannon_entropy(sample_b)
    entropy_delta = round(abs(entropy_a - entropy_b), 4)

    entropy_level_a = "High (Packed/Encrypted)" if entropy_a > 7.2 else "Normal" if entropy_a > 5.0 else "Low"
    entropy_level_b = "High (Packed/Encrypted)" if entropy_b > 7.2 else "Normal" if entropy_b > 5.0 else "Low"

    # 4. Signatures
    sig_a = detect_file_signature(sample_a, ev_a.original_filename)
    sig_b = detect_file_signature(sample_b, ev_b.original_filename)
    same_type = (sig_a.matched_extension == sig_b.matched_extension)

    # 5. String Overlap & Diffs
    strings_a = set(extract_ascii_and_unicode_strings(sample_a, min_length=4, max_strings=100))
    strings_b = set(extract_ascii_and_unicode_strings(sample_b, min_length=4, max_strings=100))

    shared_strings = sorted(list(strings_a.intersection(strings_b)))
    unique_a = sorted(list(strings_a.difference(strings_b)))
    unique_b = sorted(list(strings_b.difference(strings_a)))

    # 6. Binary Hex Headers (first 32 bytes)
    header_a_hex = " ".join(f"{b:02X}" for b in sample_a[:32])
    header_b_hex = " ".join(f"{b:02X}" for b in sample_b[:32])
    headers_match = (sample_a[:32] == sample_b[:32])

    # 7. Formulate forensic conclusions
    conclusions = []
    if exact_match:
        conclusions.append("IDENTICAL CRYPTOGRAPHIC DIGESTS: Artifacts A and B share identical SHA-256 fingerprints and byte sequences. They represent the exact same forensic asset.")
    else:
        conclusions.append(f"CRYPTOGRAPHIC DIVERGENCE: Hash mismatch confirmed. Artifacts differ by {size_delta} bytes.")

    if same_type:
        conclusions.append(f"MATCHING FILE FORMAT: Both artifacts share signature '{sig_a.description}'.")
    else:
        conclusions.append(f"FORMAT MISMATCH: Artifact A is '{sig_a.description}' while Artifact B is '{sig_b.description}'.")

    if entropy_delta < 0.2:
        conclusions.append(f"SIMILAR ENTROPY PROFILES: Entropy variance is minimal (delta: {entropy_delta}), suggesting similar compression or code compilation structures.")
    else:
        conclusions.append(f"DIVERGENT ENTROPY: Entropy delta of {entropy_delta} indicates differing levels of packing, encryption, or plaintext density.")

    if shared_strings:
        conclusions.append(f"STRING INTERSECTION: Identified {len(shared_strings)} shared ASCII/Unicode strings, indicating common codebase, dependencies, or domain references.")

    return EvidenceComparisonResponse(
        item_a_id=ev_a.id,
        item_a_name=ev_a.name,
        item_b_id=ev_b.id,
        item_b_name=ev_b.name,
        hashes=hash_comparisons,
        exact_hash_match=exact_match,
        size_a_bytes=size_a,
        size_b_bytes=size_b,
        size_a_human=format_human_bytes(size_a),
        size_b_human=format_human_bytes(size_b),
        size_delta_bytes=size_delta,
        size_ratio_percentage=ratio,
        entropy_a=entropy_a,
        entropy_b=entropy_b,
        entropy_delta=entropy_delta,
        entropy_a_level=entropy_level_a,
        entropy_b_level=entropy_level_b,
        signature_a=sig_a.description,
        signature_b=sig_b.description,
        is_same_file_type=same_type,
        shared_strings_count=len(shared_strings),
        unique_to_a_count=len(unique_a),
        unique_to_b_count=len(unique_b),
        shared_strings_sample=shared_strings[:30],
        unique_to_a_sample=unique_a[:30],
        unique_to_b_sample=unique_b[:30],
        header_a_hex=header_a_hex,
        header_b_hex=header_b_hex,
        header_bytes_match=headers_match,
        forensic_conclusions=conclusions
    )
