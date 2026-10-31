import tempfile
from pathlib import Path
from backend.app.services.file_forensics import (
    calculate_file_hashes,
    detect_file_signature,
    analyze_file_forensics
)
from backend.app.utils.security import calculate_shannon_entropy, extract_ascii_and_unicode_strings

def test_entropy_calculation():
    # Low entropy: repeated bytes
    low_data = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    low_entropy = calculate_shannon_entropy(low_data)
    assert low_entropy == 0.0

    # High entropy: all 256 byte values distributed
    high_data = bytes(range(256))
    high_entropy = calculate_shannon_entropy(high_data)
    assert high_entropy == 8.0

def test_string_extraction():
    data = b"\x00\x00\x00HelloForensicsWorld\x00\x00\x00TestPass123\x00"
    strings = extract_ascii_and_unicode_strings(data, min_length=4)
    assert "HelloForensicsWorld" in strings
    assert "TestPass123" in strings

def test_file_hashing_and_mismatch():
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
        # Write PE executable magic header MZ inside a file named .jpg
        f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00This program cannot be run in DOS mode.")
        temp_path = Path(f.name)

    try:
        hashes = calculate_file_hashes(temp_path)
        assert len(hashes.sha256) == 64
        assert len(hashes.sha512) == 128
        assert len(hashes.md5) == 32

        result = analyze_file_forensics(temp_path, "disguised_malware.jpg")
        assert result.signature.is_mismatch is True
        assert result.signature.matched_extension == "exe"
        assert result.signature.claimed_extension == "jpg"
        assert result.security_verdict in ["suspicious", "malicious"]
    finally:
        if temp_path.exists():
            temp_path.unlink()
