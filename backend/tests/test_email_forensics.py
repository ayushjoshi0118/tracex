import tempfile
from pathlib import Path
from backend.app.services.email_forensics import analyze_email_forensics, defang_url

def test_defang_url():
    assert defang_url("http://malicious.com") == "hxxp://malicious[.]com"
    assert defang_url("https://phish.org/login") == "hxxps://phish[.]org/login"

def test_email_parsing_and_mismatch():
    sample_content = """From: "Bank Security" <alerts@trusted-bank.com>
Reply-To: "External Actor" <thief@attacker-c2.com>
Subject: Security Alert: Confirm Account Now
Date: Fri, 30 Oct 2026 12:00:00 +0000
Message-ID: <test-12345@trusted-bank.com>
Authentication-Results: mx.trusted-bank.com;
    spf=fail;
    dkim=fail;
    dmarc=fail

Please confirm your password at http://192.168.1.50/login.php
"""
    with tempfile.NamedTemporaryFile(suffix=".eml", mode="w", encoding="utf-8", delete=False) as f:
        f.write(sample_content)
        temp_path = Path(f.name)

    try:
        res = analyze_email_forensics(temp_path)
        assert res.sender_reply_to_mismatch is True
        assert res.risk_score > 50.0
        assert "Likely Phishing" in res.verdict or "Suspicious" in res.verdict
        
        # Verify SPF failed check
        spf_results = [a for a in res.auth_results if a.protocol == "SPF"]
        assert len(spf_results) == 1
        assert spf_results[0].status == "fail"
        assert spf_results[0].status_category == "failed"

        # Verify URL extracted
        assert len(res.extracted_urls) >= 1
        assert res.extracted_urls[0].is_ip_address is True
    finally:
        if temp_path.exists():
            temp_path.unlink()
