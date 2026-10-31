import io
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_health_check_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["platform"] == "TRACEX"

def test_threat_intel_endpoint():
    response = client.get("/api/v1/intel/lookup?ioc=185.220.101.5")
    assert response.status_code == 200
    data = response.json()
    assert data["ioc_value"] == "185.220.101.5"
    assert data["score"]["risk_level"] in ["Critical", "High"]

def test_file_analyze_endpoint():
    file_bytes = b"MZ\x90\x00DummyPortableExecutableFileForTestingForensicScanner"
    files = {"file": ("test_sample.exe", io.BytesIO(file_bytes), "application/octet-stream")}
    response = client.post("/api/v1/files/analyze", files=files)
    assert response.status_code == 200
    data = response.json()
    assert "hashes" in data
    assert data["hashes"]["sha256"] is not None
    assert data["signature"]["matched_extension"] == "exe"

def test_investigations_and_reports_endpoint():
    # List investigations
    res = client.get("/api/v1/investigations/")
    assert res.status_code == 200
    invs = res.json()
    assert len(invs) > 0
    inv_id = invs[0]["id"]

    # Export report JSON
    json_req = {
        "format": "json",
        "include_evidence": True,
        "include_timeline": True,
        "include_iocs": True,
        "include_notes": True
    }
    rep_res = client.post(f"/api/v1/reports/{inv_id}/export", json=json_req)
    assert rep_res.status_code == 200
    rep_json = rep_res.json()
    assert rep_json["investigation"]["id"] == inv_id
    assert "forensic_findings" in rep_json
    assert "observed_facts" in rep_json["forensic_findings"]
    assert "analyst_interpretations_and_hypotheses" in rep_json["forensic_findings"]

    # Export report PDF
    pdf_req = {
        "format": "pdf",
        "include_evidence": True,
        "include_timeline": True,
        "include_iocs": True,
        "include_notes": True,
        "analyst_signature": "Lead Examiner Test",
        "badge_number": "TX-001"
    }
    pdf_res = client.post(f"/api/v1/reports/{inv_id}/export", json=pdf_req)
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 500  # Generated valid PDF stream
