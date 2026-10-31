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

def test_relationship_graph_endpoint():
    res = client.get("/api/v1/investigations/")
    assert res.status_code == 200
    inv_id = res.json()[0]["id"]

    graph_res = client.get(f"/api/v1/investigations/{inv_id}/graph")
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    assert "nodes" in graph_data
    assert "edges" in graph_data
    assert graph_data["total_nodes"] > 0
    assert any(n["type"] == "case" for n in graph_data["nodes"])
    assert any(n["type"] == "evidence" for n in graph_data["nodes"])

def test_evidence_comparison_and_transfer_endpoint():
    # Register two hermetic evidence files
    f1 = io.BytesIO(b"FORENSIC SAMPLE A CONTENT FOR COMPARISON 12345")
    f2 = io.BytesIO(b"FORENSIC SAMPLE B CONTENT FOR COMPARISON 67890 DIFFERING BYTES")
    
    r1 = client.post("/api/v1/evidence/register", data={"name": "Hermetic A", "acquired_by": "Alpha", "badge_number": "B1"}, files={"file": ("sample_a.bin", f1, "application/octet-stream")})
    r2 = client.post("/api/v1/evidence/register", data={"name": "Hermetic B", "acquired_by": "Beta", "badge_number": "B2"}, files={"file": ("sample_b.bin", f2, "application/octet-stream")})
    assert r1.status_code == 200
    assert r2.status_code == 200
    ev_a = r1.json()
    ev_b = r2.json()

    # Compare two evidence items
    comp_req = {
        "evidence_id_a": ev_a["id"],
        "evidence_id_b": ev_b["id"]
    }
    comp_res = client.post("/api/v1/evidence/compare", json=comp_req)
    assert comp_res.status_code == 200
    comp_data = comp_res.json()
    assert "hashes" in comp_data
    assert "entropy_delta" in comp_data
    assert "header_a_hex" in comp_data
    assert "forensic_conclusions" in comp_data
    assert comp_data["exact_hash_match"] is False

    # Test custody transfer
    transfer_req = {
        "transferred_to": "Examiner Delta",
        "recipient_badge": "DFIR-9002",
        "transferred_by": "Specialist Vance",
        "releasing_badge": "DFIR-8820",
        "new_location": "Secure Digital Vault Room 4B",
        "reason": "Specialized Memory Extraction Analysis",
        "notes": "Hand-delivered in tamper-evident static shielding bag."
    }
    tx_res = client.post(f"/api/v1/evidence/{ev_a['id']}/transfer", json=transfer_req)
    assert tx_res.status_code == 200
    tx_data = tx_res.json()
    assert tx_data["action"] == "Custody Transfer"
    assert tx_data["badge_number"] == "DFIR-9002"

