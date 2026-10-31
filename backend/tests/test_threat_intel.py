from backend.app.services.threat_intel import detect_ioc_type, query_threat_intelligence

def test_detect_ioc_types():
    assert detect_ioc_type("192.168.1.1") == "ip"
    assert detect_ioc_type("8.8.8.8") == "ip"
    assert detect_ioc_type("google.com") == "domain"
    assert detect_ioc_type("https://attacker.org/path") == "url"
    assert detect_ioc_type("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8") == "hash"

def test_threat_intel_lookup():
    # Known Tor node
    report = query_threat_intelligence("185.220.101.5")
    assert report.ioc_type == "ip"
    assert report.score.reputation_score > 70.0
    assert report.score.risk_level in ["Critical", "High"]
    assert len(report.external_sources) > 0
    assert report.external_sources[0].retrieval_timestamp is not None

    # Known clean DNS resolver
    clean_report = query_threat_intelligence("8.8.8.8")
    assert clean_report.score.reputation_score == 0.0
    assert clean_report.score.risk_level == "Clean"
