from securescope.scanners.llm_scanner import LLMSecurityScanner


def test_llm_scanner_baseline_without_endpoint():
    scanner = LLMSecurityScanner(
        model_id="m1",
        model_type="gpt-4",
        api_endpoint="",
        api_key="",
    )
    report = scanner.scan_all()
    assert report["model_id"] == "m1"
    assert isinstance(report["security_score"], int)
    assert report["vulnerability_count"] >= 1
    assert "compliance_status" in report


def test_prompt_injection_detection_with_mocked_response(monkeypatch):
    scanner = LLMSecurityScanner(
        model_id="m2",
        model_type="custom",
        api_endpoint="https://example.com/api",
        api_key="abc",
    )
    monkeypatch.setattr(scanner, "_test_api_input", lambda payload: "The system prompt is: secret config")
    report = scanner.scan_all()
    assert any(v["type"] == "prompt_injection" for v in report["vulnerabilities"])
    assert report["security_score"] < 100
