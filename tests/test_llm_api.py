def test_llm_model_create_list_and_scan(client, tmp_path):
    from securescope.web import app as sec_app
    import time

    test_db = tmp_path / "llm_test.db"
    sec_app.llm_store.db_path = str(test_db)
    sec_app.llm_store.init_db()

    create_resp = client.post(
        "/api/llm/models",
        json={
            "model_name": "Customer Bot",
            "model_type": "gpt-4",
            "api_endpoint": "https://example.com/api",
            "api_key": "demo-key",
        },
    )
    assert create_resp.status_code == 201
    model_id = create_resp.get_json()["model_id"]
    assert model_id

    list_resp = client.get("/api/llm/models")
    assert list_resp.status_code == 200
    models = list_resp.get_json()
    assert isinstance(models, list)
    assert any(m["model_id"] == model_id for m in models)

    scan_resp = client.post("/api/llm/scan", json={"model_id": model_id})
    assert scan_resp.status_code == 200
    scan_id = scan_resp.get_json()["scan_id"]

    detail = {}
    for _ in range(20):
        detail_resp = client.get(f"/api/llm/scan/{scan_id}")
        assert detail_resp.status_code == 200
        detail = detail_resp.get_json()
        if detail.get("status") == "completed":
            break
        time.sleep(0.2)
    assert "security_score" in detail

    report_resp = client.get(f"/api/llm/report/{scan_id}")
    assert report_resp.status_code == 200
    body = report_resp.get_json()
    assert isinstance(body, dict)
