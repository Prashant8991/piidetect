import urllib.request, json

BASE_URL = "http://127.0.0.1:8000"

def test_api():
    print("Testing API endpoints on", BASE_URL)

    # 1. GET /api/samples
    with urllib.request.urlopen(f"{BASE_URL}/api/samples", timeout=5) as r:
        assert r.status == 200
        samples = json.loads(r.read().decode())
        assert len(samples) == 3
        print("  [PASS] 1. GET /api/samples (3 samples listed)")

    # 2. POST /api/process-sample
    payload = json.dumps({"sample_id": "pptx", "redaction_mode": "tokenization"}).encode()
    req = urllib.request.Request(f"{BASE_URL}/api/process-sample", data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        assert r.status == 200
        res = json.loads(r.read().decode())
        assert res.get("verification_status") == "PASSED"
        sanitized_text = res.get("sanitized_text", "")
        audit_report = res.get("audit_report", {})
        print(f"  [PASS] 2. POST /api/process-sample (Status: {res.get('verification_status')}, Entities: {res.get('entity_count')})")

    # 3. POST /api/download-redacted
    dl_payload = json.dumps({
        "filename": "Cadence_Financial_Group_Organizational_Pack.pptx",
        "sanitized_text": sanitized_text,
        "export_format": "native"
    }).encode()
    req_dl = urllib.request.Request(f"{BASE_URL}/api/download-redacted", data=dl_payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req_dl, timeout=10) as r:
        assert r.status == 200
        content = r.read()
        ctype = r.headers.get("Content-Type")
        assert len(content) > 1000
        assert "presentation" in ctype or "application" in ctype
        print(f"  [PASS] 3. POST /api/download-redacted ({len(content)} bytes, Content-Type: {ctype})")

    # 4. POST /api/export-audit (json)
    ea_json = json.dumps({
        "filename": "Cadence_Financial_Group_Organizational_Pack.pptx",
        "audit_report": audit_report,
        "export_format": "json"
    }).encode()
    req_ea_json = urllib.request.Request(f"{BASE_URL}/api/export-audit", data=ea_json, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req_ea_json, timeout=5) as r:
        assert r.status == 200
        audit_res = json.loads(r.read().decode())
        assert audit_res.get("verification_status") == "PASSED"
        print("  [PASS] 4. POST /api/export-audit format=json")

    # 5. POST /api/export-audit (csv)
    ea_csv = json.dumps({
        "filename": "Cadence_Financial_Group_Organizational_Pack.pptx",
        "audit_report": audit_report,
        "export_format": "csv"
    }).encode()
    req_ea_csv = urllib.request.Request(f"{BASE_URL}/api/export-audit", data=ea_csv, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req_ea_csv, timeout=5) as r:
        assert r.status == 200
        csv_text = r.read().decode()
        assert "Entity_ID" in csv_text or "Token" in csv_text
        print("  [PASS] 5. POST /api/export-audit format=csv")

    # 6. POST /api/ask-agent
    agent_payload = json.dumps({
        "filename": "Cadence_Financial_Group_Organizational_Pack.pptx",
        "sanitized_text": sanitized_text,
        "verification_status": "PASSED",
        "question": "What roles are in the organization?"
    }).encode()
    req_agent = urllib.request.Request(f"{BASE_URL}/api/ask-agent", data=agent_payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req_agent, timeout=10) as r:
        assert r.status == 200
        agent_res = json.loads(r.read().decode())
        assert agent_res.get("status") in {"SUCCESS", "success"}
        print(f"  [PASS] 6. POST /api/ask-agent (Status: {agent_res.get('status')})")

    # 7. GET /api/download-manual-pdf
    with urllib.request.urlopen(f"{BASE_URL}/api/download-manual-pdf", timeout=10) as r:
        assert r.status == 200
        pdf_bytes = r.read()
        assert len(pdf_bytes) > 1000
        assert pdf_bytes.startswith(b"%PDF-")
        print(f"  [PASS] 7. GET /api/download-manual-pdf ({len(pdf_bytes)} bytes, starts with %PDF-)")

    # 8. POST /api/upload (test txt)
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="test_upload.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
        f"Internal memo: Author Desmond Achterberg, Mobile +1 (555) 0123\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="redaction_mode"\r\n\r\n'
        f"tokenization\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    req_up = urllib.request.Request(
        f"{BASE_URL}/api/upload",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    with urllib.request.urlopen(req_up, timeout=10) as r:
        assert r.status == 200
        up_res = json.loads(r.read().decode())
        assert up_res.get("verification_status") == "PASSED"
        print(f"  [PASS] 8. POST /api/upload (Status: {up_res.get('verification_status')}, Entities: {up_res.get('entity_count')})")

    print("\nALL 8 API ENDPOINTS VALIDATED SUCCESSFULLY!")

if __name__ == "__main__":
    test_api()
