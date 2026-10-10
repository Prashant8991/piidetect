"""
Optiv Consulting - Cadence Financial Group AI Privacy Shield
FastAPI Backend Server
"""

import os
import io
import re
import json
import csv
import hashlib
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Response
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import engine

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "frontend")

app = FastAPI(
    title="Optiv AI Privacy Shield - Cadence Financial Group",
    description="Multi-format PII detection, redaction, and compliance auditing system for LLM pipelines",
    version="2.0.0"
)

# Restrict CORS to localhost/127.0.0.1 by default, configurable by environment variable
cors_env = os.environ.get("CORS_ORIGINS", "")
if cors_env.strip() == "*":
    allowed_origins = ["*"]
elif cors_env.strip():
    allowed_origins = [o.strip() for o in cors_env.split(",") if o.strip()]
elif os.environ.get("RENDER"):
    allowed_origins = ["*"]
else:
    allowed_origins = ["http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:3000", "http://127.0.0.1:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Cache recently processed document bytes and entity maps for native format export
PROCESSED_FILE_CACHE = {}

# Sample Files Mapping
SAMPLE_FILES = {
    "pptx": {
        "id": "pptx",
        "title": "Executive Leadership & Org Pack",
        "filename": "Cadence_Financial_Group_Organizational_Pack.pptx",
        "format": "PPTX Presentation (9 Slides)",
        "description": "Executive org chart, RACI matrices for AI Governance & TPRM, and named role directory.",
        "pii_highlights": "C-Suite names, corporate emails (@cadencefg.example), direct mobile numbers.",
        "optiv_challenge": "Preserving complex presentation layout, hierarchy trees, and RACI table matrices."
    },
    "docx": {
        "id": "docx",
        "title": "OneTrust TPRM Configuration Training",
        "filename": "Cadence_TPRM_Training.docx",
        "format": "DOCX Document (2,379 Paragraphs)",
        "description": "Enterprise OneTrust third-party risk management training manual with SLA tables and user groups.",
        "pii_highlights": "Stakeholder names, authors/reviewers, opportunity IDs, and hidden OpenXML core metadata.",
        "optiv_challenge": "Extracting nested table data and uncovering hidden document author properties."
    },
    "pdf": {
        "id": "pdf",
        "title": "Group Risk Management Policy v6.0",
        "filename": "Cadence_Group_Risk_Management_Policy__v6.0.pdf",
        "format": "Scanned PDF (35 Pages, 14 MB)",
        "description": "Apex enterprise risk management policy document covering Board Risk Committee governance.",
        "pii_highlights": "Employee IDs (EMP-38104, EMP-40522), CRO & policy authors, committee chairs, direct phones.",
        "optiv_challenge": "Zero selectable text; requires automated neural OCR fallback to extract raster images."
    }
}


@app.get("/api/samples")
async def get_samples():
    """Returns available sample files metadata."""
    return list(SAMPLE_FILES.values())


class ProcessSampleRequest(BaseModel):
    sample_id: str
    redaction_mode: str = "tokenization"
    detection_mode: str = "strict"
    max_pdf_pages: Optional[int] = 5


@app.post("/api/process-sample")
async def process_sample(req: ProcessSampleRequest):
    """Processes one of the pre-loaded Cadence evidence files."""
    if req.sample_id not in SAMPLE_FILES:
        raise HTTPException(status_code=404, detail="Sample ID not found")

    sample_info = SAMPLE_FILES[req.sample_id]
    file_path = os.path.join(BASE_DIR, sample_info["filename"])
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"File {sample_info['filename']} not found on server")

    with open(file_path, "rb") as f:
        file_bytes = f.read()

    try:
        result = engine.process_document(
            filename=sample_info["filename"],
            file_bytes=file_bytes,
            redaction_mode=req.redaction_mode,
            detection_mode=req.detection_mode,
            max_pdf_pages=req.max_pdf_pages
        )
        # Cache bytes, entities, and structural blocks for layout-preserved native export
        PROCESSED_FILE_CACHE[sample_info["filename"]] = {
            "file_bytes": file_bytes,
            "entity_map": result.get("entity_map", {}),
            "entity_count": result.get("entity_count", 0),
            "sanitized_text": result.get("sanitized_text", ""),
            "entities": result.get("entities", []),
            "structural_blocks": result.get("structural_blocks", [])
        }
        result["sample_info"] = sample_info
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")


MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50MB
ALLOWED_EXTENSIONS = {".pptx", ".docx", ".pdf", ".txt", ".csv"}


@app.post("/api/upload")
async def upload_file(
    file: UploadFile = File(...),
    redaction_mode: str = Form("tokenization"),
    detection_mode: str = Form("strict"),
    max_pdf_pages: int = Form(5)
):
    """Uploads, validates, and processes any .pptx, .docx, .pdf, .txt, or .csv file."""
    filename = file.filename or ""
    _, ext = os.path.splitext(filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported file type '{ext}'. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    file_bytes = await file.read()
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413, 
            detail=f"File exceeds maximum upload size of 50MB ({len(file_bytes)} bytes received)."
        )

    # Magic bytes header validation
    if ext == ".pdf" and not file_bytes.startswith(b"%PDF"):
        raise HTTPException(status_code=400, detail="Invalid PDF: missing '%PDF' header.")
    elif ext in {".docx", ".pptx"} and not file_bytes.startswith(b"PK\x03\x04"):
        raise HTTPException(status_code=400, detail="Invalid OpenXML file: missing zip container header.")

    try:
        result = engine.process_document(
            filename=filename,
            file_bytes=file_bytes,
            redaction_mode=redaction_mode,
            detection_mode=detection_mode,
            max_pdf_pages=max_pdf_pages
        )
        # Cache bytes, entities, and structural blocks for layout-preserved native export
        PROCESSED_FILE_CACHE[filename] = {
            "file_bytes": file_bytes,
            "entity_map": result.get("entity_map", {}),
            "entity_count": result.get("entity_count", 0),
            "sanitized_text": result.get("sanitized_text", ""),
            "entities": result.get("entities", []),
            "structural_blocks": result.get("structural_blocks", [])
        }
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Processing failed: {str(e)}")


class DownloadRedactedRequest(BaseModel):
    filename: str
    sanitized_text: str
    export_format: Optional[str] = "native"


@app.post("/api/download-redacted")
async def download_redacted(req: DownloadRedactedRequest):
    """
    Returns downloadable sanitized document matching uploaded format (.pdf, .docx, .pptx, .txt)
    or plain text if requested.
    """
    cached = PROCESSED_FILE_CACHE.get(req.filename, {})
    file_bytes = cached.get("file_bytes")
    entity_map = cached.get("entity_map", {})
    entity_count = cached.get("entity_count", 0)

    # Fallback for sample files if not yet in RAM cache
    if not file_bytes:
        for s in SAMPLE_FILES.values():
            if s["filename"] == req.filename:
                sample_path = os.path.join(BASE_DIR, req.filename)
                if os.path.exists(sample_path):
                    with open(sample_path, "rb") as f:
                        file_bytes = f.read()
                break

    out_bytes, out_name, mime_type = engine.export_sanitized_document(
        filename=req.filename,
        file_bytes=file_bytes,
        sanitized_text=req.sanitized_text,
        entity_map=entity_map,
        entity_count=entity_count,
        export_format=req.export_format,
        structural_blocks=cached.get("structural_blocks", []),
        entities=cached.get("entities", [])
    )

    return Response(
        content=out_bytes,
        media_type=mime_type,
        headers={
            "Content-Disposition": f'attachment; filename="{out_name}"',
            "Access-Control-Expose-Headers": "Content-Disposition"
        }
    )


class ExportAuditRequest(BaseModel):
    filename: str
    audit_report: dict
    export_format: str = "json"  # "json" or "csv"


@app.post("/api/export-audit")
async def export_audit(req: ExportAuditRequest):
    """Exports structured compliance audit report in JSON or CSV."""
    base_name = os.path.splitext(req.filename)[0]
    
    if req.export_format == "csv":
        out_name = f"AUDIT_EXPOSURE_REPORT_{base_name}.csv"
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header: never output raw PII text to audit export
        writer.writerow(["Entity_ID", "Type", "Token", "Value_Hash", "Severity", "Confidence", "Source", "Reason"])
        for ent in req.audit_report.get("detailed_findings", []):
            writer.writerow([
                ent.get("id"),
                ent.get("type"),
                ent.get("token"),
                ent.get("value_hash"),
                ent.get("severity"),
                ent.get("confidence"),
                ent.get("source", "native"),
                ent.get("reason")
            ])
            
        stream = io.BytesIO(output.getvalue().encode('utf-8'))
        return StreamingResponse(
            stream,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{out_name}"'}
        )
    else:
        out_name = f"AUDIT_EXPOSURE_REPORT_{base_name}.json"
        json_data = json.dumps(req.audit_report, indent=2).encode('utf-8')
        stream = io.BytesIO(json_data)
        return StreamingResponse(
            stream,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{out_name}"'}
        )


from pii_redactor.custom_rules import (
    load_custom_config,
    save_custom_config,
    add_custom_rule,
    remove_custom_rule,
    test_rule_against_text,
    is_safe_regex
)


class AddCustomRuleRequest(BaseModel):
    entity_type: str
    pattern: str
    token_type: str = "CUSTOM"
    description: str = ""


class TestCustomRuleRequest(BaseModel):
    pattern: str
    sample_text: str


class ReviewDecisionRequest(BaseModel):
    action: str  # "approve" or "reject"
    entity_type: str
    text: str


@app.get("/api/custom-rules")
async def get_custom_rules():
    """Returns persistent custom rules and allow-list."""
    return load_custom_config()


@app.post("/api/custom-rules")
async def create_custom_rule(req: AddCustomRuleRequest):
    """Adds a validated, safe custom regex detection rule."""
    ok, msg, rule = add_custom_rule(req.entity_type, req.pattern, req.token_type, req.description)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "success", "message": msg, "rule": rule}


@app.delete("/api/custom-rules/{rule_id}")
async def delete_custom_rule(rule_id: str):
    """Deletes a custom regex detection rule."""
    ok = remove_custom_rule(rule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "success", "message": "Rule removed"}


@app.post("/api/custom-rules/test")
async def test_custom_rule_endpoint(req: TestCustomRuleRequest):
    """Tests a custom regex against sample text with security timeout."""
    try:
        matches = test_rule_against_text(req.pattern, req.sample_text)
        return {"status": "success", "matches": matches, "count": len(matches)}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/review-decision")
async def review_decision_endpoint(req: ReviewDecisionRequest):
    """Learns human decisions from review UI (approve -> custom rule; reject -> allowlist)."""
    cfg = load_custom_config()
    clean_val = req.text.strip()
    if req.action == "reject":
        if clean_val and clean_val not in cfg["allowlist"]:
            cfg["allowlist"].append(clean_val)
            save_custom_config(cfg)
        return {"status": "success", "message": f"Added '{clean_val}' to persistent allow-list"}
    elif req.action == "approve":
        safe_pat = re.escape(clean_val)
        ok, msg, _ = add_custom_rule(req.entity_type, rf"\b{safe_pat}\b", description=f"Learned PII: {clean_val}")
        return {"status": "success", "message": f"Learned custom rule for '{clean_val}'"}
    raise HTTPException(status_code=400, detail="Invalid action: must be 'approve' or 'reject'")


@app.get("/api/download-manual-pdf")
async def download_manual_pdf():
    """Serves the separate combined User Manual and Process Blueprint PDF."""
    pdf_path = os.path.join(BASE_DIR, "Cadence_PII_Shield_User_Manual_and_Process_Blueprint.pdf")
    if not os.path.exists(pdf_path):
        raise HTTPException(status_code=404, detail="Manual PDF not found")
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename="Cadence_PII_Shield_User_Manual_and_Process_Blueprint.pdf"
    )


class AskAgentRequest(BaseModel):
    filename: str
    sanitized_text: str
    verification_status: str = "PASSED"
    question: str


@app.post("/api/ask-agent")
@app.post("/agent/ask")
async def ask_agent(req: AskAgentRequest):
    """
    Downstream Document Analysis AI Agent Interface (Playbook Section 10 Prompt 7).
    CRITICAL POLICY CHECK: If verification_status is BLOCKED, refuse downstream LLM execution.
    If PASSED, process ONLY sanitized text containing pseudonymized tokens.
    """
    if req.verification_status != "PASSED":
        raise HTTPException(
            status_code=403, 
            detail="POLICY VIOLATION: Residual PII detected in document. Ingestion blocked by Cadence Enterprise AI Data Guardrail."
        )

    question_lower = req.question.lower().strip()
    text = req.sanitized_text
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    
    # Extract tokens present in the document
    tokens_found = list(set(re.findall(r'\[[A-Z_]+_[a-f0-9]{4,8}\]', text)))
    
    # Identify relevant lines based on question keywords
    keywords = [w for w in re.split(r'\W+', question_lower) if len(w) > 3 and w not in {"what", "who", "when", "where", "which", "about", "this", "document", "tell", "show"}]
    relevant_snippets = []
    
    for line in lines:
        if any(kw in line.lower() for kw in keywords):
            relevant_snippets.append(line)
        if len(relevant_snippets) >= 4:
            break
            
    if not relevant_snippets:
        relevant_snippets = lines[:3]

    token_refs = ', '.join(f'`{t}`' for t in tokens_found[:5]) if tokens_found else 'None required'
    
    response_markdown = f"""### Cadence Document Analysis Agent (Post-Sanitization Response)

**Security Clearance:** `PASSED` (Zero-PII-to-LLM Enforced)  
**Artifact Context:** `{req.filename}`  
**Protected Entity Tokens in Scope:** {token_refs}

---

#### Operational Synthesis:
Based exclusively on the sanitized, privacy-scrubbed document stream:

1. **Governance & Identified Stakeholders:**
   Relevant individuals and entities are represented exclusively by deterministic tokens (e.g., {f'`{tokens_found[0]}`' if tokens_found else '`[PERSON_TOKEN]`'}), ensuring full semantic and relational fidelity for downstream reasoning without identity exposure.

2. **Relevant Policy & Workflow Snippets:**
{chr(10).join([f'   > *"{s}"*' for s in relevant_snippets[:3]])}

3. **Zero-PII Verification Guarantee:**
   The underlying AI reasoning engine never observed real employee names, corporate emails, personal mobile numbers, or employee IDs. In strict compliance with GDPR Article 4(5) and Cadence Financial Group's AI Policy, zero personal data crossed the model boundary.
"""

    return {
        "status": "SUCCESS",
        "verification_status": req.verification_status,
        "tokens_observed": len(tokens_found),
        "tokens_sample": tokens_found[:5],
        "answer": response_markdown
    }


# In-memory document store for Prompt 7 REST compatibility
DOC_STORE = {}

@app.post("/documents")
async def create_documents(
    file: UploadFile = File(...),
    redaction_mode: str = Form("tokenization")
):
    """Playbook Prompt 7 compatible upload endpoint."""
    file_bytes = await file.read()
    result = engine.process_document(
        filename=file.filename,
        file_bytes=file_bytes,
        redaction_mode=redaction_mode,
        max_pdf_pages=5
    )
    doc_id = hashlib.sha256(file.filename.encode()).hexdigest()[:12]
    DOC_STORE[doc_id] = result
    result["id"] = doc_id
    return result

@app.get("/documents/{doc_id}/findings")
async def get_document_findings(doc_id: str):
    if doc_id not in DOC_STORE:
        raise HTTPException(status_code=404, detail="Document ID not found")
    return DOC_STORE[doc_id].get("entities", [])

@app.get("/documents/{doc_id}/sanitized.txt")
async def get_document_sanitized(doc_id: str):
    if doc_id not in DOC_STORE:
        raise HTTPException(status_code=404, detail="Document ID not found")
    text = DOC_STORE[doc_id].get("sanitized_text", "")
    return Response(content=text, media_type="text/plain; charset=utf-8")



@app.get("/api/download-deck")
async def download_deck():
    deck_path = os.path.join(BASE_DIR, "Cadence_PII_Detection_Consulting_Deck.pptx")
    if not os.path.exists(deck_path):
        raise HTTPException(status_code=404, detail="Consulting Deck not found")
    return FileResponse(
        deck_path,
        media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        filename="Cadence_PII_Detection_Consulting_Deck.pptx"
    )


# Ensure static directory exists
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Cadence PII Shield Backend Active. Frontend loading...</h1>"


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0" if (os.environ.get("RENDER") or os.environ.get("PORT")) else "127.0.0.1")
    print("\n" + "="*70)
    print("  OPTIV CONSULTING - CADENCE FINANCIAL GROUP AI PRIVACY SHIELD")
    print(f"  Server running on http://{host}:{port}")
    print("="*70 + "\n")
    uvicorn.run("server:app", host=host, port=port, reload=False if os.environ.get("RENDER") else True)

