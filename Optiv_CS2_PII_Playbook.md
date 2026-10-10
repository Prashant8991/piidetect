# Optiv Case Study 2: Cadence PII Detection & Redaction
## Build playbook, ready-to-paste agent prompts, UI spec, deck outline

Built from the four things you shared: the Optiv Case Study Brief (CS2 section), `Cadence_Group_Risk_Management_Policy__v6.0.pdf`, `Cadence_Financial_Group_Organizational_Pack.pptx`, and `Cadence_TPRM_Training.docx`. I read all 35 PDF pages, all 9 slides, the full docx text, and sampled the docx screenshots.

---

## 1. What Optiv is actually asking for

**The story.** Cadence employees use an AI "document analysis agent". A new policy says **no PII may be processed by AI models**. So every document must be **stripped of PII before it reaches the LLM**.

**Your job.** Build a repeatable, scalable system that:
1. Extracts text from each file format (scanned PDF, PPTX, DOCX).
2. Detects and classifies PII in that text.
3. Applies transparent tags and keeps source traceability (file, page, location, detector, confidence).
4. Redacts the PII before the LLM sees anything.
5. Summarizes the PII exposure for internal audit.

**The five things you must hand in** (a 10 to 15 minute stakeholder walkthrough, as a PPTX):

| # | Deliverable | What they will look for |
|---|---|---|
| 1 | Solution Blueprint | Functional design diagram: file ingestion to PII output |
| 2 | System Architecture | Detailed components inside each function and how they interact |
| 3 | Extraction Logic | Per-format extraction approach and the detection logic |
| 4 | Reliable Outcomes | **Extracted text keeps at least 80% of its original structure** (with before/after context kept). **PII detection approaches 100% coverage.** |
| 5 | Live Walkthrough | Upload the evidence files, extract text, identify and classify PII per file (Colab, Jupyter, or a simple UI) |

Team submission, about three weeks from release.

**Measurable targets you can state:**
- Structure retention at least 80%.
- PII recall about 100% (report real numbers, never claim a guarantee).
- Minimal false positives.
- Nothing unidentified goes downstream.

---

## 2. What the three sample files contain (the traps)

| File | Format | Why it is hard |
|---|---|---|
| Group Risk Management Policy v6.0 | **35-page PDF, every page is a full-page JPEG scan with no text layer** (text extraction returns nothing) | OCR is mandatory on every page. There are also images inside the scanned pages. |
| Organizational Pack | PPTX, 9 slides, native text | Org-chart shapes, RACI tables, a 16-person directory (names, emails, mobiles), and a small logo image. Text is split across many shapes and tables. |
| TPRM Training | DOCX, about 96k characters, 41 embedded media files (35 PNG, 5 EMF, 1 SVG) | Most PII is in **screenshots** (names such as user-group creators). Two big EMF vector images. Headers and footers. Many tables. |

**Hard cases in the PDF** (by page; these are the ones that will make or break your recall):

| Page | What | Why it is hard |
|---|---|---|
| 1, 2, 3 | Cover, document control, entity contacts | Many names, corporate emails, phones, and employee IDs in dense tables |
| 7 | "Out-of-hours escalation" note | A **personal mobile and a home address** inside a sentence |
| 9 | Fig 3, identity record screenshot | A **photo** plus name, email, mobile, and dates inside an image |
| 18 | Fig 8, signed RCSA attestation scan | A stamp, signatures, and a reviewer-note column that **mixes DOB, SSN, tax ID, mobile, and passport in one field** |
| 19 | Fig 9, SecureGRC user list screenshot | Names and emails in a UI screenshot. The caption says it is recoverable only through OCR. |
| 20 | Fig 11, dark terminal audit log | Light text on a dark background. Every line has at least one identifier (users, emails, IPs). |
| 22 | §16.5 incident narrative | **Identifiers inside prose with no field labels**: names, employee IDs, DOB, SSN, passport, tax ID, home address, external email, phone. Field-based extraction fails here. |
| 23 | §16.8 customer letter | A card ending in digits, a phone, an email, a home address, the last 4 of an SSN, a DOB, and relatives' names |
| 25 | §18.5 offshore roster | Indian PAN numbers, a Polish PESEL (partly masked), vendor IDs, and phones in several country formats |
| 28 | Fig 13, ID badge | **Photograph, DOB, employee ID, mobile, barcode** |

**Things that look like PII but are not** (your false-positive controls):
- Document, risk, and issue references: `GRP-POL-001`, `RSK-4488`, `ISS-2026-0112`, `ACC-2026-018`, `INC-2026-0417`.
- Company and regulator names (Cadence, Federal Reserve, PRA/FCA, Halloran & Pike).
- The Cadence **headquarters address**, which is a business address, not personal.
- The "Speak Up" hotline number and shared mailboxes such as `brc@`, `gerc@`, `board.chair@`.
- Policy, effective, approval, and review **dates** (only DOBs should be flagged).
- Money amounts, percentages, committee names, and role titles on their own.

---

## 3. The hidden rubric: Appendix E.6 of the policy PDF

Page 35 of the PDF lists six "exercise prompts for students". They are almost certainly what Optiv will probe in the walkthrough. Design your demo to answer each one directly.

| # | Exercise | Feature you must demo |
|---|---|---|
| 1 | Extract text from every page and report **which pages required OCR** | A per-page "extraction method" badge: native vs OCR |
| 2 | Enumerate **all PII instances by category, with page and location**, distinguishing body text, tables, narrative prose, and image-only | Findings table with category, page, location type, and bounding box |
| 3 | Identify every identifier that appears **only inside an image**, and measure the **recall difference against digitally native** text | A recall metric split by source (native, OCR, image-only) |
| 4 | Locate identifiers inside unlabelled narrative prose (§16.5, §16.8) and **explain why field-based extraction fails** | A side-by-side showing that a label-based baseline misses what your NER and context detection catch |
| 5 | Produce a **masked derivative that preserves page count, layout, and cross-artifact traceability of individuals via stable tokens** | Redacted output files plus consistent tokens such as `[PERSON_3f9a]` across all three files |
| 6 | Justify the **false-positive controls** for PAN, PESEL, TIN, and card-number patterns | Checksum and context validators plus an allow-list, shown in the deck |

---

## 4. Design decisions that matter

1. **Local only for anything that sees raw text.** Do not send raw pages to a cloud OCR or a vision LLM. That would break the very policy the case is about. Use local OCR (Tesseract and RapidOCR). Only the **sanitized** output may go to an LLM, for the demo "ask the agent" step.
2. **Fail closed.** If the verifier finds any residual PII in the redacted output, block the file instead of passing it downstream.
3. **Do not hard-code the sample values.** Optiv will likely run unseen files. Build general detectors (patterns, checksums, context, NER, gazetteer), not a list of the values in these three files.
4. **Defense in depth.** Run several detectors (regex with validators, Presidio, spaCy NER, a gazetteer built from tables, face and barcode detection) and take the union.
5. **A "paranoid" threshold.** Low-confidence OCR regions that look like names, digits, or emails are redacted conservatively. Make this a visible setting.
6. **Say plainly that 100% is a target, not a guarantee.** Report measured precision and recall on your annotated set, and what the misses look like.
7. **Explainable findings.** Every finding carries: file, page, location type, bounding box, entity type, detector, confidence, and a hash of the value. Never store the raw value in the audit log.

---

## 5. Architecture

**Functional flow (the slide-1 diagram):**

```
Upload -> Ingest & type sniff -> Extract (native / OCR / image-in-doc) -> Unified Document Model
      -> Detect (regex+validators | Presidio | NER | gazetteer | face/barcode)
      -> Resolve & classify (merge, dedupe, stable tokens, business-vs-personal)
      -> Redact (text, raster, in-place docx/pptx, metadata scrub)
      -> Verify (second pass, fail closed)
      -> Outputs: sanitized text for LLM + masked files + audit report + dashboard
```

**Unified document model** (the key to traceability). Every extractor outputs the same shape:

```
Document { id, filename, type, pages[] }
Page     { index, method: native|ocr|mixed, blocks[] }
Block    { id, kind: heading|para|table_cell|list_item|header|footer|note|figure_text,
           text, bbox, reading_order, source: native|ocr|embedded_image, path, ocr_conf }
Finding  { id, doc, page, block_id, bbox, entity, detector, score, source, token, value_hash }
```

**Components:**

| Layer | Component | Notes |
|---|---|---|
| Ingest | Type sniffer, size and page limits | Detects scanned-vs-native PDF per page |
| Extract | PDF: PyMuPDF to render at 300 dpi, then OCR. DOCX: python-docx plus headers, footers, tables, text boxes, then OCR on embedded media. PPTX: python-pptx walking shapes, groups, tables, notes. | Convert EMF to PNG with LibreOffice before OCR |
| OCR | Tesseract (`image_to_data`) and RapidOCR, with deskew, upscale, and **invert dark regions** | Region-aware: figures get different settings than body text |
| Detect | Presidio recognizers, custom regex plus validators, spaCy NER, gazetteer, OpenCV face detection, barcode decoding | See section 6 |
| Resolve | Merge overlaps, link names to employee IDs, create stable tokens | HMAC-based tokens |
| Redact | Burn boxes into page images, rewrite docx and pptx runs, redact embedded images, scrub metadata | Keep page count and layout |
| Verify | Re-OCR and re-scan the redacted output with a stricter set | Block on residue |
| Report | JSON, CSV, and a PDF audit summary | No raw PII values |
| API and UI | FastAPI backend, React frontend | Live progress |

---

## 6. Detection specification

| Entity | How to detect | False-positive control |
|---|---|---|
| PERSON | spaCy NER plus a gazetteer built from directory tables. Also catch initial-only forms ("M. T. Achebe", "L.-E. Brannstrom") by matching against gazetteer names. | Allow-list for committees, org names, and roles |
| EMPLOYEE_ID | `EMP-\d{5}`, `DIR-\d{4}`, vendor IDs like `MER-[A-Z]{2}-\d{4}` | Do not match risk or issue references |
| EMAIL | Standard regex | Mark corporate vs external. Allow-list shared mailboxes. |
| PHONE | Regex for international formats, **not strict validation** (the 555 numbers in the samples are fictional, so libphonenumber's validity check will reject them). Use "possible number" logic. | Allow-list the hotline number |
| SSN (US) | `\d{3}-\d{2}-\d{4}` plus the "last four digits of SSN" context pattern | Reject all-zero groups |
| DOB | Date pattern **plus context** (DOB, "date of birth", "born", or a badge field label) | Ignore effective, approval, and review dates |
| PASSPORT | Pattern plus context keyword ("passport") | Needs context to avoid random alphanumerics |
| PAN (India) | `[A-Z]{5}\d{4}[A-Z]` with the 4th-character entity-type check | Checks stop random 10-character strings from matching |
| PESEL (Poland) | 11 digits with checksum, **and the partly masked form** (6 digits plus `x`s) | Checksum for full values, context for masked |
| TIN / tax ID | Pattern plus context keyword | Context required |
| CREDIT_CARD | Luhn check, plus "card ending NNNN" and "account ending NNNN" patterns | Luhn |
| BANK / IBAN | IBAN regex with checksum | Checksum |
| ADDRESS | Street-pattern regex plus spaCy location context | **Allow-list the corporate HQ address.** Flag personal home addresses. |
| IP / USER_ID | IP regex, `user=` style fields in logs | Only in log-style contexts |
| FACE / PHOTO | OpenCV face detection on every extracted image, plus the "photograph" label | Blur the region |
| BARCODE | Decode with `pyzbar` and redact the barcode region | Decoded value is itself PII |
| SIGNATURE | Optional: ink-like region near a signature line | Mark as lower confidence |

**Business vs personal contact.** Add a `scope` attribute (corporate / personal / external). The brief wants contact details surfaced, so keep corporate emails flagged as PII but labelled corporate. Personal mobiles and home addresses are the higher-severity items.

---

## 7. Structure retention metric (the 80% target)

Define it so you can compute it and defend it:

- **Block recall:** the share of source blocks (headings, paragraphs, table cells, list items) that appear in the extracted output.
- **Reading-order fidelity:** rank correlation between source order and output order.
- **Table fidelity:** share of tables whose row/column grid survives.
- **Heading hierarchy kept:** share of headings preserved with their level.
- **Context window kept:** for each PII span, the text N tokens before and after is preserved (placeholders keep position).

Report one weighted score per file. Ground truth for DOCX and PPTX is the native structure. For the scanned PDF, hand-annotate a few pages as the reference.

---

## 8. Evaluation plan

1. Hand-annotate ground truth PII in all three files (start with the hard pages in section 2). Store as JSON.
2. Compute precision, recall, and F1 **per entity type**, and **per source** (native text, OCR text, image-only).
3. Report the image-only vs native recall gap (exercise 3).
4. Run a label-based baseline (field labels only) and show it misses narrative PII (exercise 4).
5. Run the verifier on redacted outputs and report the residual count.
6. Keep an "add missed PII" feature in the UI so annotation is fast.
7. Test on a few unseen documents you create yourself to check generalization.

---

## 9. Setup commands

Windows note: if you are on Windows, install Tesseract from the UB Mannheim installer and add it to PATH. PyMuPDF renders PDFs, so you do not need poppler.

```bash
# system tools (Debian/Ubuntu)
sudo apt-get update && sudo apt-get install -y tesseract-ocr libzbar0 libreoffice

# project
mkdir cadence-pii-shield && cd cadence-pii-shield
python -m venv .venv && source .venv/bin/activate
pip install presidio-analyzer presidio-anonymizer spacy pymupdf python-docx python-pptx \
  pytesseract pillow opencv-python-headless numpy pyzbar rapidocr-onnxruntime \
  fastapi "uvicorn[standard]" python-multipart pydantic pytest pandas rapidfuzz pyyaml
python -m spacy download en_core_web_lg

# frontend
npm create vite@latest frontend -- --template react-ts
cd frontend && npm install && npm install -D tailwindcss postcss autoprefixer
npm install framer-motion lucide-react recharts
```

Repo layout:

```
cadence-pii-shield/
  backend/app/{main.py, pipeline/{ingest,extract_pdf,extract_docx,extract_pptx,ocr,model,verify,tokens,report}.py,
               pipeline/detect/*.py, pipeline/redact/*.py, config/{allowlist.yaml,entities.yaml}}
  backend/tests/
  eval/{ground_truth/*.json, run_eval.py}
  data/samples/            # the three files go here
  frontend/
  docs/
```

---

## 10. Copy-paste prompts for your coding agent

Give these **in order**. Run the tests after each step before moving on.

### Prompt 0: master brief (paste first, keep in context)

```
You are building "Cadence PII Shield", a system for Optiv Case Study 2. Cadence policy forbids PII from reaching an LLM, so every document must be stripped of PII BEFORE LLM processing.

Inputs: scanned PDFs (image-only, no text layer), PPTX, DOCX. The sample set is in data/samples/.
Outputs per file: (1) sanitized text for the LLM, (2) masked derivative file preserving page count and layout, (3) an audit report of findings (file, page, location type, bbox, entity, detector, confidence, token, value hash; NEVER the raw value), (4) a pass/fail verification result.

Hard rules:
- All OCR and detection run locally. Never send raw document content to any external API.
- Fail closed: if the verifier finds residual PII, mark the file BLOCKED.
- No hard-coded sample values. Detectors must generalize to unseen documents.
- Every extractor outputs the unified Document/Page/Block model defined in docs/model.md.
- Targets: at least 80% structure retention, PII recall near 100% on the annotated set, minimal false positives.
- Stable tokens: HMAC-SHA256(secret, normalized_value) shortened, e.g. [PERSON_3f9a1c], identical across files for the same individual.

Stack: Python 3.11, FastAPI, PyMuPDF, python-docx, python-pptx, Tesseract + RapidOCR, Presidio, spaCy en_core_web_lg, OpenCV, pyzbar. Frontend: React + Vite + Tailwind.
Write tests with pytest. Ask me before changing any of the rules above.
```

### Prompt 1: scaffold and document model

```
Create the repo layout from the master brief. Implement backend/app/pipeline/model.py with dataclasses/pydantic for Document, Page, Block, Finding exactly as: Block{id, kind, text, bbox, reading_order, source(native|ocr|embedded_image), path, ocr_conf}; Finding{id, doc, page, block_id, bbox, entity, detector, score, source, token, value_hash}. Add docs/model.md describing them. Add a FastAPI app with GET /health and POST /process (stub). Add pytest with one test per model. Do not implement extraction yet.
```

### Prompt 2: extractors

```
Implement extractors that return the unified model.
1) PDF (extract_pdf.py): per page, try native text via PyMuPDF; if a page has under 20 characters of text, treat it as scanned: render at 300 dpi and OCR. Record page.method = native|ocr|mixed. Also extract embedded images on native pages and OCR them.
2) DOCX (extract_docx.py): iterate body in order (paragraphs AND tables), plus headers, footers, text boxes. Extract every embedded image; convert EMF/SVG to PNG with LibreOffice headless; OCR them as source=embedded_image with a link to the paragraph they sit in.
3) PPTX (extract_pptx.py): walk every slide's shapes including groups, tables, and notes; extract embedded images and OCR them. Keep reading order top-to-bottom, left-to-right.
4) ocr.py: Tesseract image_to_data (oem 1) plus RapidOCR; deskew; upscale small text 2x; auto-invert dark backgrounds; return words with bbox and confidence; merge both engines taking the union, preferring higher confidence.
Also scrub nothing yet. Add tests that run each extractor on data/samples and assert: PDF reports OCR on all 35 pages; PPTX returns 9 slides; DOCX returns table blocks and image blocks. Print a per-file summary of block counts by kind and source.
```

### Prompt 3: detectors

```
Implement detectors in backend/app/pipeline/detect/. Entities and rules:
PERSON (spaCy NER + gazetteer built from table blocks, also match initial-only forms like "M. T. Achebe" and "L.-E. Brannstrom"), EMPLOYEE_ID (EMP-\d{5}, DIR-\d{4}, MER-[A-Z]{2}-\d{4}), EMAIL, PHONE (regex for international formats, do NOT use libphonenumber validity because sample numbers are fictional), SSN (\d{3}-\d{2}-\d{4} and "last four digits of SSN"), DOB (date + context words such as DOB / date of birth / born / badge label), PASSPORT (pattern + the word passport nearby), PAN ([A-Z]{5}\d{4}[A-Z] with 4th-char type check), PESEL (11-digit checksum AND partly masked form), TIN (pattern + context), CREDIT_CARD (Luhn + "card ending NNNN"), IBAN (checksum), ADDRESS (street pattern + location context), IP_ADDRESS, USER_ID in log lines, FACE (OpenCV), BARCODE (pyzbar).
Use Presidio custom recognizers with a context enhancer. Add config/allowlist.yaml for: document/risk/issue reference patterns (GRP-POL-###, RSK-####, ISS-####-####, ACC-, INC-, EXC-), company/regulator names, the corporate HQ address, the hotline number, shared mailboxes. Add a scope attribute (corporate|personal|external) for email, phone, and address.
Unit-test every recognizer with positive, negative, and tricky cases. Each finding must carry detector name and score. Then run on data/samples and print counts by entity and by source.
```

### Prompt 4: resolve, tokens, redaction

```
Implement resolve.py: merge overlapping findings (keep highest score, union detectors), link person names to employee IDs when they co-occur (e.g. "Name (EMP-12345)"), and generate stable tokens via HMAC-SHA256 with a secret from env, normalized (lowercase, strip titles and initials where safe, alias resolution with rapidfuzz). The same individual must get the same token across all three files.
Implement redactors: (a) sanitized text/markdown with tokens, preserving block order and kinds; (b) PDF: burn black boxes into page rasters at finding bboxes and rebuild a PDF with the same page count and page size; (c) DOCX/PPTX: rewrite runs in place, redact embedded images, and scrub document metadata (author, last-modified-by); (d) face blur and barcode blackout.
Add a paranoid mode that redacts low-confidence OCR regions that look like names, digits, or emails.
Tests: page count identical after redaction; no finding value present in sanitized text; tokens identical across files for the same person.
```

### Prompt 5: verifier and audit report

```
Implement verify.py: re-OCR the redacted outputs, re-run a STRICTER detector set (lower thresholds), and compute residual findings. If any residual exists, status=BLOCKED, else PASSED. Implement report.py: JSON and CSV audit reports per file and a combined summary, with findings by entity, page, location type, source, detector, and score. Never write raw values; only value_hash and token. Include extraction method per page (native vs OCR) for exercise 1.
```

### Prompt 6: evaluation

```
Create eval/ground_truth/<file>.json format (file, page, entity, bbox or text anchor). Implement eval/run_eval.py that computes precision, recall, F1 per entity AND per source (native, ocr, embedded_image), the image-only vs native recall gap, a label-based baseline (field labels only) to show it misses narrative PII, structure retention (block recall, reading-order correlation, table fidelity, heading hierarchy, context window kept), and the residual count after verification. Output a markdown table I can paste into slides.
```

### Prompt 7: API

```
Implement FastAPI endpoints: POST /documents (multi-file upload), GET /documents/{id}/events (Server-Sent Events for stage progress: ingest, extract, ocr, detect, resolve, redact, verify), GET /documents/{id}/findings (filters: entity, page, source, min_score), GET /documents/{id}/page/{n}/original and /redacted (PNG with optional overlay), GET /documents/{id}/report.(json|csv), GET /documents/{id}/sanitized.txt, POST /documents/{id}/findings (add a missed PII item for annotation), POST /agent/ask (optional demo: sends ONLY sanitized text to an LLM; refuse if status is BLOCKED). CORS for localhost. Tests for each endpoint.
```

### Prompt 8: UI (see the full spec in section 11, paste it as the prompt)

### Prompt 9: final hardening

```
Run the full pipeline on the samples. Fix: any residual PII from the verifier, false positives against the allow-list, and anything where structure retention is under 80%. Then write README.md with setup, architecture diagram, example output, metrics table, and honest limitations. Do not tune detectors on exact sample strings; improve the general rules.
```

---

## 11. UI spec and prompt (the "premium" version)

**Design language:** dark, calm, high-contrast, security-product feel. Not a template.

- Background `#0A0B10`, surface `#12141C`, border `#232634`, text `#E8EAF2`, muted `#8A8FA3`.
- Accent: emerald `#3DF5B0` for "safe/redacted", violet `#8B7BFF` for focus, amber `#FFC857` for warnings, red `#FF5D6C` for blocked/residual.
- Fonts: Inter (UI), JetBrains Mono (data and tokens).
- Soft glow on active elements, subtle grid texture, 12 to 16px radius, smooth framer-motion transitions.
- Entity colors are consistent everywhere (persons, IDs, contact, government IDs, biometric, financial).

**Screens:**
1. **Upload:** big drag-and-drop zone, multi-file, file-type chips, "local processing only" badge.
2. **Pipeline:** animated stepper per file (Ingest, Extract, OCR, Detect, Resolve, Redact, Verify) driven by SSE, with per-page OCR-vs-native badges.
3. **Document viewer:** split pane with **original vs redacted** and a drag slider. Bounding boxes colored by entity, click a box to see entity, detector, confidence, source, token. Page thumbnails strip with a PII-density heat bar.
4. **Findings table:** filter by entity, page, source (native/OCR/image-only), confidence. Export to CSV/JSON.
5. **Exposure dashboard:** totals by category, page-by-category heatmap, "people exposed" using stable tokens, high-severity callouts (SSN, passport, home address, face), and the image-only vs native recall chart.
6. **LLM gate:** shows the sanitized text that would be sent downstream and a big **PASSED / BLOCKED** status. Optional "ask the document agent" box that only works on sanitized, passed files.
7. **Settings:** paranoid mode toggle, confidence threshold, allow-list editor.

**Paste-ready UI prompt:**

```
Build the frontend in /frontend (React + TypeScript + Vite + Tailwind + framer-motion + recharts + lucide-react) for Cadence PII Shield. Design: dark security-product aesthetic. Colors: bg #0A0B10, surface #12141C, border #232634, text #E8EAF2, muted #8A8FA3, accent emerald #3DF5B0, violet #8B7BFF, amber #FFC857, red #FF5D6C. Fonts Inter + JetBrains Mono. 12-16px radii, subtle glow on active elements, smooth transitions, responsive.
Screens: (1) Upload with drag-and-drop multi-file and a "processed locally" badge. (2) Pipeline stepper per file driven by the SSE endpoint, with per-page native/OCR badges. (3) Document viewer: split pane original vs redacted with a draggable comparison slider, page-thumbnail strip with PII-density bars, bounding-box overlays colored by entity (click to open a side panel: entity, detector, confidence, source, token). (4) Findings table with filters (entity, page, source, min confidence) and CSV/JSON export, plus an "add missed PII" action. (5) Exposure dashboard: counts by category, page-by-category heatmap, people exposed by stable token, high-severity callouts, and a native vs image-only recall chart. (6) LLM gate panel: sanitized text preview and a big PASSED/BLOCKED status; optional ask-the-agent box enabled only for PASSED files. (7) Settings: paranoid mode, threshold, allow-list editor.
Use the REST/SSE endpoints from the backend. Add loading, empty, and error states. Keep it accessible (contrast, keyboard focus). No raw PII values in the UI by default; show tokens, with a click-to-reveal for authorized review.
```

Fast fallback: if time is short, a Streamlit UI with the same screens is quicker. Use the React version only if you have the time to polish.

---

## 12. Deck outline (10 to 15 minutes, about 11 slides)

1. **Title and problem:** Cadence's policy, PII must not reach the LLM.
2. **Approach in one line:** extract locally, detect many ways, redact, verify, fail closed.
3. **Solution blueprint:** the functional flow diagram.
4. **System architecture:** components and interactions.
5. **Sample set analysis:** what each file is and why scanned PDFs, narrative prose, and images are hard.
6. **Extraction logic:** per-format approach, OCR rules, and the unified document model.
7. **Detection logic:** entity table with validators and false-positive controls.
8. **Reliable outcomes:** structure retention and PII recall numbers, native vs image-only gap, baseline comparison.
9. **Live walkthrough:** upload, pipeline, viewer, exposure dashboard, LLM gate.
10. **Exposure summary for audit:** key findings, severity, people exposed (tokens).
11. **Limits and next steps:** what still slips through, how it scales (queue, batch, GPU OCR), human review loop.

**Questions to prepare for:**
- Why not send pages to a vision LLM for OCR? (It breaks the policy.)
- How do you know recall is near 100%? (Annotated set, per-entity numbers, and honest limits.)
- What happens on low-quality scans? (Upscaling, two OCR engines, paranoid mode, fail closed.)
- How do you avoid over-redacting? (Allow-list, checksums, context, scope attribute.)
- How does it scale? (Stateless workers, queue, per-page parallelism.)

---

## 13. What I could not verify

- I read the scanned pages by eye. Exact PII counts will come from your annotation, not from this document.
- I did not run OCR on these files, so I cannot say yet how well Tesseract or RapidOCR will do on the small text in figures. Test the dark terminal log (page 20) and the ID badge (page 28) first.
- "About three weeks" is Optiv's stated window. I don't know your exact submission date, and your interview is Oct 14 to 15. Check what the interview expects you to show by then.
- Your team has not started. Split the work: extraction and OCR, detectors, redaction and verification, UI, and deck and evaluation.

## 14. Suggested 3-week plan

| Days | Goal |
|---|---|
| 1 to 3 | Setup, document model, extractors working on all three files |
| 4 to 7 | Detectors, allow-list, stable tokens |
| 8 to 10 | Redaction and verifier, annotation of ground truth |
| 11 to 14 | Evaluation, fixes, structure-retention tuning |
| 15 to 18 | UI polish and live walkthrough rehearsal |
| 19 to 21 | Deck, README, rehearsal, test on unseen files |
