# Cadence PII Shield | Local PII Detection, Redaction and Compliance Audit Engine

Cadence PII Shield is an offline, zero-trust privacy interceptor and compliance auditing engine designed for the Optiv / Cadence case study. The system inspects, tokenizes, and sanitizes sensitive enterprise artifacts across presentations (PPTX), Word documents (DOCX), scanned image PDFs (PDF), and plain text files before downstream LLM ingestion or external sharing.

All OCR, parsing, pseudonymization, and verification run 100% locally on the host machine. No raw document content or unredacted personal data is ever transmitted to any external API or third-party cloud service.

---

## Architecture and Core Design Principles

1. **Local and Air-Gapped Execution**: All document text extraction, RapidOCR ONNX inference, tokenization, and re-scan validation run entirely on local CPU/GPU hardware.
2. **Fail-Closed Verification**: Every sanitized document undergoes an independent verification pass that re-scans the redacted output with strict regexes and compares value hashes against pass-1 entities. If any residual PII or broken token fragment remains, the file status is marked `BLOCKED` and the document release is halted.
3. **Deterministic, Cross-File Stable Pseudonymization**: Entity replacements use salted HMAC-SHA256 pseudonym tokens (e.g. `[PERSON_NAME_7a689a]`). The same person or entity consistently receives the identical token across PPTX, DOCX, and PDF documents.
4. **Layout-Preserving Redaction**:
   - **PDF**: Scanned PDF pages maintain the exact original page count (e.g. 35 pages) and dimensions. Redactions are burned as solid black opaque rectangles directly over detected OCR bounding boxes on the original page stream, preserving full visual context. A parallel sanitized text stream is generated for LLM prompt ingestion.
   - **DOCX**: XML runs, headers, footers, tables, and document metadata are scrubbed and rewritten in-place. Embedded images are scanned via local OCR.
   - **PPTX**: Text shapes, table directories, and speaker notes are sanitized in-place within the OpenXML presentation tree.
5. **No Raw PII in Logs or Findings**: Value hashes (SHA-256 prefixes) and deterministic tokens are exposed in audit tables and logs rather than plain-text sensitive data.

---

## Repository Structure

```
.
├── server.py                       # FastAPI application serving compliance APIs and UI
├── engine.py                       # Core extraction, detection, pseudonymization, verification, and export engine
├── frontend/                       # Vanilla JavaScript compliance UI (hash-routed, no emoji, rectangular design)
│   ├── index.html                  # Multi-page application structure
│   ├── css/style.css               # Navy/neutral theme, accessible typography, no pills, no glassmorphism
│   └── js/app.js                   # Client-side hash router (#upload, #processing, #results, #audit)
├── pii_redactor/                   # Modular validators, checksums, and detection packages
│   ├── detect.py                   # Presidio/regex detection interfaces
│   ├── validators.py               # Luhn, Verhoeff, and MOD-97 mathematical checksums
│   ├── ocr.py                      # RapidOCR wrapper
│   └── ...
├── pii_tests/                      # Regression and unit test suite
│   ├── test_part1_regressions.py   # Regression tests for Part 1 symptoms and verifier behavior
│   └── ...
├── eval/                           # Formal benchmark and ground truth evaluation
│   ├── run_eval.py                 # Evaluation benchmark script (precision, recall, F1, structure retention)
│   └── ground_truth/               # Reference ground truth annotations (JSON)
├── data/samples/                   # Case study evaluation files (PPTX, DOCX, PDF)
├── requirements.txt                # Python package dependencies
└── README.md                       # Documentation and compliance reference
```

---

## Detection Capabilities and Validators

- **Telephony**: International formats, optional country codes, domestic formatting, and fictional 555 numbers (e.g. `+1 (555) 0123`, `+44 20 7555 0129`, `75550129`, `+33 1 55 55 01 44`). Includes allow-listing for corporate hotline numbers (`+1 (800) 555-0199`).
- **Personal Names**: Multi-tier detection combining table directory extraction, name propagation from corporate email prefixes, contextual role prefixes (*Approved by*, *Policy Owner*), and camelCase-merged OCR normalization. Protected by negative vocabularies for corporate roles, departments, regulators, and vendor risk terminology.
- **Corporate Identifiers**: Employee IDs (`EMP-XXXXX`, `DIR-XXXXX`), Vendor IDs (`MER-XX-XXXXX`), Contract IDs (`OP-XXXXXX`).
- **Mathematical Checksums**:
  - Payment Cards (`CREDIT_CARD`): Luhn Mod-10 algorithm.
  - Indian Aadhaar IDs (`IN_AADHAAR`): Verhoeff algorithm.
  - International Bank Account Numbers (`IBAN`): ISO 7064 Mod-97-10 algorithm.
- **National Identifiers**: US SSN, Indian PAN, Polish PESEL, Passports.

---

## Security Hardening and Environment Variables

The application enforces strict default security controls:

| Environment Variable | Default Value | Description |
|---|---|---|
| `PII_HMAC_SECRET` | Auto-generated in `.hmac_secret` | 32-byte cryptographically secure secret used for deterministic HMAC token generation. If unset, a random secret is created and stored in a git-ignored file. |
| `CORS_ORIGINS` | `http://localhost:8000,http://127.0.0.1:8000` | Comma-separated list of permitted CORS origins. Restricted to localhost by default. |

### Upload Validation
The `/api/upload` endpoint validates:
- Maximum file size: 50 MB.
- Allowed file extensions: `.pptx`, `.docx`, `.pdf`, `.txt`.
- Magic byte validation: Enforces OpenXML `PK\x03\x04` headers for PPTX/DOCX and `%PDF-` headers for PDF files.
- Temp file safety: Uploads are processed in isolated temporary storage and immediately cleaned up.

---

## User Interface

The web interface is designed as an internal enterprise compliance audit console:
- **Design System**: Deep navy primary palette (`#0F172A`), neutral slate background (`#F8FAFC`), crisp 1px borders, rectangular controls with 4-6px border radii. No pill shapes, no glassmorphism blur, no glowing animations.
- **Navigation**: Client-side hash routing:
  1. `#/upload`: Sample selector or secure document upload with redaction options.
  2. `#/processing`: Multi-stage progress tracking (ingest, extract, OCR, detect, redact, verify) with per-page extraction method logs.
  3. `#/results`: Side-by-side comparison pane (raw extracted artifact on the left, sanitized stream on the right) with synchronized line scrolling, format marker tags, search, and native document download.
  4. `#/audit`: Compliance findings table, entity/page/source filters, summary counts, verifier residual list, and JSON/CSV export.
- **Accessibility and Restraint**: Zero emojis across all screens, buttons, markers, tooltips, and audit reports. Accessible focus indicators, keyboard navigable, responsive across desktop, tablet, and mobile displays.

---

## Installation and Setup

### 1. Clone the Repository
```bash
git clone https://github.com/Prashant8991/piidetect.git
cd piidetect
```

### 2. Environment Setup
```bash
# Create virtual environment
python -m venv .venv

# Activate on Windows
.venv\Scripts\activate

# Activate on Linux / macOS
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Development Server
```bash
python -m uvicorn server:app --reload --host 127.0.0.1 --port 8000
```
Open your browser at `http://127.0.0.1:8000`.

---

## Verification and Evaluation

### Run Unit and Regression Tests
Execute the test suite in `pii_tests/`:
```bash
python -m unittest discover pii_tests
```

### Run Benchmark Evaluation
Run the quantitative benchmark comparing detection against ground truth annotations:
```bash
python eval/run_eval.py
```

### Measured Benchmark Performance

#### 1. Generalization Test Suite Across Splits (DEV vs Held-Out TEST vs FRESH TEST)
Evaluated across 16 document types (CV, Invoice, Medical, Banking, Contract, Minutes, Logs, Chat, Slides, Tax, etc.) in Native PDF, Scanned PDF (with simulated Gaussian blur and skew), DOCX, PPTX, TXT, and CSV formats:

| Split | Documents | High-Severity Recall | Overall Recall | Overall Precision | Overall F1 | Look-Alike False Positives | Blocked Files |
|---|---|---|---|---|---|---|---|
| DEV (Seed 42) | 16 | 85.7% | 84.8% | 86.7% | 85.7% | 3 / 59 (5.1%) | 6 / 16 |
| TEST Held-Out (Seed 1337) | 16 | 90.5% | 89.1% | 85.4% | 87.2% | 3 / 59 (5.1%) | 7 / 16 |
| FRESH TEST (Seed 9999) | 16 | 88.1% | 87.0% | 87.0% | 87.0% | 3 / 59 (5.1%) | 6 / 16 |

#### 2. Name Recall: Contextual Cues vs Standalone Names Without Any Cues
| Split | Names With Contextual Cues | Names Without Cues (Headings, Cells, Running Text) | Total Names GT | Total Names Caught |
|---|---|---|---|---|
| DEV (Seed 42) | 9 / 11 (81.8%) | 9 / 10 (90.0%) | 21 | 18 |
| TEST Held-Out (Seed 1337) | 10 / 11 (90.9%) | 10 / 10 (100.0%) | 21 | 20 |
| FRESH TEST (Seed 9999) | 11 / 11 (100.0%) | 10 / 10 (100.0%) | 21 | 21 |

#### 3. Held-Out TEST (Seed 1337) Performance by Entity Type
| Entity Type | Category | GT | TP | Detected | Recall | Precision | F1 |
|---|---|---|---|---|---|---|---|
| ADDRESS | High Severity | 2 | 2 | 2 | 100.0% | 100.0% | 100.0% |
| CREDIT_CARD | High Severity | 1 | 1 | 1 | 100.0% | 100.0% | 100.0% |
| CUSTOM_ID | High Severity | 5 | 4 | 5 | 80.0% | 80.0% | 80.0% |
| EMAIL | High Severity | 4 | 4 | 4 | 100.0% | 100.0% | 100.0% |
| PERSON_NAME | High Severity | 21 | 20 | 23 | 95.2% | 87.0% | 90.9% |
| PHONE_NUMBER | High Severity | 6 | 6 | 10 | 100.0% | 60.0% | 75.0% |
| SSN | High Severity | 1 | 1 | 1 | 100.0% | 100.0% | 100.0% |
| USER_ID | General | 1 | 1 | 1 | 100.0% | 100.0% | 100.0% |
| IP_ADDRESS | General | 1 | 1 | 0 | 100.0% | N/A | N/A |

#### 4. Case Study Sample Documents
| Artifact | Format | Ground Truth Entities | Detected Entities | Matched TP | Recall | Verification Status | Residual Count |
|---|---|---|---|---|---|---|---|
| Cadence_Financial_Group_Organizational_Pack | PPTX | 12 | 130 | 10 | 83.3% | BLOCKED (Fail-Closed) | 0 |
| Cadence_TPRM_Training | DOCX | 10 | 145 | 8 | 80.0% | BLOCKED (Fail-Closed) | 0 |
| Cadence_Group_Risk_Management_Policy__v6.0 | PDF (35 pgs) | 9 | 80 | 4 | 44.4% | BLOCKED (Fail-Closed) | 0 |

---

## Limitations and Disclosures

1. **Target, Not Guarantee**: Automated PII detection is a layered defense-in-depth guardrail and does not replace human legal review. Detection rates vary depending on scan resolution, lighting, and document layout complexity.
2. **Strict Validator Rejections**: The system enforces mathematical checksums (ISO 7064 MOD 11-2 for ORCID, MOD-97 for IBAN, Luhn for credit cards, Verhoeff for Aadhaar). Synthetically generated numbers that do not compute valid check digits are rejected by design.
3. **OCR Under Raster Noise**: On scanned PDFs with heavy synthetic Gaussian blur, tilt, and noise, local RapidOCR neural models experience character confusion or token drops (yielding ~50% recall on heavily blurred scans compared to 92.9% on native digital text).
4. **Ground Truth Benchmark Gaps**: The provided reference ground truth files in `eval/ground_truth/` are sparse subsets (9-12 items each). For example, the PPTX ground truth omits 14 of the 16 fictional 555 mobile lines in the directory table, which our detector catches.
5. **Fail-Closed Threshold**: If an unredacted telephone or credential pattern is detected in the post-redaction verification pass, or if review candidates exist in Strict mode, the file is intentionally blocked from release.

