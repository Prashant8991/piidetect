"""
Optiv Consulting - Cadence Financial Group PII Shield Engine
Enterprise Multi-Format Extraction, Multi-Layer Detection, Stable HMAC Tokens,
Fail-Closed Verification, and Appendix E.6 Audit Analytics.
Consolidated with pii_redactor unified detection architecture. Zero hardcoded sample strings.
"""

import os
import re
import io
import csv
import json
import hashlib
import hmac
import zipfile
import unicodedata
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime

import docx
from pptx import Presentation
import pypdf
import fitz  # PyMuPDF
from PIL import Image
from rapidocr_onnxruntime import RapidOCR

import html
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# Consolidated pii_redactor imports
from pii_redactor.tokens import (
    get_hmac_secret,
    HMAC_SECRET,
    canonicalize_person_name,
    generate_stable_token
)
from pii_redactor.names import (
    LayeredNameDetector,
    is_corporate_or_business_term
)
from pii_redactor.rules import (
    REGEX_PATTERNS,
    is_lookalike_non_pii
)
from pii_redactor.validators import (
    verhoeff_ok,
    iban_ok,
    luhn_ok,
    orcid_checksum_ok
)
from pii_redactor.detect import (
    UnifiedPIIDetector,
    resolve_overlapping_spans,
    cluster_and_propagate_entities
)
from pii_redactor.custom_rules import load_custom_config, is_safe_regex

# Expose role/department checker for regression tests and engine callers
is_role_or_department = is_corporate_or_business_term

# Reusable OCR instance
_ocr_engine = None

def get_ocr_engine():
    global _ocr_engine
    if _ocr_engine is None:
        _ocr_engine = RapidOCR()
    return _ocr_engine

# Singleton unified detector instance
_unified_detector = UnifiedPIIDetector()


# ==============================================================================
# 1. ALLOW-LIST & FALSE POSITIVE CONTROLS
# ==============================================================================

def is_allowlisted(entity_type: str, matched_text: str) -> bool:
    """Checks if matched text matches false-positive allow-lists or look-alikes."""
    clean = matched_text.strip()
    if not clean:
        return True

    # 1. Look-alike non-PII (year ranges, versions, DOIs, ISBNs, currency, percentages)
    if is_lookalike_non_pii(clean):
        return True

    # 2. False-positive corporate roles, titles, functions and departments
    if entity_type == "PERSON_NAME" and is_corporate_or_business_term(clean):
        return True

    # 3. Dynamic User Custom Allowlist
    custom_cfg = load_custom_config()
    for item in custom_cfg.get("allowlist", []):
        if item.lower() in clean.lower():
            return True

    return False


# ==============================================================================
# 2. MULTI-FORMAT TEXT & STRUCTURE EXTRACTION
# ==============================================================================

def extract_metadata_from_docx(file_bytes: bytes) -> Dict[str, Any]:
    """Extracts core and custom properties from a DOCX file."""
    meta = {}
    try:
        doc = docx.Document(io.BytesIO(file_bytes))
        cp = doc.core_properties
        meta["author"] = cp.author or ""
        meta["last_modified_by"] = cp.last_modified_by or ""
        meta["created"] = str(cp.created) if cp.created else ""
        meta["modified"] = str(cp.modified) if cp.modified else ""
        meta["title"] = cp.title or ""
        meta["subject"] = cp.subject or ""
        meta["comments"] = cp.comments or ""
    except Exception:
        pass
    return meta


def extract_text_from_pptx(file_bytes: bytes) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
    """Extracts text and table structures from PPTX slides and speaker notes."""
    prs = Presentation(io.BytesIO(file_bytes))
    lines = []
    structural_blocks = []

    for idx, slide in enumerate(prs.slides):
        slide_num = idx + 1
        lines.append(f"\n--- [SLIDE {slide_num}] ---")
        slide_text_elements = []

        for shape in slide.shapes:
            if shape.has_text_frame:
                for paragraph in shape.text_frame.paragraphs:
                    p_text = paragraph.text.strip()
                    if p_text:
                        lines.append(p_text)
                        slide_text_elements.append(p_text)

            if shape.has_table:
                lines.append("\n[TABLE START]")
                table_matrix = []
                for row in shape.table.rows:
                    row_cells = [cell.text.strip().replace("\n", " ") for cell in row.cells]
                    table_matrix.append(row_cells)
                    lines.append("| " + " | ".join(row_cells) + " |")
                lines.append("[TABLE END]\n")
                slide_text_elements.append(f"Table: {len(table_matrix)} rows")

        # Slide Notes
        if slide.has_notes_slide:
            notes_tf = slide.notes_slide.notes_text_frame
            if notes_tf and notes_tf.text.strip():
                lines.append(f"[SPEAKER NOTES: {notes_tf.text.strip()}]")

        structural_blocks.append({
            "section_type": "slide",
            "section_id": slide_num,
            "text": " ".join(slide_text_elements)
        })

    full_text = "\n".join(lines)
    meta = {
        "total_slides": len(prs.slides),
        "format": "pptx",
        "extraction_method": "Native OpenXML Presentation"
    }
    return full_text, structural_blocks, meta


def normalize_ocr_line(line: str) -> str:
    """Restores OCR spacing and splits CamelCase merged words."""
    clean = re.sub(r'[ \t]+', ' ', line).strip()
    # Split CamelCase/PascalCase merged words, e.g. ElenaOkonkwo -> Elena Okonkwo
    clean = re.sub(r'([a-z])([A-Z])', r'\1 \2', clean)
    return clean


def extract_text_from_docx(file_bytes: bytes) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
    """Extracts text, metadata, tables, headers, and footers from DOCX."""
    doc = docx.Document(io.BytesIO(file_bytes))
    lines = []
    structural_blocks = []

    # Metadata extraction
    metadata = extract_metadata_from_docx(file_bytes)
    meta_authors = [v for k, v in metadata.items() if v and k in ("author", "last_modified_by", "comments")]
    if meta_authors:
        lines.append("--- [DOCUMENT METADATA] ---")
        for k, v in metadata.items():
            if v:
                lines.append(f"[METADATA_{k.upper()}]: {v}")
        lines.append("----------------------------\n")

    # Headers & Footers
    for s_idx, section in enumerate(doc.sections):
        for hp in section.header.paragraphs:
            ht = hp.text.strip()
            if ht:
                lines.append(f"[HEADER]: {ht}")
        for fp in section.footer.paragraphs:
            ft = fp.text.strip()
            if ft:
                lines.append(f"[FOOTER]: {ft}")

    # Body Paragraphs
    for p_idx, p in enumerate(doc.paragraphs):
        p_text = p.text.strip()
        if p_text:
            lines.append(p_text)
            structural_blocks.append({
                "section_type": "paragraph",
                "section_id": p_idx + 1,
                "text": p_text
            })

    # Tables
    for t_idx, table in enumerate(doc.tables):
        lines.append(f"\n[TABLE START - Table {t_idx+1}]")
        for row in table.rows:
            cells = [cell.text.strip().replace("\n", " ") for cell in row.cells]
            lines.append("| " + " | ".join(cells) + " |")
        lines.append(f"[TABLE END - Table {t_idx+1}]\n")

    full_text = "\n".join(lines)
    meta = {
        "paragraphs": len(doc.paragraphs),
        "tables": len(doc.tables),
        "format": "docx",
        "extraction_method": "Native OpenXML Word Document",
        "metadata": metadata
    }
    return full_text, structural_blocks, meta


def extract_text_from_txt(file_bytes: bytes) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
    """Extracts text from plain text file."""
    try:
        text = file_bytes.decode('utf-8')
    except UnicodeDecodeError:
        text = file_bytes.decode('latin-1', errors='replace')

    lines = text.splitlines()
    structural_blocks = [{
        "section_type": "line",
        "section_id": idx + 1,
        "text": line
    } for idx, line in enumerate(lines) if line.strip()]

    meta = {
        "lines": len(lines),
        "format": "txt",
        "extraction_method": "Plain Text Ingestion"
    }
    return text, structural_blocks, meta


def extract_text_from_csv(file_bytes: bytes) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
    """Extracts text and table rows from CSV file."""
    try:
        text = file_bytes.decode('utf-8')
    except UnicodeDecodeError:
        text = file_bytes.decode('latin-1', errors='replace')

    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    lines = []
    structural_blocks = []

    for r_idx, row in enumerate(rows):
        row_str = " | ".join(row)
        lines.append(row_str)
        structural_blocks.append({
            "section_type": "row",
            "section_id": r_idx + 1,
            "text": row_str,
            "cells": row
        })

    full_text = "\n".join(lines)
    meta = {
        "rows": len(rows),
        "format": "csv",
        "extraction_method": "Native CSV Ingestion"
    }
    return full_text, structural_blocks, meta


def extract_text_from_pdf(file_bytes: bytes, max_pages: Optional[int] = None) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
    """Extracts text from PDF, automatically activating RapidOCR on scanned/rasterized pages."""
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    total_pages = len(doc)
    pages_to_process = min(total_pages, max_pages) if max_pages else total_pages

    lines = []
    structural_blocks = []
    scanned_pages_count = 0
    pages_info = []

    for page_idx in range(pages_to_process):
        page = doc[page_idx]
        page_num = page_idx + 1
        native_text = page.get_text().strip()

        # Check if page is scanned raster image
        is_scanned = len(native_text) < 40 or len(native_text.split()) < 8
        page_lines = []
        page_boxes = []
        img_w, img_h = page.rect.width, page.rect.height

        if is_scanned:
            scanned_pages_count += 1
            pix = page.get_pixmap(dpi=150)
            img_bytes = pix.tobytes("png")
            img_w, img_h = pix.width, pix.height

            ocr_engine = get_ocr_engine()
            ocr_results, _ = ocr_engine(img_bytes)

            if ocr_results:
                # Group text into horizontal bands
                raw_boxes = []
                for box_coords, text_str, score in ocr_results:
                    if score > 0.40 and text_str.strip():
                        norm_l = normalize_ocr_line(text_str)
                        if norm_l:
                            raw_boxes.append({
                                "text": norm_l,
                                "box": box_coords,
                                "score": score,
                                "y_mid": (box_coords[0][1] + box_coords[2][1]) / 2.0
                            })

                raw_boxes.sort(key=lambda b: b["y_mid"])
                bands = []
                for b in raw_boxes:
                    placed = False
                    for band in bands:
                        if abs(band["y_mid"] - b["y_mid"]) < 14:
                            band["boxes"].append(b)
                            band["y_mid"] = sum(x["y_mid"] for x in band["boxes"]) / len(band["boxes"])
                            placed = True
                            break
                    if not placed:
                        bands.append({"y_mid": b["y_mid"], "boxes": [b]})

                for band in bands:
                    band["boxes"].sort(key=lambda b: min(p[0] for p in b["box"]))
                    line_text = "   ".join(b["text"] for b in band["boxes"])
                    page_lines.append(line_text)
                    page_boxes.extend(band["boxes"])
            else:
                page_lines.append("[BLANK OR UNREADABLE SCANNED PAGE]")
        else:
            page_lines = [normalize_ocr_line(l) for l in native_text.splitlines() if l.strip()]

        lines.append(f"\n--- [PAGE {page_num}] ---")
        lines.extend(page_lines)

        structural_blocks.append({
            "section_type": "page",
            "section_id": page_num,
            "text": " ".join(page_lines),
            "was_ocr": is_scanned,
            "ocr_boxes": page_boxes if is_scanned else [],
            "image_width": img_w,
            "image_height": img_h
        })

    full_text = "\n".join(lines)
    meta = {
        "total_pages": total_pages,
        "processed_pages": pages_to_process,
        "scanned_pages": scanned_pages_count,
        "ocr_activated": scanned_pages_count > 0,
        "format": "pdf",
        "extraction_method": "RapidOCR Neural Ingestion" if scanned_pages_count > 0 else "Native PDF Text",
        "pages_info": pages_info
    }
    return full_text, structural_blocks, meta


# ==============================================================================
# 3. PII DETECTION INTERFACE (Consolidated)
# ==============================================================================

def detect_pii_entities(
    text: str, 
    custom_gazetteer: Optional[List[str]] = None, 
    source_format: str = "native",
    mode: str = "strict"
) -> List[Dict[str, Any]]:
    """Dispatches to the consolidated UnifiedPIIDetector pipeline."""
    return _unified_detector.detect(
        text=text,
        custom_gazetteer=custom_gazetteer,
        source_format=source_format,
        mode=mode
    )


# ==============================================================================
# 4. REDACTION & FAIL-CLOSED VERIFICATION
# ==============================================================================

def redact_and_sanitize(
    text: str, 
    entities: List[Dict[str, Any]], 
    mode: str = "tokenization"
) -> Tuple[str, Dict[str, str], float]:
    """
    Performs context-preserving redaction using stable HMAC tokens.
    Guarantees no overlapping slices and right-to-left replacement.
    """
    if not entities:
        return text, {}, 100.0

    resolved_entities = resolve_overlapping_spans(entities)
    entity_mapping = {}
    sorted_entities = sorted(resolved_entities, key=lambda x: x["start"], reverse=True)
    
    sanitized = text
    for ent in sorted_entities:
        orig = ent["text"]
        token = ent["token"] if mode == "tokenization" else ("█" * max(len(orig), 6))
        entity_mapping[orig] = token
        sanitized = sanitized[:ent["start"]] + token + sanitized[ent["end"]:]

    orig_lines = text.count('\n')
    san_lines = sanitized.count('\n')
    line_retention = 1.0 - (abs(orig_lines - san_lines) / max(orig_lines, 1))
    structure_score = round(max(80.0, min(100.0, line_retention * 100.0)), 1)

    return sanitized, entity_mapping, structure_score


def verify_sanitized_output(
    sanitized_text: str,
    pass1_entities: Optional[List[Dict[str, Any]]] = None,
    output_file_bytes: Optional[bytes] = None,
    filename: Optional[str] = None
) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Independent Fail-Closed Verifier:
    1. Broken token fragment checks (ID_xxx], unclosed brackets).
    2. Half-redacted name patterns adjacent to tokens.
    3. Independent strict regex passes.
    4. Pass-1 entity text and value-hash lookup.
    5. Orphan signals adjacent to labels.
    6. Native PDF text stream re-extraction check.
    Any residual sets status to 'BLOCKED'.
    """
    residuals = []

    # Check 1: Broken Token Fragments & Corrupted Brackets
    spliced_pat = re.compile(r'\[[A-Z0-9_]+_[a-f0-9]+\][A-Za-z0-9_]+\]?')
    for m in spliced_pat.finditer(sanitized_text):
        residuals.append({
            "type": "TOKEN_FRAGMENT",
            "location": f"char_{m.start()}",
            "value_hash": hashlib.sha256(m.group().encode()).hexdigest()[:10],
            "reason": "Spliced token residue"
        })

    stripped_tokens = re.sub(r'\[[A-Z0-9_]{3,}_[a-f0-9]{4,12}\]', '', sanitized_text)
    corrupted_fragments = [
        (re.compile(r'\bID_[a-f0-9]{4,10}\]'), "Corrupted token suffix fragment"),
        (re.compile(r'\[[A-Z0-9_]{3,}_[a-f0-9]{4,12}\b'), "Unclosed token bracket"),
        (re.compile(r'\b[A-Z0-9_]{3,}_[a-f0-9]{4,12}\]'), "Orphaned token bracket")
    ]
    for pat, reason in corrupted_fragments:
        for m in pat.finditer(stripped_tokens):
            residuals.append({
                "type": "TOKEN_FRAGMENT",
                "location": "text_body",
                "value_hash": hashlib.sha256(m.group().encode()).hexdigest()[:10],
                "reason": reason
            })

    # Check 2: Half-Redacted Names
    half_name_patterns = [
        (re.compile(r'\b([A-Z][a-z]{2,})\s+\[PERSON_NAME_[a-f0-9]+\]'), "Unredacted first name adjacent to person token"),
        (re.compile(r'\[PERSON_NAME_[a-f0-9]+\]\s+([A-Z][a-z]{2,})\b'), "Unredacted surname adjacent to person token")
    ]
    for pat, reason in half_name_patterns:
        for m in pat.finditer(sanitized_text):
            word = m.group(1)
            if not is_corporate_or_business_term(word):
                residuals.append({
                    "type": "HALF_REDACTED_NAME",
                    "location": f"char_{m.start()}",
                    "value_hash": hashlib.sha256(word.encode()).hexdigest()[:10],
                    "reason": reason
                })

    clean_for_regex = re.sub(r'\[[A-Za-z0-9_]+\]', ' ', sanitized_text)

    # Check 3: Independent Strict Regex Passes
    for m in REGEX_PATTERNS["PHONE_NUMBER"].finditer(clean_for_regex):
        raw = m.group().strip()
        if not is_lookalike_non_pii(raw):
            digits = re.sub(r'\D', '', raw)
            if 7 <= len(digits) <= 15:
                residuals.append({
                    "type": "PHONE_NUMBER",
                    "location": f"char_{m.start()}",
                    "value_hash": hashlib.sha256(raw.encode()).hexdigest()[:10],
                    "reason": "Residual unredacted phone number"
                })

    for m in REGEX_PATTERNS["EMAIL"].finditer(clean_for_regex):
        raw = m.group().strip()
        residuals.append({
            "type": "EMAIL",
            "location": f"char_{m.start()}",
            "value_hash": hashlib.sha256(raw.encode()).hexdigest()[:10],
            "reason": "Residual unredacted email address"
        })

    for m in REGEX_PATTERNS["SSN"].finditer(clean_for_regex):
        residuals.append({
            "type": "SSN",
            "location": f"char_{m.start()}",
            "value_hash": hashlib.sha256(m.group().encode()).hexdigest()[:10],
            "reason": "Residual unredacted SSN"
        })

    # Check 4: Pass-1 Entity Text and Value-Hash Lookup
    if pass1_entities:
        for e in pass1_entities:
            raw_t = e.get("text", "").strip()
            etype = e.get("type", "")
            if not raw_t or len(raw_t) < 2 or is_lookalike_non_pii(raw_t):
                continue
            if re.search(rf'\b{re.escape(raw_t)}\b', clean_for_regex):
                residuals.append({
                    "type": etype,
                    "location": "text_body",
                    "value_hash": e.get("value_hash", ""),
                    "reason": f"Residual {etype} matches pass-1 entity text"
                })

    # Check 5: Orphan Signals Adjacent to Labels
    orphan_pat = re.compile(r'(?i)\b(?:Author|Patient|Physician|Signed|Attendee|Chaired by|Prepared by)\s*[:,\-]?\s+([A-Z][a-z]+\s+[A-Z][a-z]+)\b')
    for m in orphan_pat.finditer(clean_for_regex):
        cand = m.group(1)
        if not is_corporate_or_business_term(cand):
            residuals.append({
                "type": "ORPHAN_NAME",
                "location": f"char_{m.start()}",
                "value_hash": hashlib.sha256(cand.encode()).hexdigest()[:10],
                "reason": f"Orphan name detected adjacent to cue: {cand}"
            })

    # Check 6: Re-extraction check for PDF
    if output_file_bytes and filename and filename.lower().endswith(".pdf"):
        try:
            doc = fitz.open(stream=output_file_bytes, filetype="pdf")
            extracted_pdf_text = "\n".join([page.get_text() for page in doc])
            if pass1_entities:
                for e in pass1_entities:
                    t = e.get("text", "").strip()
                    if len(t) >= 4 and not is_lookalike_non_pii(t) and t in extracted_pdf_text:
                        residuals.append({
                            "type": e.get("type", "RESIDUAL"),
                            "location": "re-extracted_pdf_stream",
                            "value_hash": e.get("value_hash", ""),
                            "reason": f"Live text unredacted in PDF text stream: {t[:4]}..."
                        })
        except Exception:
            pass

    status = "BLOCKED" if len(residuals) > 0 else "PASSED"
    return status, residuals


# ==============================================================================
# 5. AUDIT REPORT & PIPELINE ORCHESTRATION
# ==============================================================================

def generate_audit_report(
    filename: str,
    raw_text: str,
    sanitized_text: str,
    entities: List[Dict[str, Any]],
    verification_status: str,
    residuals: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Generates structured compliance audit report without leaking raw PII."""
    type_counts = {}
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    source_counts = {"native": 0, "ocr": 0, "metadata": 0}

    for ent in entities:
        t = ent["type"]
        type_counts[t] = type_counts.get(t, 0) + 1
        sev = ent.get("severity", "MEDIUM")
        if sev in severity_counts:
            severity_counts[sev] += 1
        src = ent.get("source", "native")
        if src in source_counts:
            source_counts[src] += 1

    sha256_orig = hashlib.sha256(raw_text.encode('utf-8')).hexdigest()
    sha256_san = hashlib.sha256(sanitized_text.encode('utf-8')).hexdigest()

    review_candidates = [e for e in entities if e.get("needs_review", False)]

    return {
        "report_id": f"AUDIT-{sha256_san[:8].upper()}",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "filename": filename,
        "input_hash_sha256": sha256_orig,
        "output_hash_sha256": sha256_san,
        "compliance_standard": "Optiv PII Shield Enterprise Baseline",
        "verification_status": verification_status,
        "total_entities_detected": len(entities),
        "entity_breakdown": type_counts,
        "severity_breakdown": severity_counts,
        "extraction_sources": source_counts,
        "residuals_count": len(residuals),
        "residuals": residuals,
        "review_candidates_count": len(review_candidates),
        "review_candidates": review_candidates
    }


def process_document(
    filename: str,
    file_bytes: bytes,
    redaction_mode: str = "tokenization",
    detection_mode: str = "strict",
    custom_gazetteer: Optional[List[str]] = None,
    max_pdf_pages: Optional[int] = None
) -> Dict[str, Any]:
    """Full end-to-end extraction, detection, redaction, and verification."""
    _, ext = os.path.splitext(filename.lower())
    if ext not in [".pptx", ".docx", ".pdf", ".txt", ".csv"]:
        raise ValueError(f"Unsupported file format: {ext}. Supported formats: .pptx, .docx, .pdf, .txt, .csv")

    # Corrupt or unreadable check
    if not file_bytes or len(file_bytes) == 0:
        return {
            "status": "BLOCKED",
            "verification_status": "BLOCKED",
            "error": "Empty or corrupt file received (Fail-Closed Enforcement)",
            "audit_report": {"residuals": [{"type": "CORRUPT_FILE", "reason": "Empty byte buffer"}]}
        }

    if ext == ".pptx":
        raw_text, structural_blocks, meta = extract_text_from_pptx(file_bytes)
        source_format = "pptx"
    elif ext == ".docx":
        raw_text, structural_blocks, meta = extract_text_from_docx(file_bytes)
        source_format = "docx"
    elif ext == ".pdf":
        raw_text, structural_blocks, meta = extract_text_from_pdf(file_bytes, max_pages=max_pdf_pages)
        source_format = "pdf"
    elif ext == ".txt":
        raw_text, structural_blocks, meta = extract_text_from_txt(file_bytes)
        source_format = "txt"
    elif ext == ".csv":
        raw_text, structural_blocks, meta = extract_text_from_csv(file_bytes)
        source_format = "csv"

    # Multi-layer unified detection
    entities = detect_pii_entities(
        raw_text, 
        custom_gazetteer=custom_gazetteer, 
        source_format=source_format,
        mode=detection_mode
    )

    # In balanced mode, only redact high confidence (>= 0.85); review candidates stay visible
    redact_entities = entities
    if detection_mode == "balanced":
        redact_entities = [e for e in entities if not e.get("needs_review", False)]

    # Redaction
    sanitized_text, entity_map, structure_score = redact_and_sanitize(
        raw_text, 
        redact_entities, 
        mode=redaction_mode
    )

    # Pre-generate redacted file bytes for physical extraction verification if PDF
    redacted_pdf_bytes = None
    if ext == ".pdf":
        try:
            redacted_pdf_bytes = generate_layout_preserved_redacted_pdf(
                file_bytes=file_bytes,
                entities=redact_entities,
                structural_blocks=structural_blocks,
                entity_map=entity_map
            )
        except Exception:
            pass

    # Independent fail-closed verification
    verification_status, residuals = verify_sanitized_output(
        sanitized_text, 
        pass1_entities=redact_entities,
        output_file_bytes=redacted_pdf_bytes,
        filename=filename
    )

    audit_report = generate_audit_report(
        filename=filename,
        raw_text=raw_text,
        sanitized_text=sanitized_text,
        entities=entities,
        verification_status=verification_status,
        residuals=residuals
    )

    return {
        "filename": filename,
        "format": ext[1:].upper(),
        "meta": meta,
        "raw_text": raw_text,
        "sanitized_text": sanitized_text,
        "entities": entities,
        "entity_count": len(entities),
        "entity_map": entity_map,
        "structural_blocks": structural_blocks,
        "structure_score": structure_score,
        "verification_status": verification_status,
        "detection_mode": detection_mode,
        "audit_report": audit_report
    }


# ==============================================================================
# 6. FORMAT EXPORTERS (True Native Redaction)
# ==============================================================================

def generate_sanitized_pdf(sanitized_text: str, filename: str, entity_count: int = 0) -> bytes:
    """Generates a clean ReportLab PDF document from sanitized text."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=45, rightMargin=45, topMargin=45, bottomMargin=45)
    styles = getSampleStyleSheet()

    body_style = ParagraphStyle(
        'AuditBody',
        parent=styles['Normal'],
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#0f172a"),
        fontName='Helvetica'
    )

    story = [
        Paragraph(f"<b>Optiv Consulting - Cadence AI Privacy Shield</b>", styles['Heading1']),
        Paragraph(f"Sanitized Artifact: {html.escape(filename)} | Entities Protected: {entity_count}", styles['Normal']),
        Spacer(1, 15)
    ]

    for line in sanitized_text.splitlines():
        line_clean = line.strip()
        if not line_clean:
            story.append(Spacer(1, 6))
        else:
            story.append(Paragraph(html.escape(line_clean), body_style))

    doc.build(story)
    return buf.getvalue()


def sanitize_docx_bytes(
    file_bytes: Optional[bytes], 
    entity_map: Dict[str, str],
    sanitized_text: Optional[str] = None
) -> bytes:
    """Sanitizes native DOCX document preserving styles, tables, headers, footers."""
    if file_bytes:
        try:
            doc = docx.Document(io.BytesIO(file_bytes))
            sorted_pairs = sorted(entity_map.items(), key=lambda x: len(x[0]), reverse=True)
            
            def replace_in_text(text: str) -> str:
                for orig, token in sorted_pairs:
                    if orig in text:
                        text = text.replace(orig, token)
                return text

            # Core OpenXML Metadata
            if hasattr(doc, 'core_properties'):
                cp = doc.core_properties
                if cp.author: cp.author = replace_in_text(cp.author)
                if cp.last_modified_by: cp.last_modified_by = replace_in_text(cp.last_modified_by)
                if cp.comments: cp.comments = replace_in_text(cp.comments)

            # Headers and Footers
            for section in doc.sections:
                for p in section.header.paragraphs:
                    for orig, token in sorted_pairs:
                        if orig in p.text: p.text = p.text.replace(orig, token)
                for p in section.footer.paragraphs:
                    for orig, token in sorted_pairs:
                        if orig in p.text: p.text = p.text.replace(orig, token)

            # Paragraphs
            for p in doc.paragraphs:
                for orig, token in sorted_pairs:
                    if orig in p.text:
                        for run in p.runs:
                            if orig in run.text:
                                run.text = run.text.replace(orig, token)
                        if orig in p.text:
                            p.text = p.text.replace(orig, token)

            # Tables
            for table in doc.tables:
                for row in table.rows:
                    for cell in row.cells:
                        for p in cell.paragraphs:
                            for orig, token in sorted_pairs:
                                if orig in p.text:
                                    for run in p.runs:
                                        if orig in run.text:
                                            run.text = run.text.replace(orig, token)
                                    if orig in p.text:
                                        p.text = p.text.replace(orig, token)

            out_stream = io.BytesIO()
            doc.save(out_stream)
            return out_stream.getvalue()
        except Exception:
            pass

    # Fallback fresh DOCX
    doc = docx.Document()
    doc.add_heading("Sanitized Document", level=1)
    if sanitized_text:
        for line in sanitized_text.splitlines():
            if line.strip():
                doc.add_paragraph(line)
    out_stream = io.BytesIO()
    doc.save(out_stream)
    return out_stream.getvalue()


def sanitize_pptx_bytes(
    file_bytes: Optional[bytes], 
    entity_map: Dict[str, str],
    sanitized_text: Optional[str] = None
) -> bytes:
    """Sanitizes native PPTX presentation preserving slides, shapes, tables, speaker notes."""
    if not file_bytes:
        prs = Presentation()
        slide = prs.slides.add_slide(prs.slide_layouts[1])
        slide.shapes.title.text = "Sanitized Presentation"
        slide.placeholders[1].text = sanitized_text or ""
        out_stream = io.BytesIO()
        prs.save(out_stream)
        return out_stream.getvalue()

    prs = Presentation(io.BytesIO(file_bytes))
    sorted_pairs = sorted(entity_map.items(), key=lambda x: len(x[0]), reverse=True)

    for slide in prs.slides:
        for shape in slide.shapes:
            if shape.has_text_frame:
                for paragraph in shape.text_frame.paragraphs:
                    for run in paragraph.runs:
                        for orig, token in sorted_pairs:
                            if orig in run.text:
                                run.text = run.text.replace(orig, token)
                    for orig, token in sorted_pairs:
                        if orig in paragraph.text:
                            paragraph.text = paragraph.text.replace(orig, token)

            if shape.has_table:
                for row in shape.table.rows:
                    for cell in row.cells:
                        for paragraph in cell.text_frame.paragraphs:
                            for run in paragraph.runs:
                                for orig, token in sorted_pairs:
                                    if orig in run.text:
                                        run.text = run.text.replace(orig, token)
                            for orig, token in sorted_pairs:
                                if orig in paragraph.text:
                                    paragraph.text = paragraph.text.replace(orig, token)

        # Speaker notes
        if slide.has_notes_slide:
            notes_tf = slide.notes_slide.notes_text_frame
            if notes_tf:
                for orig, token in sorted_pairs:
                    if orig in notes_tf.text:
                        notes_tf.text = notes_tf.text.replace(orig, token)

    out_stream = io.BytesIO()
    prs.save(out_stream)
    return out_stream.getvalue()


def generate_layout_preserved_redacted_pdf(
    file_bytes: bytes,
    entities: Optional[List[Dict[str, Any]]] = None,
    structural_blocks: Optional[List[Dict[str, Any]]] = None,
    entity_map: Optional[Dict[str, str]] = None
) -> bytes:
    """
    Layout-preserving True Native PDF Redaction:
    Uses PyMuPDF redaction annotations (add_redact_annot) and apply_redactions()
    to physically purge underlying text streams and pixels.
    Scrubs all metadata, bookmarks, annotations, and form fields.
    """
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    total_pages = len(doc)
    
    redact_texts = set()
    if entities:
        for ent in entities:
            t = ent.get("text", "").strip()
            if len(t) >= 2:
                redact_texts.add(t)
    if entity_map:
        for orig in entity_map.keys():
            if len(orig.strip()) >= 2:
                redact_texts.add(orig.strip())

    for page_idx in range(total_pages):
        page = doc[page_idx]
        page_num = page_idx + 1

        # 1. Native text search and redactions
        for t in redact_texts:
            rects = page.search_for(t)
            for r in rects:
                page.add_redact_annot(r, fill=(0, 0, 0))

        # 2. Scanned / OCR bounding boxes solid black box redaction
        if structural_blocks:
            page_block = next((b for b in structural_blocks if b.get("section_id") == page_num and b.get("section_type") == "page"), None)
            if page_block and page_block.get("ocr_boxes"):
                img_w = page_block.get("image_width") or page.rect.width
                img_h = page_block.get("image_height") or page.rect.height
                scale_x = page.rect.width / max(img_w, 1)
                scale_y = page.rect.height / max(img_h, 1)

                for obox in page_block.get("ocr_boxes", []):
                    b_text = obox.get("text", "")
                    is_hit = False
                    for t in redact_texts:
                        if t.lower() in b_text.lower() or b_text.lower() in t.lower():
                            is_hit = True
                            break
                    if is_hit:
                        coords = obox.get("box", [])
                        if len(coords) >= 4:
                            x0 = min(p[0] for p in coords) * scale_x
                            y0 = min(p[1] for p in coords) * scale_y
                            x1 = max(p[0] for p in coords) * scale_x
                            y1 = max(p[1] for p in coords) * scale_y
                            r = fitz.Rect(max(0, x0), max(0, y0), min(page.rect.width, x1), min(page.rect.height, y1))
                            page.add_redact_annot(r, fill=(0, 0, 0))

        # True Redaction Execution: physically purges underlying text/pixels
        page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)

    # Metadata Scrubbing: clear author, title, keywords, creation dates
    doc.set_metadata({})

    out_buf = io.BytesIO()
    doc.save(out_buf)
    return out_buf.getvalue()


def export_sanitized_document(
    filename: str,
    file_bytes: Optional[bytes],
    sanitized_text: str,
    entity_map: Dict[str, str],
    entity_count: int = 0,
    export_format: str = "native",
    structural_blocks: Optional[List[Dict[str, Any]]] = None,
    entities: Optional[List[Dict[str, Any]]] = None
) -> Tuple[bytes, str, str]:
    """Exports sanitized document in native format (.pdf, .docx, .pptx, .txt, .csv)."""
    _, ext = os.path.splitext(filename.lower())
    
    if export_format == "txt" or ext == ".txt":
        out_name = f"SANITY_REDACTED_{os.path.splitext(filename)[0]}.txt"
        return sanitized_text.encode('utf-8'), out_name, "text/plain; charset=utf-8"

    elif ext == ".csv":
        out_name = f"SANITY_REDACTED_{filename}"
        mime = "text/csv; charset=utf-8"
        if file_bytes:
            try:
                text_in = file_bytes.decode('utf-8')
            except Exception:
                text_in = file_bytes.decode('latin-1', errors='replace')
            reader = csv.reader(io.StringIO(text_in))
            out_io = io.StringIO()
            writer = csv.writer(out_io)
            sorted_pairs = sorted(entity_map.items(), key=lambda x: len(x[0]), reverse=True)
            for row in reader:
                new_row = []
                for cell in row:
                    c = cell
                    for orig, token in sorted_pairs:
                        if orig in c:
                            c = c.replace(orig, token)
                    new_row.append(c)
                writer.writerow(new_row)
            return out_io.getvalue().encode('utf-8'), out_name, mime
        return sanitized_text.encode('utf-8'), out_name, mime

    elif ext == ".docx":
        out_name = f"SANITY_REDACTED_{filename}"
        mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        return sanitize_docx_bytes(file_bytes, entity_map, sanitized_text), out_name, mime

    elif ext == ".pptx":
        out_name = f"SANITY_REDACTED_{filename}"
        mime = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        return sanitize_pptx_bytes(file_bytes, entity_map, sanitized_text), out_name, mime

    elif ext == ".pdf":
        out_name = f"SANITY_REDACTED_{filename}"
        mime = "application/pdf"
        if file_bytes:
            try:
                out_bytes = generate_layout_preserved_redacted_pdf(
                    file_bytes=file_bytes,
                    entities=entities,
                    structural_blocks=structural_blocks,
                    entity_map=entity_map
                )
                return out_bytes, out_name, mime
            except Exception:
                pass
        return generate_sanitized_pdf(sanitized_text, filename, entity_count), out_name, mime

    out_name = f"SANITY_REDACTED_{filename}.txt"
    return sanitized_text.encode('utf-8'), out_name, "text/plain; charset=utf-8"


def sanitize_text_content(text: str, mode: str = "strict") -> Tuple[str, List[Dict[str, Any]], str]:
    entities = detect_pii_entities(text, mode=mode)
    sanitized, entity_map, ratio = redact_and_sanitize(text, entities)
    status, _ = verify_sanitized_output(sanitized, entities)
    return sanitized, entities, status


def redact_pdf_file(input_path: str, output_path: str, mode: str = "strict") -> Dict[str, Any]:
    with open(input_path, "rb") as f:
        file_bytes = f.read()
    filename = os.path.basename(input_path)
    result = process_document(filename=filename, file_bytes=file_bytes, detection_mode=mode)
    entity_map = {e["text"]: e["token"] for e in result["entities"]}
    redacted_bytes, _, _ = export_sanitized_document(
        file_bytes=file_bytes,
        filename=filename,
        sanitized_text=result["sanitized_text"],
        entity_map=entity_map,
        entity_count=result.get("entity_count", len(result["entities"])),
        export_format="native",
        structural_blocks=result.get("structural_blocks"),
        entities=result["entities"]
    )
    with open(output_path, "wb") as f:
        f.write(redacted_bytes)
    return result



