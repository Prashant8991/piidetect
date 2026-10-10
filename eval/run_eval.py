"""
Optiv Consulting - Cadence AI Privacy Shield
Comprehensive Evaluation Benchmark Harness
Evaluates DEV, TEST, FRESH TEST generalization splits and Cadence case fixtures.
Computes Precision, Recall, F1 across Entity Types, Formats, Document Types,
High-Severity subsets, Contextual vs. Standalone Names, Look-alike False Positive Rates,
and Fail-Closed Verification Status.
"""

import os
import sys
import json
import re
from typing import Dict, List, Any, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import engine

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL_DIR = os.path.join(BASE_DIR, "eval")
GEN_DATA_DIR = os.path.join(EVAL_DIR, "generalization", "data")
GT_DIR = os.path.join(EVAL_DIR, "ground_truth")

HIGH_SEVERITY_TYPES = {
    "PERSON_NAME", "SSN", "GOVERNMENT_ID", "PAN_GOV_ID", "AADHAAR_GOV_ID",
    "PESEL_GOV_ID", "PASSPORT", "IBAN", "CREDIT_CARD", "BANK_ROUTING_CODE",
    "EMAIL", "PHONE_NUMBER", "DOB", "ADDRESS", "CUSTOM_ID"
}

CADENCE_FIXTURES = [
    {
        "filename": "Cadence_Financial_Group_Organizational_Pack.pptx",
        "gt_json": "Cadence_Financial_Group_Organizational_Pack.json",
        "format": "PPTX",
        "doc_type": "Org Chart / Pack"
    },
    {
        "filename": "Cadence_TPRM_Training.docx",
        "gt_json": "Cadence_TPRM_Training.json",
        "format": "DOCX",
        "doc_type": "Training Guide"
    },
    {
        "filename": "Cadence_Group_Risk_Management_Policy__v6.0.pdf",
        "gt_json": "Cadence_Group_Risk_Management_Policy__v6.0.json",
        "format": "PDF",
        "doc_type": "Policy Document",
        "max_pages": 5
    }
]


def normalize_val(val: str) -> str:
    """Normalizes string for robust substring matching in evaluation."""
    v = val.lower().strip()
    v = re.sub(r'[\s\-_.:,;()\[\]/]+', '', v)
    return v


def evaluate_split(split_name: str, split_dir: str, mode: str = "strict") -> Dict[str, Any]:
    if not os.path.exists(split_dir):
        return {"error": f"Directory not found: {split_dir}"}

    manifest_file = os.path.join(split_dir, "manifest.json")
    if not os.path.exists(manifest_file):
        return {"error": f"Manifest not found in {split_dir}"}

    with open(manifest_file, "r", encoding="utf-8") as f:
        docs = json.load(f)

    # Accumulators
    by_entity_type = {}
    by_format = {}
    by_doc_type = {}
    by_source = {"native": {"gt": 0, "tp": 0, "det": 0}, "ocr": {"gt": 0, "tp": 0, "det": 0}}
    
    high_sev_stats = {"gt": 0, "tp": 0, "det": 0}
    other_sev_stats = {"gt": 0, "tp": 0, "det": 0}
    
    names_with_context = {"gt": 0, "tp": 0}
    names_without_context = {"gt": 0, "tp": 0}

    total_must_not_redact = 0
    fp_must_not_redact = 0

    blocked_files = 0
    total_residuals = 0
    missed_items = []
    false_positives = []

    for doc_meta in docs:
        filename = doc_meta["filename"]
        file_path = os.path.join(split_dir, filename)
        gt_file = os.path.join(split_dir, f"{filename}.json")

        if not os.path.exists(file_path) or not os.path.exists(gt_file):
            continue

        with open(file_path, "rb") as f:
            file_bytes = f.read()

        with open(gt_file, "r", encoding="utf-8") as f:
            gt_data = json.load(f)

        fmt = gt_data.get("format", "TXT")
        source = gt_data.get("source", "native")
        doc_type = filename.replace(".pdf", "").replace(".docx", "").replace(".pptx", "").replace(".txt", "").replace(".csv", "").replace("_", " ").title()

        if fmt not in by_format:
            by_format[fmt] = {"gt": 0, "tp": 0, "det": 0}
        if doc_type not in by_doc_type:
            by_doc_type[doc_type] = {"gt": 0, "tp": 0, "det": 0}

        # Process document
        res = engine.process_document(filename=filename, file_bytes=file_bytes, detection_mode=mode)
        detected = res["entities"]
        
        if res.get("verification_status") == "BLOCKED":
            blocked_files += 1

        # Check verifier residual count from sanitized text
        v_status, v_res = engine.verify_sanitized_output(res["sanitized_text"], res["entities"])
        total_residuals += len(v_res)

        det_norms = [normalize_val(d["text"]) for d in detected]

        # Evaluate Ground Truth Entities
        for g in gt_data.get("entities", []):
            g_text = g["text"]
            etype = g["entity"]
            has_ctx = g.get("has_context", True)
            g_norm = normalize_val(g_text)

            is_high_sev = (etype in HIGH_SEVERITY_TYPES)

            # Global & Type tracking
            if etype not in by_entity_type:
                by_entity_type[etype] = {"gt": 0, "tp": 0, "det": 0}
            by_entity_type[etype]["gt"] += 1
            by_format[fmt]["gt"] += 1
            by_doc_type[doc_type]["gt"] += 1
            by_source[source]["gt"] += 1

            if is_high_sev:
                high_sev_stats["gt"] += 1
            else:
                other_sev_stats["gt"] += 1

            if etype == "PERSON_NAME":
                if has_ctx:
                    names_with_context["gt"] += 1
                else:
                    names_without_context["gt"] += 1

            # Match against detections
            matched = any(g_norm in dn or dn in g_norm for dn in det_norms)
            if matched:
                by_entity_type[etype]["tp"] += 1
                by_format[fmt]["tp"] += 1
                by_doc_type[doc_type]["tp"] += 1
                by_source[source]["tp"] += 1

                if is_high_sev:
                    high_sev_stats["tp"] += 1
                else:
                    other_sev_stats["tp"] += 1

                if etype == "PERSON_NAME":
                    if has_ctx:
                        names_with_context["tp"] += 1
                    else:
                        names_without_context["tp"] += 1
            else:
                missed_items.append({
                    "file": filename,
                    "entity": etype,
                    "text": g_text,
                    "has_context": has_ctx,
                    "format": fmt,
                    "source": source
                })

        # Track total detected counts
        for d in detected:
            dtype = d["type"]
            if dtype not in by_entity_type:
                by_entity_type[dtype] = {"gt": 0, "tp": 0, "det": 0}
            by_entity_type[dtype]["det"] += 1
            by_format[fmt]["det"] += 1
            by_doc_type[doc_type]["det"] += 1
            by_source[source]["det"] += 1

            if dtype in HIGH_SEVERITY_TYPES:
                high_sev_stats["det"] += 1
            else:
                other_sev_stats["det"] += 1

        # Evaluate "Must Not Redact" Look-alikes
        for item in gt_data.get("must_not_redact", []):
            total_must_not_redact += 1
            i_norm = normalize_val(item)
            if any(i_norm in dn or dn in i_norm for dn in det_norms):
                fp_must_not_redact += 1
                false_positives.append({
                    "file": filename,
                    "item": item,
                    "format": fmt
                })

    return {
        "split": split_name,
        "total_docs": len(docs),
        "by_entity_type": by_entity_type,
        "by_format": by_format,
        "by_doc_type": by_doc_type,
        "by_source": by_source,
        "high_sev_stats": high_sev_stats,
        "other_sev_stats": other_sev_stats,
        "names_with_context": names_with_context,
        "names_without_context": names_without_context,
        "total_must_not_redact": total_must_not_redact,
        "fp_must_not_redact": fp_must_not_redact,
        "blocked_files": blocked_files,
        "total_residuals": total_residuals,
        "missed_items": missed_items,
        "false_positives": false_positives
    }


def evaluate_cadence_fixtures() -> Dict[str, Any]:
    stats = {"gt": 0, "tp": 0, "det": 0, "residuals": 0, "blocked": 0, "files": []}
    
    for c in CADENCE_FIXTURES:
        filename = c["filename"]
        file_path = os.path.join(BASE_DIR, filename)
        if not os.path.exists(file_path):
            file_path = os.path.join(BASE_DIR, "data", "samples", filename)

        gt_path = os.path.join(GT_DIR, c["gt_json"])
        if not os.path.exists(file_path) or not os.path.exists(gt_path):
            continue

        with open(file_path, "rb") as f:
            file_bytes = f.read()
        with open(gt_path, "r", encoding="utf-8") as f:
            gt_data = json.load(f)

        max_p = c.get("max_pages", None)
        res = engine.process_document(filename=filename, file_bytes=file_bytes, max_pdf_pages=max_p)
        detected = res["entities"]
        det_norms = [normalize_val(d["text"]) for d in detected]

        tp_count = 0
        for g in gt_data:
            g_norm = normalize_val(g["text"])
            if any(g_norm in dn or dn in g_norm for dn in det_norms):
                tp_count += 1

        stats["gt"] += len(gt_data)
        stats["tp"] += tp_count
        stats["det"] += len(detected)
        
        if res.get("verification_status") == "BLOCKED":
            stats["blocked"] += 1

        v_status, v_res = engine.verify_sanitized_output(res["sanitized_text"], res["entities"])
        stats["residuals"] += len(v_res)

        rec = (tp_count / max(len(gt_data), 1)) * 100.0
        prec = (tp_count / max(len(detected), 1)) * 100.0 if detected else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

        stats["files"].append({
            "filename": filename,
            "format": c["format"],
            "gt": len(gt_data),
            "tp": tp_count,
            "det": len(detected),
            "rec": rec,
            "prec": prec,
            "f1": f1,
            "status": res.get("verification_status")
        })

    return stats


def compute_metrics(tp: int, gt: int, det: int) -> Tuple[float, float, float]:
    rec = (tp / max(gt, 1)) * 100.0
    prec = (tp / max(det, 1)) * 100.0 if det else 0.0
    f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    return round(prec, 1), round(rec, 1), round(f1, 1)


def format_table(headers: List[str], rows: List[List[Any]]) -> str:
    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(str(cell)))

    header_line = "| " + " | ".join(f"{h:<{col_widths[i]}}" for i, h in enumerate(headers)) + " |"
    sep_line = "| " + " | ".join("-" * col_widths[i] for i in range(len(headers))) + " |"
    row_lines = [
        "| " + " | ".join(f"{str(cell):<{col_widths[i]}}" for i, cell in enumerate(row)) + " |"
        for row in rows
    ]
    return "\n".join([header_line, sep_line] + row_lines)


def run_comprehensive_eval():
    print("=" * 80)
    print("CADENCE PII SHIELD: RIGOROUS EVALUATION BENCHMARK")
    print("Generalization Test Suite across DEV, TEST, FRESH TEST and Cadence Fixtures")
    print("=" * 80 + "\n")

    dev_res = evaluate_split("DEV (Seed 42)", os.path.join(GEN_DATA_DIR, "dev"))
    test_res = evaluate_split("TEST Held-Out (Seed 1337)", os.path.join(GEN_DATA_DIR, "test"))
    fresh_res = evaluate_split("FRESH TEST (Seed 9999)", os.path.join(GEN_DATA_DIR, "fresh_test"))
    fixtures_res = evaluate_cadence_fixtures()

    # Table 1: Overall Generalization Summary (DEV vs TEST vs FRESH TEST)
    t1_headers = ["Split", "Docs", "High-Sev Rec (%)", "Overall Rec (%)", "Overall Prec (%)", "Overall F1 (%)", "FP Lookalikes", "Blocked Files"]
    t1_rows = []
    for r in [dev_res, test_res, fresh_res]:
        tp_tot = sum(v["tp"] for v in r["by_entity_type"].values())
        gt_tot = sum(v["gt"] for v in r["by_entity_type"].values())
        det_tot = sum(v["det"] for v in r["by_entity_type"].values())
        p, rec, f1 = compute_metrics(tp_tot, gt_tot, det_tot)
        
        h_tp = r["high_sev_stats"]["tp"]
        h_gt = r["high_sev_stats"]["gt"]
        h_rec = round((h_tp / max(h_gt, 1)) * 100.0, 1)

        fp_rate = f"{r['fp_must_not_redact']}/{r['total_must_not_redact']} ({(r['fp_must_not_redact']/max(r['total_must_not_redact'],1))*100:.1f}%)"
        t1_rows.append([
            r["split"], r["total_docs"], f"{h_rec}%", f"{rec}%", f"{p}%", f"{f1}%", fp_rate, f"{r['blocked_files']}/{r['total_docs']}"
        ])

    print("### TABLE 1: OVERALL GENERALIZATION ACROSS SPLITS")
    print(format_table(t1_headers, t1_rows) + "\n\n")

    # Table 2: Name Detection Breakdown (With Context vs Standalone Without Context)
    t2_headers = ["Split", "Names With Cues (Rec %)", "Names Without Cues (Rec %)", "Total Names GT", "Names TP"]
    t2_rows = []
    for r in [dev_res, test_res, fresh_res]:
        c_tp, c_gt = r["names_with_context"]["tp"], r["names_with_context"]["gt"]
        s_tp, s_gt = r["names_without_context"]["tp"], r["names_without_context"]["gt"]
        c_rec = round((c_tp / max(c_gt, 1)) * 100.0, 1)
        s_rec = round((s_tp / max(s_gt, 1)) * 100.0, 1)
        t2_rows.append([
            r["split"], f"{c_tp}/{c_gt} ({c_rec}%)", f"{s_tp}/{s_gt} ({s_rec}%)", c_gt + s_gt, c_tp + s_tp
        ])
    print("### TABLE 2: NAME RECALL WITH VS. WITHOUT CONTEXTUAL CUES")
    print(format_table(t2_headers, t2_rows) + "\n\n")

    # Table 3: Breakdown by Entity Type on Held-Out TEST (Seed 1337)
    t3_headers = ["Entity Type", "Category", "GT", "TP", "Detected", "Recall (%)", "Precision (%)", "F1 (%)"]
    t3_rows = []
    for etype, data in sorted(test_res["by_entity_type"].items()):
        category = "High Severity" if etype in HIGH_SEVERITY_TYPES else "General"
        p, rec, f1 = compute_metrics(data["tp"], data["gt"], data["det"])
        t3_rows.append([etype, category, data["gt"], data["tp"], data["det"], f"{rec}%", f"{p}%", f"{f1}%"])
    print("### TABLE 3: HELD-OUT TEST (SEED 1337) - PERFORMANCE BY ENTITY TYPE")
    print(format_table(t3_headers, t3_rows) + "\n\n")

    # Table 4: Breakdown by Document Format and Ingestion Source (Native vs. Scanned OCR)
    t4_headers = ["Slice / Dimension", "Value", "GT", "TP", "Detected", "Recall (%)", "Precision (%)", "F1 (%)"]
    t4_rows = []
    for fmt, data in sorted(test_res["by_format"].items()):
        p, rec, f1 = compute_metrics(data["tp"], data["gt"], data["det"])
        t4_rows.append(["Format", fmt, data["gt"], data["tp"], data["det"], f"{rec}%", f"{p}%", f"{f1}%"])
    for src, data in sorted(test_res["by_source"].items()):
        p, rec, f1 = compute_metrics(data["tp"], data["gt"], data["det"])
        t4_rows.append(["Ingestion Source", src.upper(), data["gt"], data["tp"], data["det"], f"{rec}%", f"{p}%", f"{f1}%"])
    print("### TABLE 4: HELD-OUT TEST (SEED 1337) - BY FORMAT & SOURCE")
    print(format_table(t4_headers, t4_rows) + "\n\n")

    # Table 5: Cadence Case Study Sample Fixtures
    t5_headers = ["Fixture Document", "Format", "GT Annotations", "TP", "Detected", "Recall (%)", "Precision (%)", "Verification Status"]
    t5_rows = []
    for f in fixtures_res["files"]:
        t5_rows.append([
            f["filename"], f["format"], f["gt"], f["tp"], f["det"], f"{f['rec']:.1f}%", f"{f['prec']:.1f}%", f["status"]
        ])
    print("### TABLE 5: CADENCE CASE STUDY FIXTURES PERFORMANCE")
    print(format_table(t5_headers, t5_rows) + "\n\n")

    # Table 6: Error Analysis & Remaining Gaps (Held-out TEST)
    print("### REMAINING MISSES AND FALSE POSITIVES (HELD-OUT TEST)")
    if test_res["missed_items"]:
        print(f"Total Misses: {len(test_res['missed_items'])}")
        for m in test_res["missed_items"]:
            print(f"- [MISS] {m['file']} ({m['format']}/{m['source']}): '{m['text']}' ({m['entity']}) - Context Cue: {m['has_context']}")
    else:
        print("Zero misses on held-out TEST set.")

    if test_res["false_positives"]:
        print(f"\nTotal False Positives on Look-alikes: {len(test_res['false_positives'])}")
        for fp in test_res["false_positives"]:
            print(f"- [FP] {fp['file']} ({fp['format']}): '{fp['item']}'")
    else:
        print("Zero false positives on look-alike non-PII.")

    print("\n" + "=" * 80)
    print("BENCHMARK COMPLETE")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_comprehensive_eval()
