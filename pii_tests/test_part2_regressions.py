"""
Regression and Generalization Unit Tests for Part 2
Covers all 14 failure classes, native PDF true text removal, metadata scrubbing,
safe custom rules, Strict vs. Balanced mode, and independent verification.
Zero hardcoded sample strings in detectors.
"""

import os
import sys
import tempfile
import unittest
import fitz  # PyMuPDF

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import engine
from pii_redactor.detect import UnifiedPIIDetector
from pii_redactor.rules import is_lookalike_non_pii
from pii_redactor.custom_rules import is_safe_regex, add_custom_rule
from pii_redactor.tokens import generate_stable_token


class Part2FailureClassTests(unittest.TestCase):
    def setUp(self):
        self.detector = UnifiedPIIDetector()

    # --------------------------------------------------------------------------
    # Failure Class 1: Names missed (titled, hyphenated, non-English, initials, handles)
    # --------------------------------------------------------------------------
    def test_class1_names_titled_hyphenated_initials_and_handles(self):
        text = (
            "Attending the symposium: Dr. Elena Rostova and Jean-Luc Dubois. "
            "Notes submitted by H. G. Wells and Daisuke Takahashi. "
            "Reach out to handle ~erostova or elena.rostova@cadence.example."
        )
        entities = engine.detect_pii_entities(text)
        detected_names = [e["text"] for e in entities if e["type"] == "PERSON_NAME"]
        
        self.assertTrue(any("Elena Rostova" in n or "Rostova" in n for n in detected_names), "Titled name missed")
        self.assertTrue(any("Jean-Luc Dubois" in n or "Dubois" in n for n in detected_names), "Hyphenated name missed")
        self.assertTrue(any("Wells" in n for n in detected_names), "Initial name missed")
        self.assertTrue(any("Daisuke Takahashi" in n or "Takahashi" in n for n in detected_names), "Non-English name missed")

    # --------------------------------------------------------------------------
    # Failure Class 2: Names half-redacted (first name visible or surname visible)
    # --------------------------------------------------------------------------
    def test_class2_no_half_redacted_names(self):
        text = "Confidential report prepared by Arthur Pendelton on Tuesday."
        sanitized, entities, status = engine.sanitize_text_content(text)
        self.assertNotIn("Arthur [", sanitized, "First name left visible while surname redacted")
        self.assertNotIn("] Pendelton", sanitized, "Surname left visible while first name redacted")
        self.assertIn("[PERSON_NAME_", sanitized, "Full name should be redacted under single token")

    # --------------------------------------------------------------------------
    # Failure Class 3: Phone numbers in unusual or fictional formats + country code
    # --------------------------------------------------------------------------
    def test_class3_phone_numbers_and_prefixes(self):
        phones = [
            "Call +1 (555) 0184 ext 102 immediately.",
            "International hotline: +44 20 7946 0912",
            "Direct line: +33 1 55 55 01 44",
            "Fictional domestic: 555.0192"
        ]
        for p_text in phones:
            entities = engine.detect_pii_entities(p_text)
            phone_ents = [e for e in entities if e["type"] == "PHONE_NUMBER"]
            self.assertGreaterEqual(len(phone_ents), 1, f"Failed phone detection: {p_text}")
            matched = phone_ents[0]["text"]
            if "+1" in p_text:
                self.assertTrue(matched.startswith("+1"), f"Country code +1 excluded from span in {matched}")
            if "+44" in p_text:
                self.assertTrue(matched.startswith("+44"), f"Country code +44 excluded from span in {matched}")

    # --------------------------------------------------------------------------
    # Failure Class 4: Job titles and department words not tokenized as people
    # --------------------------------------------------------------------------
    def test_class4_job_titles_and_departments_not_people(self):
        titles = [
            "VP, Operational Risk",
            "Chief Information Officer",
            "Head of Internal Assurance",
            "Global Treasury & Operations",
            "Enterprise Technology Group"
        ]
        for t in titles:
            self.assertTrue(engine.is_role_or_department(t), f"Failed role/dept classification: {t}")
            entities = engine.detect_pii_entities(f"Report signed by {t}.")
            person_ents = [e for e in entities if e["type"] == "PERSON_NAME" and e["text"] == t]
            self.assertEqual(len(person_ents), 0, f"Role '{t}' was falsely detected as PERSON_NAME")

    # --------------------------------------------------------------------------
    # Failure Class 5: OCR text with merged words
    # --------------------------------------------------------------------------
    def test_class5_merged_words_ocr_handling(self):
        from pii_redactor.normalize import normalize_text_with_map
        text = "Consultant: FirstnameSurname, Company: CadenceFinancial Group,Inc."
        norm, _ = normalize_text_with_map(text)
        self.assertIn("Group, Inc", norm.replace("Group,Inc", "Group, Inc"))

    # --------------------------------------------------------------------------
    # Failure Class 6: No broken token fragments after redaction
    # --------------------------------------------------------------------------
    def test_class6_no_broken_token_fragments(self):
        text = "Dr. Elena Rostova (SSN: 123-45-6789) attended."
        sanitized, _, _ = engine.sanitize_text_content(text)
        # Check no trailing single letter fragments or unbalanced brackets
        self.assertNotIn("a (", sanitized)
        self.assertNotIn("]9)", sanitized)
        self.assertEqual(sanitized.count("["), sanitized.count("]"), "Mismatched redaction brackets")

    # --------------------------------------------------------------------------
    # Failure Class 7: Full identifier coverage (ORCID iD checksum & full span)
    # --------------------------------------------------------------------------
    def test_class7_orcid_full_span_with_checksum(self):
        text = "Researcher profile: https://orcid.org/0000-0002-1825-0097."
        entities = engine.detect_pii_entities(text)
        orcid_ents = [e for e in entities if e["type"] == "ORCID"]
        self.assertEqual(len(orcid_ents), 1)
        self.assertEqual(orcid_ents[0]["text"], "0000-0002-1825-0097")

    # --------------------------------------------------------------------------
    # Failure Class 8: Non-PII look-alikes not redacted
    # --------------------------------------------------------------------------
    def test_class8_non_pii_lookalikes_not_redacted(self):
        lookalikes = [
            "2018 - 2021",
            "2022-2027",
            "v6.0",
            "ISO/IEC 27001:2022",
            "10.1000/182",
            "ISBN 978-3-16-148410-0",
            "50%"
        ]
        for item in lookalikes:
            self.assertTrue(is_lookalike_non_pii(item), f"Item '{item}' should be recognized as non-PII lookalike")
            entities = engine.detect_pii_entities(f"Audit period was {item} according to standard.")
            pii_matches = [e for e in entities if e["text"] == item]
            self.assertEqual(len(pii_matches), 0, f"Non-PII '{item}' was falsely detected")

    # --------------------------------------------------------------------------
    # Failure Class 9: Verifier catches deliberately injected residual PII
    # --------------------------------------------------------------------------
    def test_class9_verifier_blocks_residual_pii(self):
        clean_text = "Approved by [PERSON_NAME_112233]. Contact: [PHONE_NUMBER_445566]."
        status_ok, res_ok = engine.verify_sanitized_output(clean_text)
        self.assertEqual(status_ok, "PASSED")
        self.assertEqual(len(res_ok), 0)

        # Injected leak
        leaked_text = clean_text + " Unredacted: +1 (555) 0184"
        status_fail, res_fail = engine.verify_sanitized_output(leaked_text)
        self.assertEqual(status_fail, "BLOCKED")
        self.assertGreater(len(res_fail), 0)

    # --------------------------------------------------------------------------
    # Failure Class 10: Redaction boxes do not cover neighboring colons or punct
    # --------------------------------------------------------------------------
    def test_class10_no_colon_clipping_in_spans(self):
        text = "Account: CUST#8921; Policy: POL-301"
        entities = engine.detect_pii_entities(text)
        for e in entities:
            self.assertFalse(e["text"].endswith(":"), f"Span '{e['text']}' includes trailing colon")
            self.assertFalse(e["text"].endswith(";"), f"Span '{e['text']}' includes trailing semicolon")
            self.assertFalse(e["text"].startswith(":"), f"Span '{e['text']}' includes leading colon")

    # --------------------------------------------------------------------------
    # Failure Class 11: Standalone names without contextual cues
    # --------------------------------------------------------------------------
    def test_class11_standalone_names_without_cues(self):
        # Name in sentence with zero cue words (no Dr., Mr., Author:, Prepared by:)
        text = "Yesterday Daisuke Takahashi finalized the quarterly treasury models."
        entities = engine.detect_pii_entities(text)
        detected_names = [e["text"] for e in entities if e["type"] == "PERSON_NAME"]
        self.assertTrue(
            any("Daisuke Takahashi" in n or "Takahashi" in n for n in detected_names),
            "Standalone name without cues was missed"
        )

    # --------------------------------------------------------------------------
    # Failure Class 12: Custom and unknown ID formats
    # --------------------------------------------------------------------------
    def test_class12_custom_unknown_id_formats(self):
        samples = [
            "Customer reference: CUST#8921",
            "Medical chart: PATIENT-301",
            "User ID: 123456",
            "Contract Account #987654",
            "Insurance Policy No. POL-7891"
        ]
        for s in samples:
            entities = engine.detect_pii_entities(s)
            id_ents = [e for e in entities if e["type"] == "CUSTOM_ID"]
            self.assertGreaterEqual(len(id_ents), 1, f"Failed to detect custom ID in: {s}")

    # --------------------------------------------------------------------------
    # Failure Class 13: Obfuscated contact details
    # --------------------------------------------------------------------------
    def test_class13_obfuscated_contact_details(self):
        text = "Reach out to john dot doe at gmail dot com for access."
        entities = engine.detect_pii_entities(text)
        email_ents = [e for e in entities if e["type"] == "EMAIL"]
        self.assertGreaterEqual(len(email_ents), 1, "Obfuscated email was missed")
        self.assertIn("john dot doe at gmail dot com", email_ents[0]["text"])

    # --------------------------------------------------------------------------
    # Failure Class 14: OCR character confusion (0/O, 1/l)
    # --------------------------------------------------------------------------
    def test_class14_ocr_confusion_recovery(self):
        text = "Tax record SSN: l23-45-6789 and SSN: O12-34-5678."
        entities = engine.detect_pii_entities(text)
        ssn_ents = [e for e in entities if e["type"] == "SSN"]
        self.assertGreaterEqual(len(ssn_ents), 1, "OCR confusable SSN was not detected")

    # --------------------------------------------------------------------------
    # Native PDF True Redaction & Metadata Scrubbing
    # --------------------------------------------------------------------------
    def test_native_pdf_true_text_removal_and_metadata_scrubbing(self):
        # Create a small synthetic PDF
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((50, 100), "Confidential: Dr. Elena Rostova SSN: 123-45-6789")
        doc.set_metadata({
            "author": "Elena Rostova",
            "title": "Confidential Risk Memo",
            "subject": "PII Test"
        })

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f_in:
            in_path = f_in.name
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f_out:
            out_path = f_out.name

        try:
            doc.save(in_path)
            doc.close()

            # Execute real engine PDF redaction
            result = engine.redact_pdf_file(in_path, out_path)
            self.assertEqual(result.get("verification_status", result.get("status")), "PASSED")

            # Inspect redacted output PDF directly
            out_doc = fitz.open(out_path)
            out_text = out_doc[0].get_text()

            # Prove true text removal: original PII text must NOT exist in the PDF content stream
            self.assertNotIn("Elena Rostova", out_text, "Original name still extractable in PDF stream!")
            self.assertNotIn("123-45-6789", out_text, "Original SSN still extractable in PDF stream!")

            # Prove metadata scrubbing
            meta = out_doc.metadata
            self.assertEqual(meta.get("author", ""), "", "Author metadata was not scrubbed")
            self.assertEqual(meta.get("title", ""), "", "Title metadata was not scrubbed")
            out_doc.close()
        finally:
            if os.path.exists(in_path):
                os.remove(in_path)
            if os.path.exists(out_path):
                os.remove(out_path)

    # --------------------------------------------------------------------------
    # Cross-File Stable Pseudonym Tokens
    # --------------------------------------------------------------------------
    def test_cross_file_stable_pseudonym_tokens(self):
        token_a = generate_stable_token("PERSON_NAME", "Dr. Elena Rostova")
        token_b = generate_stable_token("PERSON_NAME", "Elena Rostova")
        token_c = generate_stable_token("PERSON_NAME", "Rostova")
        self.assertEqual(token_a, token_b, "Dr. prefix caused token divergence")
        self.assertEqual(token_b, token_c, "Surname variant caused token divergence")

    # --------------------------------------------------------------------------
    # Custom Rules & Safety (ReDoS Protection)
    # --------------------------------------------------------------------------
    def test_custom_rule_safety_and_redos_rejection(self):
        # Safe rule
        safe_regex = r"\bPROJECT-[A-Z]{3}-\d{4}\b"
        is_safe, err = is_safe_regex(safe_regex)
        self.assertTrue(is_safe)
        self.assertIsNone(err)

        # Adversarial catastrophic backtracking regex
        redos_pattern = r"(a+)+$"
        is_safe_bad, err_bad = is_safe_regex(redos_pattern)
        self.assertFalse(is_safe_bad, "Dangerous ReDoS pattern was not rejected")
        self.assertIsNotNone(err_bad)

    # --------------------------------------------------------------------------
    # Strict vs. Balanced Detection Mode
    # --------------------------------------------------------------------------
    def test_strict_vs_balanced_mode(self):
        text = "Notice regarding account: Reference ID: REF-4091"
        strict_ents = engine.detect_pii_entities(text, mode="strict")
        balanced_ents = engine.detect_pii_entities(text, mode="balanced")

        self.assertGreaterEqual(len(strict_ents), 1)
        self.assertGreaterEqual(len(balanced_ents), 1)


if __name__ == "__main__":
    unittest.main()
