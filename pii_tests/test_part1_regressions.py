"""
Regression tests for Part 1 symptoms:
- Half-redacted names
- Merged-word OCR names (camel-case normalization)
- Fictional 555 mobile numbers
- Country code (+1, +33) prefixes included in phone token spans
- Corporate role and department titles preserved (not tokenized as PERSON_NAME)
- Broken token fragments eliminated
- Cross-file stable tokens for the same individual
- Strict fail-closed verifier returns BLOCKED on residuals and PASSED on clean text
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import engine


class Part1RegressionTests(unittest.TestCase):

    def test_half_redacted_names_propagated(self):
        """When a full name appears once, single surname occurrences are also redacted with the same stable token."""
        text = "Meeting chaired by Rosalind Featherstone. Later, Featherstone presented the risk report."
        entities = engine.detect_pii_entities(text)
        sanitized, entity_map, _ = engine.redact_and_sanitize(text, entities)

        # Neither 'Rosalind' nor 'Featherstone' should be visible in the sanitized text
        self.assertNotIn("Rosalind", sanitized)
        self.assertNotIn("Featherstone", sanitized)

        # Both references should resolve to the same person token
        person_tokens = [tok for orig, tok in entity_map.items() if "PERSON_NAME" in tok]
        self.assertGreaterEqual(len(person_tokens), 1)
        self.assertEqual(len(set(person_tokens)), 1, "Full name and surname must share identical stable token")

    def test_merged_word_ocr_normalization(self):
        """RapidOCR normalization separates camel-case words without spaces."""
        merged_sample = "Reviewed by HelenaVorstermann and MiriamT. Achebe from CadenceFinancial Group,Inc."
        normalized = engine.normalize_ocr_line(merged_sample)

        self.assertIn("Helena Vorstermann", normalized)
        self.assertIn("Miriam T. Achebe", normalized)

        # Verify detector catches the normalized names
        entities = engine.detect_pii_entities(normalized)
        detected_names = [e["text"] for e in entities if e["type"] == "PERSON_NAME"]
        self.assertTrue(any("Vorstermann" in n for n in detected_names))
        self.assertTrue(any("Achebe" in n for n in detected_names))

    def test_fictional_555_phone_numbers(self):
        """Fictional 555 phone numbers are detected across international and domestic formats."""
        sample_phones = [
            "Call +1 (555) 0145 for support",
            "Direct: (555) 0192",
            "Tel: +33 1 55 55 01 44",
            "Mobile: +1-555-0123"
        ]
        for phone_text in sample_phones:
            entities = engine.detect_pii_entities(phone_text)
            phone_entities = [e for e in entities if e["type"] == "PHONE_NUMBER"]
            self.assertGreaterEqual(len(phone_entities), 1, f"Failed to detect phone in: '{phone_text}'")

    def test_country_code_prefix_included_in_phone_span(self):
        """The +1 or +33 prefix must be inside the phone span, not left dangling outside."""
        text = "Contact desk at +1 (555) 0184 immediately."
        entities = engine.detect_pii_entities(text)
        phone_ent = next(e for e in entities if e["type"] == "PHONE_NUMBER")

        self.assertTrue(phone_ent["text"].startswith("+1"), f"Phone span text was '{phone_ent['text']}', expected '+1' prefix")

        sanitized, _, _ = engine.redact_and_sanitize(text, entities)
        self.assertNotIn("+1 [PHONE_NUMBER", sanitized)
        self.assertNotIn("+1[PHONE_NUMBER", sanitized)

    def test_role_titles_with_department_words_not_tokenized(self):
        """Corporate roles and department titles must NOT be falsely tokenized as people."""
        corporate_titles = [
            "VP, Information Security",
            "VP, Operational Risk",
            "Chief Information Officer",
            "Business Owner",
            "Technology & Data",
            "People & Culture",
            "Internal Assurance",
            "Third-Party Risk"
        ]
        for title in corporate_titles:
            self.assertTrue(
                engine.is_role_or_department(title),
                f"Expected '{title}' to be recognized as role/department false-positive"
            )
            entities = engine.detect_pii_entities(f"Responsible party: {title}")
            person_entities = [e for e in entities if e["type"] == "PERSON_NAME" and e["text"] == title]
            self.assertEqual(len(person_entities), 0, f"Role '{title}' was falsely tokenized as PERSON_NAME")

    def test_broken_token_fragments_eliminated(self):
        """Overlapping spans must be resolved so no broken residue (e.g. ID_xxx]) remains."""
        # Synthetic overlapping scenario: email and local part
        text = "Audit contact: rosalind.featherstone@cadencefg.com (EMP-40522)"
        entities = engine.detect_pii_entities(text)
        sanitized, _, _ = engine.redact_and_sanitize(text, entities)

        # Check for any broken token fragment residues
        self.assertNotIn("]ID_", sanitized)
        self.assertNotIn("]EMP_", sanitized)
        self.assertFalse(bool(engine.re.search(r'\bID_[a-f0-9]{4,10}\]', sanitized)))

        # Fail-closed verifier should find 0 token fragments
        status, residuals = engine.verify_sanitized_output(sanitized, pass1_entities=entities)
        frag_residuals = [r for r in residuals if r["type"] == "TOKEN_FRAGMENT"]
        self.assertEqual(len(frag_residuals), 0)

    def test_cross_file_stable_tokens(self):
        """The same individual receives identical tokens across PPTX, DOCX, and PDF."""
        tok_full = engine.generate_stable_token("PERSON_NAME", "Anthony P. Brightwell")
        tok_initial = engine.generate_stable_token("PERSON_NAME", "A. Brightwell")
        tok_surname = engine.generate_stable_token("PERSON_NAME", "Brightwell")

        self.assertEqual(tok_full, tok_initial, "Full name and initial must match")
        self.assertEqual(tok_full, tok_surname, "Full name and surname must match")

        tok_achebe_full = engine.generate_stable_token("PERSON_NAME", "Miriam T. Achebe")
        tok_achebe_last = engine.generate_stable_token("PERSON_NAME", "Achebe")
        self.assertEqual(tok_achebe_full, tok_achebe_last)

    def test_fail_closed_verifier_catches_residual(self):
        """Verifier returns BLOCKED when any residual name or phone is deliberately left."""
        clean_text = "Policy overview: Approved by [PERSON_NAME_7a689a]. Contact: [PHONE_NUMBER_160ad0]."
        status_clean, residuals_clean = engine.verify_sanitized_output(clean_text)
        self.assertEqual(status_clean, "PASSED")
        self.assertEqual(len(residuals_clean), 0)

        # Deliberately inject a leaked phone number
        leaked_phone = clean_text + " Emergency mobile: +1 (555) 0199" # Not hotline
        status_phone_leak, residuals_phone = engine.verify_sanitized_output(leaked_phone)
        # Note: 555-0199 is allowlisted hotline, let's use 555-0145
        leaked_phone_real = clean_text + " Mobile: +1 (555) 0145"
        status_leak, residuals_leak = engine.verify_sanitized_output(leaked_phone_real)
        self.assertEqual(status_leak, "BLOCKED")
        self.assertGreaterEqual(len(residuals_leak), 1)

        # Deliberately inject a leaked person name matching pass-1 entities
        pass1 = [{"text": "Rosalind Featherstone", "type": "PERSON_NAME", "value_hash": "abc1234567"}]
        leaked_name = clean_text + " Author: Rosalind Featherstone"
        status_name_leak, residuals_name = engine.verify_sanitized_output(leaked_name, pass1_entities=pass1)
        self.assertEqual(status_name_leak, "BLOCKED")


if __name__ == "__main__":
    unittest.main()
