"""Tests for conservative document-wide person-name propagation."""
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pii_redactor.detect import detect_all, detect_text
from pii_redactor.names import is_common_word, registry_from_seeds, registry_spans


class NameRegistryTest(unittest.TestCase):
    @patch("pii_redactor.detect.get_analyzer")
    def test_only_labelled_rule_names_seed_the_registry(self, mock_get_analyzer):
        mock_get_analyzer.return_value.analyze.return_value = []
        _, seeds, _ = detect_text(
            "Dr. Siddharth Gaikwad. Owner: Nikhil Karkera."
        )

        self.assertEqual(seeds, {"Nikhil Karkera"})

    def test_common_words_are_not_registered_or_fuzzy_matched(self):
        names = registry_from_seeds({"Final Workflows", "Siddharth Gaikwad"})

        self.assertTrue(is_common_word("final"))
        self.assertNotIn("final", names)
        self.assertNotIn("workflows", names)
        self.assertIn("siddharth", names)
        self.assertIn("gaikwad", names)
        self.assertEqual(registry_spans("Final Workflows", names), [])

    @patch("pii_redactor.detect.detect_text")
    def test_ner_only_repetitions_do_not_seed_the_registry(self, mock_detect_text):
        text = "Final Workflows. Final Workflows."
        mock_detect_text.return_value = (
            [{"start": 0, "end": 15, "entity_type": "PERSON", "score": 0.55, "src": "ner"}],
            set(),
            ["Final Workflows", "Final Workflows"],
        )
        unit = SimpleNamespace(text=text)

        names = detect_all([unit])

        self.assertEqual(names, set())
        self.assertEqual(len(unit.final), 1)
        self.assertEqual(unit.final[0]["src"], "ner")


if __name__ == "__main__":
    unittest.main()
