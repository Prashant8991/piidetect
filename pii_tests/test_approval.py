"""Tests for interactive approval of detected PII."""
import os
import sys
import unittest
from unittest.mock import call, patch
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pii_redactor.pipeline import approve


def detection(text, value):
    start = text.index(value)
    return {"start": start, "end": start + len(value), "entity_type": "PERSON", "score": 0.99}


class ApproveTest(unittest.TestCase):
    @patch("builtins.input", side_effect=["y", "n"])
    def test_prompts_for_each_unique_value_and_reuses_answers(self, mock_input):
        text1 = "Jane Doe met JANE   DOE."
        text2 = "Jane Doe met John Smith."
        units = [
            SimpleNamespace(
                uid="p1",
                text=text1,
                final=[detection(text1, "Jane Doe"), detection(text1, "JANE   DOE")],
            ),
            SimpleNamespace(
                uid="p2",
                text=text2,
                final=[detection(text2, "Jane Doe"), detection(text2, "John Smith")],
            ),
        ]

        approve(units)

        self.assertEqual(mock_input.call_count, 2)
        self.assertEqual(len(units[0].keep), 2)
        self.assertEqual(len(units[1].keep), 1)
        self.assertEqual(units[1].keep[0]["start"], detection(text2, "Jane Doe")["start"])

    @patch("builtins.input", return_value="n")
    def test_prompts_even_for_high_confidence_detection(self, mock_input):
        text = "alex@example.com"
        unit = SimpleNamespace(
            uid="p1",
            text=text,
            final=[{
                "start": 0,
                "end": len(text),
                "entity_type": "EMAIL",
                "score": 1.0,
            }],
        )

        approve([unit])

        mock_input.assert_called_once()
        self.assertEqual(unit.keep, [])


if __name__ == "__main__":
    unittest.main()
