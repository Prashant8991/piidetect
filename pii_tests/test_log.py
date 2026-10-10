"""Tests for privacy-safe PII logging."""
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pii_redactor.pipeline import write_log


class WriteLogTest(unittest.TestCase):
    def test_logs_detections_without_document_text(self):
        document_text = "Private report text for Alex Example. PII: alex@example.com."
        unit = SimpleNamespace(
            uid="p1",
            text=document_text,
            keep=[{
                "start": document_text.index("alex@example.com"),
                "end": len(document_text) - 1,
                "entity_type": "EMAIL",
                "score": 0.99,
                "src": "regex",
            }],
        )
        handler = SimpleNamespace(warnings=[])

        with tempfile.TemporaryDirectory() as directory:
            log_path = os.path.join(directory, "pii_logs.txt")
            write_log([unit], handler, log_path)
            with open(log_path, encoding="utf-8") as log:
                contents = log.read()

        self.assertIn("alex@example.com", contents)
        self.assertNotIn("Private report text", contents)
        self.assertNotIn("Alex Example", contents)
        self.assertNotIn("--- ORIGINAL ---", contents)
        self.assertNotIn("--- REDACTED ---", contents)


if __name__ == "__main__":
    unittest.main()
