"""Command line: python -m pii_redactor <file> [options]"""
import argparse

from .pipeline import run


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pii_redactor", description="Detect and redact PII in PDF, DOCX and PPTX files.")
    ap.add_argument("file")
    ap.add_argument("-o", "--output", help="output path (default: redacted_<name>.<ext>)")
    ap.add_argument("--log", default="pii_logs.txt")
    ap.add_argument(
        "--review", action="store_true",
        help="deprecated; confirmation is now requested for every unique detected value",
    )
    ap.add_argument("--fail-closed", action="store_true", help="black out regions OCR could not read")
    ap.add_argument("--cache", action="store_true", help="cache PDF OCR results in .ocr_cache (faster reruns)")
    ap.add_argument("--verify", dest="verify", action="store_true", default=None, help="force the post-redaction leak check")
    ap.add_argument("--no-verify", dest="verify", action="store_false", help="skip the leak check")
    ap.add_argument("--workers", type=int, default=None)
    a = ap.parse_args(argv)
    run(a.file, a.output, a.log, a.review, a.fail_closed, a.cache, a.verify, a.workers)
