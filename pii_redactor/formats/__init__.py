"""File-format handlers. Add a new format by subclassing Handler and listing it here."""
import os

from .docx import DocxHandler
from .pdf import PdfHandler
from .pptx import PptxHandler

HANDLERS = [PdfHandler, DocxHandler, PptxHandler]


def get_handler(path):
    ext = os.path.splitext(path)[1].lower()
    for h in HANDLERS:
        if ext in h.exts:
            return h
    raise SystemExit(f"Unsupported file type '{ext}'. Supported: " + ", ".join(e for h in HANDLERS for e in h.exts))
