"""Data model shared by all formats."""
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Unit:
    """One block of detectable text (a PDF page, a slide, a chunk of paragraphs, one image)."""
    uid: str                      # human-readable id used in the log, e.g. "p3", "slide2", "img:/word/media/image1.png"
    text: str                     # plain text sent to the detectors
    ctx: Any = None               # format-private data used later to apply the redaction
    review: list = field(default_factory=list)   # regions OCR could not read (format coordinates)
    spans: list = field(default_factory=list)    # raw detections
    seeds: set = field(default_factory=set)
    ner: list = field(default_factory=list)
    final: list = field(default_factory=list)    # merged detections
    keep: list = field(default_factory=list)     # detections approved for redaction
