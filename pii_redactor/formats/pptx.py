"""PowerPoint (.pptx): slides, tables, notes, layouts/masters, charts, SmartArt, comments, images, metadata."""
import re

import pptx

from .office_xml import OfficeHandler


class PptxHandler(OfficeHandler):
    exts = (".pptx",)
    TEXT_PART_RX = re.compile(
        r"^/ppt/(slides/slide\d+|notesSlides/notesSlide\d+|slideLayouts/slideLayout\d+|slideMasters/slideMaster\d+"
        r"|charts/chart\d*|diagrams/(data|drawing)\d*|comments/[\w\-]+)\.xml$")
    SCRUB_PART_RX = re.compile(r"^/ppt/commentAuthors\.xml$")

    def _open(self):
        return pptx.Presentation(self.path)

    def _package(self):
        return self.doc.part.package
