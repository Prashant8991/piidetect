"""Word (.docx): body, tables, text boxes, headers/footers, footnotes, comments, charts, images, metadata."""
import re

import docx

from .office_xml import OfficeHandler


class DocxHandler(OfficeHandler):
    exts = (".docx",)
    TEXT_PART_RX = re.compile(
        r"^/word/(document|header\d*|footer\d*|footnotes|endnotes|comments|charts/chart\d*|diagrams/(data|drawing)\d*)\.xml$")
    SCRUB_PART_RX = None

    def _open(self):
        return docx.Document(self.path)
