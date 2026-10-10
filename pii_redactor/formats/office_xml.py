"""Shared DOCX/PPTX engine.

Both formats are zipped XML. This module turns every paragraph into text, maps detections back to the exact
text runs (so formatting survives), OCRs + blanks embedded images, and scrubs metadata that leaks identity.
"""
import io
import re
from concurrent.futures import ProcessPoolExecutor

from lxml import etree
from PIL import Image, ImageDraw

from ..config import CHUNK_PARAS, IMG_DPI, MIN_IMG_PX, PAD
from ..models import Unit
from ..ocr import ocr_image
from ..textlayout import build_text, span_boxes
from .base import Handler

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
P = "http://schemas.openxmlformats.org/presentationml/2006/main"
C = "http://schemas.openxmlformats.org/drawingml/2006/chart"
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"

PARA_TAGS = {f"{{{W}}}p", f"{{{A}}}p"}
CELL_TAGS = {f"{{{W}}}tc", f"{{{A}}}tc"}
# tag -> None (editable text node) or a fixed character
TEXT_MAP = {f"{{{W}}}t": None, f"{{{W}}}delText": None, f"{{{A}}}t": None,
            f"{{{W}}}tab": "\t", f"{{{W}}}br": "\n", f"{{{W}}}cr": "\n", f"{{{A}}}br": "\n"}
EMAIL_RX = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
IMAGE_TYPES = {"image/png", "image/jpeg", "image/bmp", "image/tiff"}


# ---------------------------------------------------------------- paragraphs
class XmlPara:
    """A paragraph made of ordered nodes: ('T', element) = editable text, ('x', char) = fixed character."""

    def __init__(self, nodes, cell=None):
        self.nodes, self.cell = nodes, cell
        self.row = cell.getparent() if cell is not None else None
        self.text = "".join((o.text or "") if k == "T" else o for k, o in nodes)

    def redact(self, edits):
        """edits: [(start, end, replacement)] in paragraph coordinates. Formatting of surrounding runs is kept."""
        offs, pos = [], 0
        for k, o in self.nodes:
            n = len(o.text or "") if k == "T" else 1
            offs.append((pos, pos + n))
            pos += n
        for s, e, rep in sorted(edits, reverse=True):          # right-to-left keeps earlier offsets valid
            placed = False
            for (k, o), (ns, ne) in zip(self.nodes, offs):
                if k != "T" or ne <= s or ns >= e:
                    continue
                txt = o.text or ""
                o.text = txt[:max(s, ns) - ns] + ("" if placed else rep) + txt[min(e, ne) - ns:]
                if etree.QName(o).namespace == W:
                    o.set(XML_SPACE, "preserve")
                placed = True


class AttrPara:
    """An XML attribute treated as a paragraph (alt text of pictures)."""

    def __init__(self, el, attr):
        self.el, self.attr, self.cell, self.row = el, attr, None, None
        self.text = el.get(attr) or ""

    def redact(self, edits):
        t = self.text
        for s, e, rep in sorted(edits, reverse=True):
            t = t[:s] + rep + t[e:]
        self.el.set(self.attr, t)


def _collect(el, nodes):
    for ch in el:
        if not isinstance(ch.tag, str) or ch.tag in PARA_TAGS:
            continue                                         # nested paragraphs (text boxes) are handled on their own
        if ch.tag in TEXT_MAP:
            m = TEXT_MAP[ch.tag]
            nodes.append(("T", ch) if m is None else ("x", m))
        else:
            _collect(ch, nodes)


def paragraphs(root):
    out = []
    for p in root.iter(*PARA_TAGS):
        nodes = []
        _collect(p, nodes)
        if not any(k == "T" and o.text for k, o in nodes):
            continue
        cell = p.getparent()
        while cell is not None and cell.tag not in CELL_TAGS:
            cell = cell.getparent()
        out.append(XmlPara(nodes, cell))
    # single-element text: chart labels, legacy PowerPoint comments
    for el in root.iter(f"{{{C}}}v", f"{{{P}}}text"):
        par = el.getparent()
        if el.tag == f"{{{C}}}v" and etree.QName(par.getparent()).localname not in ("strCache", "strLit"):
            continue
        if el.text and el.text.strip():
            out.append(XmlPara([("T", el)]))
    # alt text
    for el in root.iter():
        if isinstance(el.tag, str) and etree.QName(el).localname in ("docPr", "cNvPr"):
            for attr in ("descr", "title"):
                if (el.get(attr) or "").strip():
                    out.append(AttrPara(el, attr))
    return out


def unit_from_paras(uid, paras):
    """Join paragraphs into one text block; cells of the same table row are tab-separated (like a PDF row)."""
    parts, segs, pos, prev = [], [], 0, None
    for p in paras:
        if prev is not None:
            same_row = p.cell is not None and prev.row is not None and p.row is prev.row and p.cell is not prev.cell
            parts.append("\t" if same_row else "\n")
            pos += 1
        segs.append((pos, pos + len(p.text), p))
        parts.append(p.text)
        pos += len(p.text)
        prev = p
    return Unit(uid, "".join(parts), ctx=segs)


def apply_text_edits(unit, tokens):
    per = {}
    for s in unit.keep:
        val = " ".join(unit.text[s["start"]:s["end"]].split())
        tok, first = tokens.token(s["entity_type"], val), True
        for a, b, p in unit.ctx:
            if b <= s["start"] or a >= s["end"]:
                continue
            per.setdefault(id(p), (p, []))[1].append(
                (max(s["start"], a) - a, min(s["end"], b) - a, tok if first else ""))
            first = False
    for p, edits in per.values():
        p.redact(edits)


# ---------------------------------------------------------------- images
def _flatten(img):
    if img.mode in ("RGBA", "LA", "P"):
        img = img.convert("RGBA")
        bg = Image.new("RGB", img.size, "white")
        bg.paste(img, mask=img.split()[3])
        return bg
    return img.convert("RGB")


def _ocr_blob(blob):
    return ocr_image(_flatten(Image.open(io.BytesIO(blob))), IMG_DPI)


def redact_blob(blob, boxes_pt):
    img = Image.open(io.BytesIO(blob))
    fmt = img.format or "PNG"
    work = img.convert("RGBA" if fmt == "PNG" else "RGB")
    draw, k = ImageDraw.Draw(work), IMG_DPI / 72.0
    for x0, y0, x1, y1 in boxes_pt:
        draw.rectangle([x0 * k, y0 * k, x1 * k, y1 * k], fill=(0, 0, 0, 255) if fmt == "PNG" else (0, 0, 0))
    out = io.BytesIO()
    work.save(out, format=fmt, **({"quality": 95} if fmt == "JPEG" else {}))
    return out.getvalue()


def blank_blob(blob):
    img = Image.open(io.BytesIO(blob))
    out = io.BytesIO()
    Image.new("RGB", img.size, "white").save(out, format=img.format or "JPEG")
    return out.getvalue()


# ---------------------------------------------------------------- scrubbing
def scrub_authors(root):
    for el in root.iter():
        if not isinstance(el.tag, str):
            continue
        for attr in list(el.attrib):
            q = etree.QName(attr)
            if (q.namespace == W and q.localname in ("author", "initials")) or \
               (etree.QName(el).localname == "cmAuthor" and q.localname in ("name", "initials")):
                el.set(attr, "REDACTED")
    for el in root.iter(f"{{{W}}}instrText"):
        if el.text:
            el.text = EMAIL_RX.sub("redacted@example.invalid", el.text)
    for el in root.iter(f"{{{W}}}fldSimple"):
        key = f"{{{W}}}instr"
        if el.get(key):
            el.set(key, EMAIL_RX.sub("redacted@example.invalid", el.get(key)))


# ---------------------------------------------------------------- handler base for DOCX / PPTX
class OfficeHandler(Handler):
    TEXT_PART_RX = None          # partnames that hold text (set by subclass)
    SCRUB_PART_RX = None         # extra partnames scrubbed for authors only
    UNSUPPORTED_RX = re.compile(r"/embeddings/|\.(emf|wmf|svg)$", re.I)

    # --- subclass hooks -------------------------------------------------
    def _open(self):
        raise NotImplementedError

    def _package(self):
        return self.doc.part.package

    # --- helpers --------------------------------------------------------
    def _root(self, part):
        if hasattr(part, "_element"):
            return part._element
        if part not in self._roots:
            self._roots[part] = etree.fromstring(part.blob)
        return self._roots[part]

    @staticmethod
    def _label(name):
        return re.sub(r"\.xml$", "", name.rsplit("/", 1)[-1])

    # --- extract --------------------------------------------------------
    def extract(self):
        self.doc, self._roots, units = self._open(), {}, []
        self.pkg = self._package()
        for part in self.pkg.iter_parts():
            name = str(part.partname)
            if self.UNSUPPORTED_RX.search(name):
                self.warnings.append(f"not processed (unsupported content): {name}")
            if self.TEXT_PART_RX.match(name):
                paras = paragraphs(self._root(part))
                for i in range(0, len(paras), CHUNK_PARAS):
                    units.append(unit_from_paras(f"{self._label(name)}#{i // CHUNK_PARAS + 1}", paras[i:i + CHUNK_PARAS]))
        units += self._image_units()
        return units

    def _image_units(self):
        parts = []
        for part in self.pkg.iter_parts():
            if part.content_type not in IMAGE_TYPES or "thumbnail" in str(part.partname).lower():
                continue
            try:
                w, h = Image.open(io.BytesIO(part.blob)).size
            except Exception:
                self.warnings.append(f"unreadable image: {part.partname}")
                continue
            if min(w, h) >= MIN_IMG_PX[0] and w * h >= MIN_IMG_PX[1]:
                parts.append(part)
        if not parts:
            return []
        blobs = [p.blob for p in parts]
        if len(blobs) >= 2:
            with ProcessPoolExecutor(max_workers=self.workers) as ex:
                results = list(ex.map(_ocr_blob, blobs))
        else:
            results = [_ocr_blob(blobs[0])]
        units = []
        for part, blob, (words, review) in zip(parts, blobs, results):
            text, items = build_text(words)
            if text.strip() or review:
                units.append(Unit(f"img:{part.partname}", text, ctx={"part": part, "blob": blob, "items": items}, review=review))
        return units

    # --- redact ---------------------------------------------------------
    def redact(self, units, out_path, tokens, fail_closed=False):
        for u in units:
            if isinstance(u.ctx, dict):                      # image unit
                boxes = [b for s in u.keep for b in span_boxes(u.ctx["items"], s["start"], s["end"], PAD)]
                if fail_closed:
                    boxes += list(u.review)
                if boxes:
                    u.ctx["part"]._blob = redact_blob(u.ctx["blob"], boxes)
            else:
                apply_text_edits(u, tokens)
        for part in self.pkg.iter_parts():
            name = str(part.partname)
            if "thumbnail" in name.lower() and part.content_type in IMAGE_TYPES:
                part._blob = blank_blob(part.blob)           # first-page preview would leak everything
            elif self.TEXT_PART_RX.match(name) or (self.SCRUB_PART_RX and self.SCRUB_PART_RX.match(name)):
                scrub_authors(self._root(part))
            elif name == "/docProps/app.xml":
                part._blob = re.sub(rb"<(Company|Manager)>.*?</\1>", rb"<\1></\1>", part.blob, flags=re.S)
            for rel in part.rels.values():                   # mailto:/tel: hyperlink targets
                if rel.is_external and rel.reltype.endswith("/hyperlink") and re.match(r"(?i)mailto:|tel:", rel.target_ref):
                    rel._target = "mailto:redacted@example.invalid"
        cp = self.doc.core_properties
        cp.author = cp.last_modified_by = cp.comments = ""
        for part, root in self._roots.items():               # write back parts we parsed ourselves
            part._blob = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)
        self.doc.save(out_path)
