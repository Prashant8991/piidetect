"""PDF: native text + OCR of embedded images/scans; redaction draws black boxes (and blanks image pixels)."""
import io
import os
import pickle
from concurrent.futures import ProcessPoolExecutor

import pymupdf
from PIL import Image

from ..config import MIN_IMG_PT, OCR_DPI, PAD
from ..models import Unit
from ..ocr import ocr_image
from ..textlayout import build_text, span_boxes
from .base import Handler


def _extract_page(args):
    path, page_no, cache_dir = args
    cf = os.path.join(cache_dir, f"{os.path.basename(path)}_{page_no}.pkl") if cache_dir else None
    if cf and os.path.exists(cf):
        return page_no, pickle.load(open(cf, "rb"))
    doc = pymupdf.open(path)
    page = doc[page_no - 1]
    words = [(w[0], w[1], w[2], w[3], w[4], ("n", w[5], w[6])) for w in page.get_text("words")]
    review = []
    for im in page.get_image_info():
        r = pymupdf.Rect(im["bbox"]) & page.rect
        if r.width < MIN_IMG_PT or r.height < MIN_IMG_PT:
            continue
        pix = page.get_pixmap(dpi=OCR_DPI, clip=r)
        w, rv = ocr_image(Image.open(io.BytesIO(pix.tobytes("png"))), OCR_DPI)
        words += [(a + r.x0, b + r.y0, c + r.x0, d + r.y0, t, ("o", r.x0, r.y0) + key[1:]) for a, b, c, d, t, key in w]
        review += [(a + r.x0, b + r.y0, c + r.x0, d + r.y0) for a, b, c, d in rv]
    doc.close()
    if cf:
        pickle.dump((words, review), open(cf, "wb"))
    return page_no, (words, review)


class PdfHandler(Handler):
    exts = (".pdf",)
    verify_by_default = False        # re-OCRing the output is slow; enable with --verify

    def extract(self):
        doc = pymupdf.open(self.path)
        total = len(doc)
        doc.close()
        cache_dir = None
        if self.cache:
            cache_dir = ".ocr_cache"
            os.makedirs(cache_dir, exist_ok=True)
        jobs = [(self.path, n, cache_dir) for n in range(1, total + 1)]
        with ProcessPoolExecutor(max_workers=self.workers) as ex:
            results = dict(ex.map(_extract_page, jobs))
        units = []
        for n in range(1, total + 1):
            words, review = results[n]
            text, items = build_text(words)
            units.append(Unit(f"p{n}", text, ctx={"items": items, "page": n}, review=review))
        return units

    def redact(self, units, out_path, tokens, fail_closed=False):
        doc = pymupdf.open(self.path)
        for u in units:
            page = doc[u.ctx["page"] - 1]
            for s in u.keep:
                for b in span_boxes(u.ctx["items"], s["start"], s["end"], PAD):
                    page.add_redact_annot(pymupdf.Rect(b), fill=(0, 0, 0))
            if fail_closed:
                for b in u.review:
                    page.add_redact_annot(pymupdf.Rect(b), fill=(0, 0, 0))
            if u.keep or (fail_closed and u.review):
                page.apply_redactions()
        doc.set_metadata({})
        doc.del_xml_metadata()
        doc.save(out_path, garbage=4, deflate=True, clean=True)
        doc.close()
