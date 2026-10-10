import os
import io
import numpy as np
from PIL import Image, ImageOps, ImageStat

try:
    import pytesseract
    pytesseract.pytesseract.tesseract_cmd = os.getenv(
        "TESSERACT_CMD", r"C:\Program Files\Tesseract-OCR\tesseract.exe")
    HAS_TESSERACT = os.path.exists(pytesseract.pytesseract.tesseract_cmd)
except Exception:
    HAS_TESSERACT = False

_rapid_ocr = None
def _get_rapid_ocr():
    global _rapid_ocr
    if _rapid_ocr is None:
        try:
            from rapidocr_onnxruntime import RapidOCR
            _rapid_ocr = RapidOCR()
        except Exception:
            _rapid_ocr = None
    return _rapid_ocr

from .config import OCR_DPI


def _tess(img, psm=None):
    if HAS_TESSERACT:
        try:
            cfg = f"--psm {psm}" if psm else ""
            d = pytesseract.image_to_data(img, config=cfg, output_type=pytesseract.Output.DICT)
            out = []
            for i, w in enumerate(d["text"]):
                if w.strip() and float(d["conf"][i]) >= 0:
                    out.append((d["left"][i], d["top"][i], d["left"][i] + d["width"][i], d["top"][i] + d["height"][i],
                                w.strip(), (d["block_num"][i], d["par_num"][i], d["line_num"][i]), float(d["conf"][i])))
            return out
        except Exception:
            pass

    # RapidOCR fallback when system Tesseract binary is not installed
    ocr = _get_rapid_ocr()
    if ocr is not None:
        try:
            arr = np.array(img.convert("RGB"))
            ocr_res, _ = ocr(arr)
            out = []
            if ocr_res:
                for idx, (box, text_line, score) in enumerate(ocr_res):
                    words = text_line.strip().split()
                    if not words:
                        continue
                    xs = [pt[0] for pt in box]
                    ys = [pt[1] for pt in box]
                    min_x, max_x = min(xs), max(xs)
                    min_y, max_y = min(ys), max(ys)
                    w_width = (max_x - min_x) / len(words)
                    for w_idx, w in enumerate(words):
                        w_left = min_x + w_idx * w_width
                        w_right = w_left + w_width
                        out.append((w_left, min_y, w_right, max_y, w, (1, 1, idx), float(score) * 100))
            return out
        except Exception:
            pass
    return []


def _bands(spans, gap):
    spans = sorted(spans)
    out = []
    for a, b in spans:
        if out and a - out[-1][1] <= gap:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def _mean_conf(ws):
    return sum(w[6] for w in ws) / len(ws) if ws else -1


def _group_lines(words):
    lines = {}
    for w in words:
        lines.setdefault(w[5], []).append(w)
    return lines


def _bbox(ws):
    return min(w[0] for w in ws), min(w[1] for w in ws), max(w[2] for w in ws), max(w[3] for w in ws)


def ocr_image(img, dpi=OCR_DPI, upscale=3):
    """Two-pass OCR. Pass 1 reads the region; pass 2 re-reads low-confidence / unread bands (figures,
    scans, screenshots) at 3x and keeps whichever reading of each line is better.
    Coordinates are returned in points (1/72 in) from the image top-left.
    Returns (words, review_boxes). review_boxes = areas that still could not be read."""
    img = img.convert("L")
    k = 72.0 / dpi
    words = _tess(img)
    H, W = img.height, img.width

    bad = []
    for ws in _group_lines(words).values():
        short = sum(1 for w in ws if len(w[4]) <= 2) / len(ws)
        if _mean_conf(ws) < 72 or (len(ws) >= 4 and short > 0.5):
            bad.append((min(w[1] for w in ws), max(w[3] for w in ws)))
    strip = int(36 / k)
    for y in range(0, H, strip):
        box = (0, y, W, min(H, y + strip))
        inside = [w for w in words if box[1] <= (w[1] + w[3]) / 2 < box[3]]
        if ImageStat.Stat(img.crop(box)).stddev[0] > 28 and (len(inside) < 3 or _mean_conf(inside) < 70):
            bad.append((box[1], box[3]))
    ext = int(30 / k)
    bands = [b for b in _bands(bad, int(10 / k)) if b[1] - b[0] >= int(8 / k)]

    review = []
    for y0, y1 in bands:
        y0, y1 = max(0, y0 - ext), min(H, y1 + ext)
        strip_img = img.crop((0, y0, W, y1))
        bb = strip_img.point(lambda v: 255 if v < 200 else 0).getbbox()
        if not bb:
            continue
        pad = int(4 / k)
        x0, x1 = max(0, bb[0] - pad), min(W, bb[2] + pad)
        crop = strip_img.crop((x0, 0, x1, strip_img.height))
        big = ImageOps.autocontrast(crop.resize((crop.width * upscale, crop.height * upscale), Image.LANCZOS))
        cands = [big]
        if ImageStat.Stat(crop).mean[0] < 120:
            cands.append(ImageOps.invert(big))
        best = []
        for c in cands:
            new = [(a / upscale + x0, b / upscale + y0, c2 / upscale + x0, d / upscale + y0, t, key, cf)
                   for a, b, c2, d, t, key, cf in _tess(c, 6)]
            if _mean_conf(new) * len(new) ** 0.5 > _mean_conf(best) * max(len(best), 1) ** 0.5:
                best = new
        # line-by-line merge: keep the better reading of every line
        for nkey, nl in _group_lines(best).items():
            nx0, ny0, nx1, ny1 = _bbox(nl)
            hit = []
            for okey, ol in _group_lines(words).items():
                ox0, oy0, ox1, oy1 = _bbox(ol)
                v = min(ny1, oy1) - max(ny0, oy0)
                if v > 0.5 * min(ny1 - ny0, oy1 - oy0) and min(nx1, ox1) > max(nx0, ox0):
                    hit.append(ol)
            old = [w for ol in hit for w in ol]
            if not old or _mean_conf(nl) > _mean_conf(old) + 3:
                words = [w for w in words if w not in old] + [
                    (a, b, c2, d, t, ("b", y0) + key, cf) for a, b, c2, d, t, key, cf in nl]
        in_band = [w for w in words if y0 <= (w[1] + w[3]) / 2 <= y1 and x0 <= w[0] <= x1]
        if len(in_band) < 4 or _mean_conf(in_band) < 50:
            review.append((x0 * k, y0 * k, x1 * k, y1 * k))

    out = [(w[0] * k, w[1] * k, w[2] * k, w[3] * k, w[4], ("o",) + tuple(w[5])) for w in words]
    return out, review
