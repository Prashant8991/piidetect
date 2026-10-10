"""Turn positioned words (PDF or OCR) into plain text, keeping a map from characters back to boxes."""


def build_text(words):
    """Group words into lines, lines top-to-bottom; keep char offsets per word."""
    lines = {}
    for w in words:
        lines.setdefault(w[5], []).append(w)
    ordered = sorted(lines.values(), key=lambda ws: (round(min(w[1] for w in ws) / 4), min(w[0] for w in ws)))
    parts, items, pos = [], [], 0
    for ws in ordered:
        ws.sort(key=lambda w: w[0])
        prev = None
        for w in ws:
            if prev is not None:
                gap = w[0] - prev[2]
                h = max(prev[3] - prev[1], 6)
                sep = "\t" if gap > 2.2 * h else " "
                parts.append(sep)
                pos += len(sep)
            items.append((pos, pos + len(w[4]), w[:4]))
            parts.append(w[4])
            pos += len(w[4])
            prev = w
        parts.append("\n")
        pos += 1
    return "".join(parts), items


def span_boxes(items, s, e, pad=1.2, gap=14):
    """Boxes (x0, y0, x1, y1) covering characters [s, e), merged per visual line."""
    boxes = [b for a, z, b in items if a < e and s < z]
    boxes.sort(key=lambda b: (round(b[1] / 3), b[0]))
    out = []
    for b in boxes:
        if out and abs(out[-1][1] - b[1]) < 4 and b[0] - out[-1][2] < gap:
            o = out[-1]
            out[-1] = [min(o[0], b[0]), min(o[1], b[1]), max(o[2], b[2]), max(o[3], b[3])]
        else:
            out.append(list(b))
    return [(x0 - pad, y0 - pad, x1 + pad, y1 + pad) for x0, y0, x1, y1 in out]
