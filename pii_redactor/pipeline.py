"""End-to-end flow: extract -> detect -> approve -> redact -> log -> leak check. Format-independent."""
import os
import re
import time

from .detect import detect_all
from .formats import get_handler
from .tokens import TokenMap

TOKEN_RX = re.compile(r"\[[A-Z_]+_\d+\]|\[REDACTED\]")


def approve(units, review=True):
    """Ask whether each unique detected value is PII before redacting it."""
    answers = {}
    for u in units:
        u.keep = []
        for s in u.final:
            val = " ".join(u.text[s["start"]:s["end"]].split())
            if not val:
                continue
            if not review:
                u.keep.append(s)
                continue
            key = val.casefold()
            if key not in answers:
                try:
                    answers[key] = input(
                        f"[?] {u.uid} '{val}' ({s['entity_type']}) treat as PII and redact? (y/N): "
                    ).strip().casefold() == "y"
                except (EOFError, OSError):
                    answers[key] = True
            if not answers[key]:
                continue
            u.keep.append(s)


def write_log(units, handler, log_path):
    with open(log_path, "w", encoding="utf-8") as log:
        for u in units:
            for s in u.keep:
                val = " ".join(u.text[s["start"]:s["end"]].split())
                if val:
                    log.write(f"{u.uid:<14} {s['entity_type']:14} {s['score']:.2f} {s['src']:9} '{val}'\n")


def leak_check(out_path, names, workers=None, cache=False):
    """Re-read the redacted file and run detection again. Anything found is a miss."""
    h = get_handler(out_path)(out_path, workers=workers, cache=False)
    units = h.extract()
    detect_all(units, names=names, workers=workers)
    leaks = []
    for u in units:
        for s in u.final:
            val = " ".join(u.text[s["start"]:s["end"]].split())
            if val and not TOKEN_RX.search(val) and "[" not in val and "_" not in val:
                leaks.append((u.uid, s["entity_type"], val))
    return leaks


def run(path, out_path=None, log_path="pii_logs.txt", review=False, fail_closed=False,
        cache=False, verify=None, workers=None):
    t0 = time.time()
    base, ext = os.path.splitext(os.path.basename(path))
    out_path = out_path or f"redacted_{base}{ext}"
    handler = get_handler(path)(path, workers=workers, cache=cache)

    units = handler.extract()
    print(f"[*] {os.path.basename(path)}: {len(units)} text blocks extracted ({time.time() - t0:.1f}s)")
    names = detect_all(units, workers=workers)
    approve(units, review)
    total = sum(len(u.keep) for u in units)
    print(f"[*] {total} detections approved | name registry: {len(names)} tokens")

    handler.redact(units, out_path, TokenMap(), fail_closed)
    write_log(units, handler, log_path)
    for w in handler.warnings:
        print("[!]", w)
    unread = sum(len(u.review) for u in units)
    if unread:
        print(f"[!] {unread} region(s) OCR could not read ({'blacked out' if fail_closed else 'review manually, or use --fail-closed'})")

    if verify if verify is not None else handler.verify_by_default:
        leaks = leak_check(out_path, names, workers, cache)
        print(f"[*] Leak check: {len(leaks)} item(s) still detected" + (" - OK" if not leaks else ""))
        for uid, typ, val in leaks[:20]:
            print(f"      LEAK {uid} {typ}: {val}")
    print(f"[OK] {time.time() - t0:.1f}s | {out_path} | {log_path}")
    return out_path
