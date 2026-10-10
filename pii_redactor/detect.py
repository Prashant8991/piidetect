"""Detection engine: rules + Presidio/spaCy per text block, then a document-wide name registry and merge."""
import re
from concurrent.futures import ProcessPoolExecutor
from functools import lru_cache

from .config import MAILBOX_WORDS, NET_ENTITIES, ORG_ALLOW
from .names import (line_split, registry_from_seeds, registry_spans, trim_person)
from .rules import CARD, NAME_BEFORE_ID, PERSON_LABEL, RULES, phone_spans
from .validators import iban_ok, luhn_ok, verhoeff_ok


@lru_cache(maxsize=1)
def get_analyzer():
    try:
        from presidio_analyzer import AnalyzerEngine
        return AnalyzerEngine()
    except Exception:
        return None


def detect_text(text):
    """Detect PII in one block of plain text. Returns (spans, name_seeds, ner_names)."""
    spans, seeds, ner_names = [], set(), []

    def add(typ, s, e, score, src="rule"):
        spans.append({"start": s, "end": e, "entity_type": typ, "score": score, "src": src})

    for typ, rx, grp, score in RULES:
        for m in rx.finditer(text):
            s, e = m.start(grp), m.end(grp)
            if typ == "IN_AADHAAR":
                digits = re.sub(r"\D", "", text[s:e])
                ctx = text[max(0, s - 40):s].lower()
                if not (verhoeff_ok(digits) or "aadhaar" in ctx or "aadhar" in ctx):
                    continue
            if typ == "ADDRESS" and any(a.lower() in text[max(0, s - 60):e + 60].lower() for a in ORG_ALLOW):
                continue
            if typ == "IBAN":
                raw = re.sub(r"\s", "", text[s:e])
                ctx = text[max(0, s - 30):s].lower()
                if not (iban_ok(raw) or re.search(r"a/c|acct|account|iban", ctx)):
                    continue
            if typ in ("ACCOUNT_NUMBER", "BANK_CODE"):
                if sum(ch.isdigit() for ch in text[s:e]) < (6 if typ == "ACCOUNT_NUMBER" else 1):
                    continue
            if typ == "PERSON":
                t = trim_person(text, s, e)
                if not t:
                    continue
                s, e = t
                if rx is PERSON_LABEL:
                    seeds.add(text[s:e])
            add(typ, s, e, score)
    for s, e in phone_spans(text):
        add("PHONE_NUMBER", s, e, 0.8)
    for m in CARD.finditer(text):
        d = re.sub(r"\D", "", m.group())
        if 13 <= len(d) <= 19 and luhn_ok(d) and not re.match(r"[A-Z]{2}\d{2}", text[max(0, m.start() - 4):m.end()].lstrip()[:4]) \
                and not any(x["entity_type"] in ("IBAN", "ACCOUNT_NUMBER") and x["start"] <= m.start() < x["end"] for x in spans):
            add("CREDIT_CARD", m.start(), m.end(), 0.9)
    for m in NAME_BEFORE_ID.finditer(text):
        t = trim_person(text, m.start(1), m.end(1))
        if t:
            add("PERSON", t[0], t[1], 0.9, "name_id")
            seeds.add(text[t[0]:t[1]])
    # surname / name derived from e-mail local parts
    for m in re.finditer(r"([A-Za-z]+(?:[._][A-Za-z]+)?)@", text):
        parts = re.split(r"[._]", m.group(1))
        if len(parts) == 2 and not (set(p.lower() for p in parts) & MAILBOX_WORDS):
            if len(parts[0]) == 1 and len(parts[1]) >= 3:
                seeds.add("@" + parts[1])
            elif len(parts[0]) >= 3 and len(parts[1]) >= 3:
                seeds.add("@" + parts[0])
                seeds.add("@" + parts[1])
    if text.strip():
        analyzer = get_analyzer()
        if analyzer is not None:
            try:
                for r in analyzer.analyze(text=text, language="en", entities=NET_ENTITIES, score_threshold=0.5):
                    add(r.entity_type, r.start, r.end, float(r.score), "presidio")
                for r in analyzer.analyze(text=text, language="en", entities=["PERSON"], score_threshold=0.5):
                    for a, b in line_split(text, r.start, r.end):
                        t = trim_person(text, a, b)
                        if t and len(text[t[0]:t[1]].split()) >= 2:
                            add("PERSON", t[0], t[1], 0.55, "ner")
                            ner_names.append(text[t[0]:t[1]])
            except Exception:
                pass
    return spans, seeds, ner_names


def merge(spans):
    """Structured types beat PERSON. Overlapping spans of the same class are unioned so no residue is left."""
    cls = lambda t: "P" if t == "PERSON" else "S"
    kept = []
    for s in sorted(spans, key=lambda s: (cls(s["entity_type"]) == "P", -s["score"], s["start"])):
        clash = [k for k in kept if s["start"] < k["end"] and k["start"] < s["end"]]
        if not clash:
            kept.append(dict(s))
        elif all(cls(k["entity_type"]) == cls(s["entity_type"]) for k in clash):
            s = dict(s)
            for k in clash:
                if k["score"] >= s["score"]:
                    s["entity_type"], s["score"], s["src"] = k["entity_type"], k["score"], k["src"]
                s["start"], s["end"] = min(s["start"], k["start"]), max(s["end"], k["end"])
                kept.remove(k)
            kept.append(s)
    return sorted(kept, key=lambda s: s["start"])


def _worker(text):
    return detect_text(text)


def detect_all(units, names=None, workers=None):
    """Fill unit.spans/seeds/ner/final for every unit. Returns the name registry.
    Pass `names` (a previous registry) to reuse it, e.g. for the post-redaction leak check."""
    texts = [u.text for u in units]
    if len(texts) >= 3:
        with ProcessPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(_worker, texts, chunksize=1))
    else:
        results = [detect_text(t) for t in texts]
    for u, (spans, seeds, ner) in zip(units, results):
        u.spans, u.seeds, u.ner = spans, seeds, ner
    if names is None:
        seeds = set().union(*(u.seeds for u in units)) if units else set()
        names = registry_from_seeds(seeds)
    for u in units:
        u.final = merge(list(u.spans) + registry_spans(u.text, names))
    return names
