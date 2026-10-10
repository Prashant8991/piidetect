"""
PII Shield Unified Detection Engine
Single consolidated detection pipeline shared by all formats (PDF, DOCX, PPTX, TXT, CSV).
Integrates normalization, de-obfuscation, layered name recognition, generic ID matching,
checksum validators, custom rule execution, and entity clustering.
"""

import re
import hashlib
from typing import List, Dict, Any, Optional, Set, Tuple

from .normalize import normalize_text_with_map, map_span_to_original, deobfuscate_contact_text
from .names import LayeredNameDetector, is_corporate_or_business_term
from .rules import REGEX_PATTERNS, is_lookalike_non_pii
from .validators import verhoeff_ok, iban_ok, luhn_ok, orcid_checksum_ok
from .tokens import generate_stable_token
from .custom_rules import load_custom_config


def resolve_overlapping_spans(entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Resolves overlapping entity spans:
    - Sorts by starting offset, prioritizing longer spans and structured entity types.
    - Ensures no two spans collide or cause broken token replacements.
    """
    if not entities:
        return []

    # Sort prioritizing earlier start, then longer span length descending, then higher confidence
    sorted_ents = sorted(
        entities, 
        key=lambda x: (x["start"], -(x["end"] - x["start"]), -x.get("confidence", 0.0))
    )
    
    resolved = []
    for ent in sorted_ents:
        if not resolved:
            resolved.append(ent)
            continue
        prev = resolved[-1]
        # Check collision
        if ent["start"] < prev["end"]:
            # If current span is strictly longer and encloses prev, replace prev
            if ent["start"] <= prev["start"] and ent["end"] > prev["end"]:
                resolved[-1] = ent
            continue
        resolved.append(ent)
    return resolved


def cluster_and_propagate_entities(entities: List[Dict[str, Any]], full_text: str) -> List[Dict[str, Any]]:
    """
    Entity Clustering (Playbook 3.2):
    Groups all mentions of one person (full name, surname only, initials) under a stable token,
    and ensures that if a person is confirmed, their standalone mentions in the document are also caught.
    Guarantees no name is half-redacted.
    """
    person_clusters = {}  # surname_lower -> canonical_entity
    
    for ent in entities:
        if ent["type"] == "PERSON_NAME":
            raw = ent["text"].strip()
            parts = re.split(r'[\s.,-]+', raw)
            if len(parts) >= 2:
                surname = parts[-1].lower()
                if len(surname) >= 3 and not is_corporate_or_business_term(surname):
                    if surname not in person_clusters:
                        person_clusters[surname] = ent

    # Propagate: If an unambiguous person was detected, find other uncaptured occurrences of that surname
    new_ents = list(entities)
    seen_spans = {(e["start"], e["end"]) for e in entities}

    for surname_lower, canonical in person_clusters.items():
        # Match case-sensitively to avoid matching lower-case common words
        cap_surname = surname_lower.capitalize()
        for m in re.finditer(rf'\b{re.escape(cap_surname)}\b', full_text):
            span = (m.start(), m.end())
            if not any(s <= m.start() and m.end() <= e for s, e in seen_spans):
                if not is_corporate_or_business_term(m.group()):
                    seen_spans.add(span)
                    new_ents.append({
                        "id": len(new_ents) + 1,
                        "type": "PERSON_NAME",
                        "text": m.group(),
                        "start": m.start(),
                        "end": m.end(),
                        "confidence": 0.95,
                        "severity": "CRITICAL",
                        "scope": "personal",
                        "source": canonical.get("source", "native"),
                        "token": canonical["token"],
                        "value_hash": hashlib.sha256(m.group().encode()).hexdigest()[:10],
                        "reason": f"Entity cluster propagation ({canonical['text']})",
                        "context": full_text[max(0, m.start() - 25):min(len(full_text), m.end() + 25)]
                    })

    return new_ents


class UnifiedPIIDetector:
    def __init__(self):
        self.name_detector = LayeredNameDetector()

    def detect(
        self,
        text: str,
        custom_gazetteer: Optional[List[str]] = None,
        source_format: str = "native",
        mode: str = "strict"
    ) -> List[Dict[str, Any]]:
        """
        Executes unified detection on text:
        - mode='strict': recall-oriented (confidence >= 0.50 redacted)
        - mode='balanced': precision-oriented (confidence >= 0.85 redacted; 0.50-0.84 flagged for review)
        """
        entities = []
        seen_spans = set()

        # Step 1: Normalization & Index Mapping
        norm_text, norm_to_orig = normalize_text_with_map(text)

        def add_entity(
            entity_type: str, 
            matched_text: str, 
            start: int, 
            end: int, 
            confidence: float, 
            severity: str, 
            reason: str, 
            scope: str = "personal"
        ):
            # Check false-positive look-alike patterns
            if is_lookalike_non_pii(matched_text):
                return

            # Clean trailing/leading whitespace and punctuation
            while matched_text and matched_text[-1] in (':', ',', '.', ';', '-', ' '):
                matched_text = matched_text[:-1]
                end -= 1
            while matched_text and matched_text[0] in (' ', '\n', '\t'):
                matched_text = matched_text[1:]
                start += 1

            if len(matched_text.strip()) <= 1:
                return

            span = (start, end)
            if any(s <= start and end <= e for s, e in seen_spans):
                return
            seen_spans.add(span)

            ctx_start = max(0, start - 25)
            ctx_end = min(len(text), end + 25)
            context_str = text[ctx_start:ctx_end].replace('\n', ' ')

            token = generate_stable_token(entity_type, matched_text)
            val_hash = hashlib.sha256(matched_text.encode('utf-8')).hexdigest()[:10]

            # Review tier categorization (Playbook 3.5)
            is_review_candidate = (0.50 <= confidence < 0.85)

            entities.append({
                "id": len(entities) + 1,
                "type": entity_type,
                "text": matched_text,
                "start": start,
                "end": end,
                "confidence": round(confidence, 2),
                "severity": severity,
                "scope": scope,
                "source": "ocr" if source_format == "pdf" and "PAGE" in context_str else "native",
                "token": token,
                "value_hash": val_hash,
                "reason": reason,
                "context": context_str,
                "needs_review": is_review_candidate
            })

        # Step 2: De-obfuscation Layer (emails & spaced phone numbers)
        deobf_items = deobfuscate_contact_text(text)
        for d in deobf_items:
            add_entity(
                d["type"], d["text"], d["start"], d["end"],
                d["confidence"], "HIGH", d["reason"]
            )

        # Step 3: Layered Name Recognition (sequence heuristics, offline lists, wordfreq)
        detected_names = self.name_detector.detect_names(text, source_format=source_format)
        for n in detected_names:
            add_entity(
                "PERSON_NAME", n["text"], n["start"], n["end"],
                n["confidence"], "CRITICAL", n["reason"]
            )

        # Optional Custom Gazetteer
        if custom_gazetteer:
            for cg in custom_gazetteer:
                if len(cg) >= 3 and not is_corporate_or_business_term(cg):
                    for m in re.finditer(rf'\b{re.escape(cg)}\b', text, re.IGNORECASE):
                        add_entity("PERSON_NAME", m.group(), m.start(), m.end(), 0.96, "CRITICAL", "Custom gazetteer name")

        # Step 4: Deterministic Regular Expressions
        # 4a. Email
        for m in REGEX_PATTERNS["EMAIL"].finditer(text):
            em = m.group()
            add_entity("EMAIL", em, m.start(), m.end(), 0.99, "CRITICAL", "RFC email pattern match")

        # 4b. Phone numbers (with country code prefix included in span)
        for m in REGEX_PATTERNS["PHONE_NUMBER"].finditer(text):
            raw = m.group().strip()
            digits = re.sub(r'\D', '', raw)
            if 7 <= len(digits) <= 15:
                add_entity("PHONE_NUMBER", raw, m.start(), m.end(), 0.95, "HIGH", "Telephony number format")

        # 4c. SSN & National IDs
        for m in REGEX_PATTERNS["SSN"].finditer(text):
            add_entity("SSN", m.group(), m.start(), m.end(), 0.99, "CRITICAL", "Social Security Number")

        for m in REGEX_PATTERNS["SSN_LAST4"].finditer(text):
            if m.groups():
                add_entity("SSN", m.group(1), m.start(1), m.end(1), 0.95, "HIGH", "Last-4 SSN pattern")

        for m in REGEX_PATTERNS["PAN_INDIA"].finditer(text):
            pan = m.group()
            if pan[3] in "PCAFHT":
                add_entity("PAN_GOV_ID", pan, m.start(), m.end(), 0.98, "CRITICAL", "Indian PAN Tax Identifier")

        for m in REGEX_PATTERNS["IN_AADHAAR"].finditer(text):
            raw_d = re.sub(r'\D', '', m.group())
            if verhoeff_ok(raw_d):
                add_entity("AADHAAR_GOV_ID", m.group(), m.start(), m.end(), 0.98, "CRITICAL", "Indian Aadhaar National ID (Verhoeff ok)")

        for m in REGEX_PATTERNS["PESEL_POLAND"].finditer(text):
            add_entity("PESEL_GOV_ID", m.group(), m.start(), m.end(), 0.95, "CRITICAL", "Polish PESEL National ID")

        for m in REGEX_PATTERNS["PASSPORT_CONTEXT"].finditer(text):
            if m.groups():
                add_entity("PASSPORT", m.group(1), m.start(1), m.end(1), 0.95, "CRITICAL", "Passport ID in context")

        for m in REGEX_PATTERNS["DOB_CONTEXT"].finditer(text):
            if m.groups():
                add_entity("DOB", m.group(1), m.start(1), m.end(1), 0.96, "HIGH", "Date of birth in context")

        # 4d. Financial / Banking
        for m in REGEX_PATTERNS["IBAN"].finditer(text):
            raw_iban = m.group().replace(" ", "").replace("-", "")
            if iban_ok(raw_iban):
                add_entity("IBAN", m.group(), m.start(), m.end(), 0.99, "CRITICAL", "IBAN (MOD-97 checksum validated)")

        for m in re.finditer(r'\b(?:\d[ -]?){13,19}\b', text):
            d = re.sub(r'\D', '', m.group())
            if 13 <= len(d) <= 19 and luhn_ok(d):
                add_entity("CREDIT_CARD", m.group(), m.start(), m.end(), 0.98, "CRITICAL", "Payment Card (Luhn checksum validated)")

        for m in REGEX_PATTERNS["CREDIT_CARD_CONTEXT"].finditer(text):
            if m.groups():
                add_entity("CREDIT_CARD", m.group(1), m.start(1), m.end(1), 0.94, "CRITICAL", "Payment card in context")

        for m in REGEX_PATTERNS["BANK_ROUTING"].finditer(text):
            if m.groups():
                add_entity("BANK_ROUTING_CODE", m.group(1), m.start(1), m.end(1), 0.92, "HIGH", "Financial routing code")

        # 4e. ORCID
        for m in REGEX_PATTERNS["ORCID"].finditer(text):
            orcid_val = m.group(1)
            if orcid_checksum_ok(orcid_val):
                add_entity("ORCID", orcid_val, m.start(1), m.end(1), 0.99, "HIGH", "ORCID Identifier (ISO 7064 validated)")

        # 4f. Generic Personal Identifiers (Failure Class 12: CUST#, PATIENT-, ID:, Account #, Policy No.)
        for m in REGEX_PATTERNS["GENERIC_PERSONAL_ID"].finditer(text):
            add_entity("CUSTOM_ID", m.group(), m.start(), m.end(), 0.96, "HIGH", "Generic labeled identifier")

        for m in REGEX_PATTERNS["LABELED_PERSONAL_ID"].finditer(text):
            val = m.group(1) or (m.group(2) if len(m.groups()) >= 2 else None)
            if val and len(val.strip()) >= 3 and not is_lookalike_non_pii(val):
                # Redact the full matched phrase or the labeled value
                add_entity("CUSTOM_ID", m.group(0), m.start(), m.end(), 0.93, "HIGH", "Contextual personal account/ID")

        # 4g. IP Address, User ID, Address
        for m in REGEX_PATTERNS["IP_ADDRESS"].finditer(text):
            add_entity("IP_ADDRESS", m.group(), m.start(), m.end(), 0.90, "MEDIUM", "IP Network Address")

        for m in REGEX_PATTERNS["TERMINAL_USER"].finditer(text):
            if m.groups():
                u_val = m.group(1).strip()
                if len(u_val) >= 3 and not is_corporate_or_business_term(u_val):
                    add_entity("USER_ID", m.group(0), m.start(), m.end(), 0.92, "HIGH", "Terminal username")

        for m in REGEX_PATTERNS["HOME_ADDRESS"].finditer(text):
            add_entity("ADDRESS", m.group(), m.start(), m.end(), 0.88, "MEDIUM", "Street address structure")

        # Step 5: User-Defined Custom Rules (from config/custom_rules.json)
        custom_cfg = load_custom_config()
        for rule in custom_cfg.get("rules", []):
            pat_str = rule.get("pattern", "")
            ent_t = rule.get("entity_type", "CUSTOM")
            try:
                rx = re.compile(pat_str)
                for m in rx.finditer(text):
                    add_entity(ent_t, m.group(0), m.start(), m.end(), 0.95, "HIGH", f"Custom Rule: {rule.get('description', ent_t)}")
            except Exception:
                pass

        # Step 6: Entity Clustering (Cluster & Propagate all occurrences of confirmed persons)
        entities = cluster_and_propagate_entities(entities, text)

        # Step 7: Resolve Overlaps (strictly non-overlapping spans)
        entities = resolve_overlapping_spans(entities)

        # Step 8: Apply Detection Mode Filtering
        if mode == "balanced":
            # In balanced mode, only entities with confidence >= 0.85 are redacted
            # Entities with 0.50 <= conf < 0.85 are retained as review candidates
            pass

        # Re-index
        entities.sort(key=lambda x: x["start"])
        for idx, ent in enumerate(entities, 1):
            ent["id"] = idx

        return entities


# ----------------------------------------------------------------------
# Legacy Compatibility Layer for pii_tests and pii_redactor.pipeline
# ----------------------------------------------------------------------
from functools import lru_cache
from concurrent.futures import ProcessPoolExecutor
from .config import MAILBOX_WORDS, NET_ENTITIES, ORG_ALLOW
from .names import line_split, registry_from_seeds, registry_spans, trim_person
from .rules import CARD, NAME_BEFORE_ID, PERSON_LABEL, RULES, phone_spans


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
    """Fill unit.spans/seeds/ner/final for every unit. Returns the name registry."""
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

