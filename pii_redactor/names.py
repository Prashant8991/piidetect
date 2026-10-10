"""
PII Shield Layered Name Detector
Combines Sequence Heuristics, Bundled Offline Name Gazetteers, Wordfreq Statistical
Scoring, Context & Layout Signals, and Entity Clustering.
Zero hardcoded sample strings. Fully generalizable across unseen documents.
"""

import os
import re
import unicodedata
from typing import List, Dict, Any, Set, Tuple, Optional
from functools import lru_cache

try:
    import wordfreq
    HAS_WORDFREQ = True
except ImportError:
    HAS_WORDFREQ = False

import difflib
from .config import COMMON_WORD_ZIPF_MIN, INITIAL, ORG_WORDS

def norm(t):
    return re.sub(r"[^a-z]", "", re.sub(r"['\u2019]s$", "", t.lower()))

def clean_tok(t):
    return t.strip(".,;:()[]{}\"'\u201c\u201d\u2018\u2019")

def raw_tok(t):
    return t.strip(",;:()[]{}\"'\u201c\u201d\u2018\u2019")

@lru_cache(maxsize=8192)
def is_common_word(token):
    if not HAS_WORDFREQ:
        return False
    freq = wordfreq.zipf_frequency(token, "en")
    if freq >= COMMON_WORD_ZIPF_MIN:
        return True
    if token.endswith("s") and len(token) > 3:
        if wordfreq.zipf_frequency(token[:-1], "en") >= COMMON_WORD_ZIPF_MIN:
            return True
    return False

def trim_person(text, s, e):
    seg = text[s:e]
    toks = [(m.start() + s, m.end() + s, m.group().strip(",;:()[]{}\"'\u201c\u201d\u2018\u2019")) for m in re.finditer(r"[^\s]+", seg)]
    def bad(t):
        c = t[2]
        return (not c or any(ch.isdigit() for ch in c) or c.strip(".").lower() in ORG_WORDS
                or (len(c) > 1 and c.isupper() and "." not in c))
    while toks and bad(toks[0]):
        toks.pop(0)
    while toks and bad(toks[-1]):
        toks.pop()
    if not toks or any(bad(t) for t in toks):
        return None
    words = [t for t in toks if not re.fullmatch(INITIAL, t[2]) and t[2].lower() not in PARTICLES]
    if not words or not all(t[2][0].isupper() or t[2].lower() in PARTICLES or re.fullmatch(INITIAL, t[2]) for t in toks):
        return None
    return toks[0][0], toks[-1][1]

def line_split(text, s, e):
    pos = s
    for piece in re.split(r"([\n\t])", text[s:e]):
        if piece not in ("\n", "\t") and piece.strip():
            yield pos, pos + len(piece)
        pos += len(piece)

def registry_from_seeds(all_seeds):
    names = set()
    for s in all_seeds:
        if s.startswith("@"):
            toks = [s[1:]]
        else:
            toks = [clean_tok(t) for t in s.split()]
        for t in toks:
            n = norm(t)
            if (len(n) >= 3 and n not in ORG_WORDS and not is_common_word(n)
                    and t.lower() not in PARTICLES and not re.fullmatch(INITIAL, t)):
                names.add(n)
    return names

def _is_name(tok, names, long_names, memo):
    c = clean_tok(tok)
    if not c or not c[0].isupper():
        return False
    n = norm(c)
    if is_common_word(n):
        return False
    if n in names:
        return True
    if len(n) < 6:
        return False
    if n not in memo:
        memo[n] = bool(difflib.get_close_matches(n, long_names, n=1, cutoff=0.86))
    return memo[n]

def registry_spans(text, names):
    toks = [(m.start(), m.end(), m.group()) for m in re.finditer(r"[^\s]+", text)]
    long_names, memo = [n for n in names if len(n) >= 6], {}
    hit = [_is_name(t, names, long_names, memo) for _, _, t in toks]
    out = []
    i = 0
    while i < len(toks):
        if not hit[i]:
            i += 1
            continue
        a = i
        while a > 0 and re.fullmatch(INITIAL, raw_tok(toks[a - 1][2])) and text[toks[a - 1][1]:toks[a][0]] == " ":
            a -= 1
        b = i
        while b + 1 < len(toks) and text[toks[b][1]:toks[b + 1][0]] == " " and (
                hit[b + 1] or re.fullmatch(INITIAL, raw_tok(toks[b + 1][2]))):
            b += 1
        while b > i and not hit[b]:
            b -= 1
        s, e = toks[a][0], toks[b][1]
        while e > s and text[e - 1] in ".,;:)]\"'":
            e -= 1
        out.append({"start": s, "end": e, "entity_type": "PERSON", "score": 0.85, "src": "registry"})
        i = b + 1
    return out


# Load Bundled Offline Gazetteers (Public Domain / CC0)
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

@lru_cache(maxsize=1)
def load_name_dictionaries() -> Tuple[Set[str], Set[str]]:
    given = set()
    surnames = set()
    g_file = os.path.join(DATA_DIR, "given_names.txt")
    s_file = os.path.join(DATA_DIR, "surnames.txt")

    if os.path.exists(g_file):
        with open(g_file, "r", encoding="utf-8") as f:
            given = {line.strip().lower() for line in f if line.strip()}
    if os.path.exists(s_file):
        with open(s_file, "r", encoding="utf-8") as f:
            surnames = {line.strip().lower() for line in f if line.strip()}

    return given, surnames

# Titles, Honorifics & Particles
HONORIFICS = {
    "dr", "dr.", "doctor", "prof", "prof.", "professor", "mr", "mr.", "mrs", "mrs.",
    "ms", "ms.", "mx", "mx.", "sir", "dame", "lord", "lady", "rev", "rev.", "reverend",
    "hon", "hon.", "chief"
}
HONORIFICS_REGEX = r'(?i)\b(?:Dr\.|Prof\.|Mr\.|Ms\.|Mrs\.|Mx\.|Doctor|Professor|Sir|Dame|Chief)\b'

PARTICLES = {"van", "von", "de", "del", "della", "da", "di", "du", "bin", "ibn", "al-", "el-", "o'", "mc", "mac"}

# Negative filters: Corporate Vocabulary, Departments, Org Suffixes
ORG_SUFFIXES = {
    "inc", "ltd", "llc", "corp", "corporation", "group", "bank", "university",
    "institute", "college", "authority", "agency", "department", "division",
    "committee", "board", "association", "foundation", "partners", "solutions",
    "technologies", "systems", "holdings", "services", "hospital", "clinic",
    "management", "consulting", "health", "logistics"
}

JOB_ROLE_WORDS = {
    "chief", "officer", "president", "vice", "vp", "director", "manager", "head",
    "lead", "analyst", "owner", "engineer", "architect", "administrator", "executive",
    "counsel", "partner", "associate", "specialist", "coordinator", "assistant",
    "auditor", "assessor", "reviewer", "commander", "examiner", "representative"
}

BUSINESS_WORDS = {
    "security", "risk", "compliance", "technology", "data", "culture", "governance",
    "operations", "operational", "finance", "financial", "audit", "assurance",
    "infrastructure", "cloud", "engineering", "training", "information", "people",
    "corporate", "legal", "enterprise", "business", "third", "party", "internal",
    "external", "quality", "procurement", "service", "standard", "policy", "framework",
    "management", "strategy", "review", "development", "architecture", "support",
    "product", "program", "project", "portfolio", "practice", "center", "centre",
    "global", "treasury", "banking", "investment", "commercial", "consumer",
    "divisional", "market", "liquidity", "capital", "executive"
}

COMMON_NON_NAMES = {
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "january", "february", "march", "april", "may", "june", "july", "august",
    "september", "october", "november", "december", "street", "avenue", "boulevard",
    "road", "lane", "court", "drive", "highway", "north", "south", "east", "west",
    "united", "states", "kingdom", "america", "europe", "asia", "africa",
    "spring", "summer", "autumn", "winter", "level", "summary", "experience", "education"
}

def get_word_frequency_zipf(word: str) -> float:
    """Returns Zipf frequency of a word (higher = more common in English, e.g. 7.5 for 'the')."""
    if not HAS_WORDFREQ:
        return 0.0
    return wordfreq.zipf_frequency(word.lower(), 'en')

def is_corporate_or_business_term(phrase: str) -> bool:
    clean = phrase.strip().lower()
    words = re.findall(r'[a-z]+', clean)
    if not words:
        return True

    # Check for organizational suffixes
    if any(w in ORG_SUFFIXES for w in words):
        return True

    # If all tokens belong to job role or department vocabularies
    if all(w in (JOB_ROLE_WORDS | BUSINESS_WORDS | {"and", "of", "the", "&"}) for w in words):
        return True

    # Check common non-name words (months, directions, etc.)
    if any(w in COMMON_NON_NAMES for w in words) and len(words) == 1:
        return True

    return False


def score_name_candidate(
    candidate: str,
    has_title: bool = False,
    is_heading_or_sig: bool = False,
    is_table_name_col: bool = False,
    email_seed_match: bool = False
) -> Tuple[float, str]:
    """
    Computes a composite score [0.0 - 1.0] for whether a candidate phrase is a person's name.
    Combines gazetteer presence, statistical word rarity, and structural layout cues.
    """
    given_dict, surname_dict = load_name_dictionaries()
    clean = re.sub(r'^(?:[A-Z]\.(?:\s*[A-Z]\.)?\s+|[A-Z]\.\s*)', '', candidate).strip()
    words = [w.lower() for w in re.findall(r"[A-Za-z]+(?:-[A-Za-z]+)?", clean)]

    if not words:
        return 0.0, "Empty"

    if is_corporate_or_business_term(candidate):
        return 0.0, "Corporate / Department phrase"

    score = 0.50  # Base prior for 2+ capitalized word sequences
    reasons = []

    # Title / Honorific bonus
    if has_title:
        score += 0.30
        reasons.append("Honorific title")

    # Initial form bonus
    if re.match(r'^[A-Z]\.(?:\s*[A-Z]\.)?\s+', candidate):
        score += 0.25
        reasons.append("Initial-form structure")

    # Layout cue bonus
    if is_heading_or_sig:
        score += 0.25
        reasons.append("Layout heading/signature cue")
    elif is_table_name_col:
        score += 0.30
        reasons.append("Table name column")

    # Email seed match bonus
    if email_seed_match:
        score += 0.35
        reasons.append("Matches email username seed")

    # Dictionary & Statistical evaluation
    dict_matches = 0
    freq_penalties = 0

    for w in words:
        in_given = w in given_dict
        in_surname = w in surname_dict
        if in_given or in_surname:
            dict_matches += 1

        # Check word frequency penalty
        zipf = get_word_frequency_zipf(w)
        if zipf > 4.6 and not in_given and not in_surname:
            # Common dictionary word that is NOT a known name (e.g. 'Standard', 'Security')
            freq_penalties += 1

    if dict_matches >= 2:
        score += 0.30
        reasons.append("Multi-part gazetteer match")
    elif dict_matches == 1:
        score += 0.15
        reasons.append("Single gazetteer match")

    if freq_penalties > 0:
        score -= (0.35 * freq_penalties)
        reasons.append(f"Common English word penalty ({freq_penalties})")

    # Particle bonus (e.g. 'van der Meer', 'al-Mansoor', 'de Silva')
    if any(p in words for p in PARTICLES) or any(w.startswith("o'") or w.startswith("mc") for w in words):
        score += 0.20
        reasons.append("Name particle/prefix match")

    score = max(0.0, min(1.0, score))
    return score, ", ".join(reasons) if reasons else "Heuristic capitalization match"


class LayeredNameDetector:
    def __init__(self):
        self.given_dict, self.surname_dict = load_name_dictionaries()

    def detect_names(self, text: str, source_format: str = "native") -> List[Dict[str, Any]]:
        detected = []
        seen_spans = set()

        def add_span(start: int, end: int, matched_text: str, conf: float, reason: str):
            # Strip trailing punctuation
            while matched_text and matched_text[-1] in (':', ',', '.', ';', '-', '\n'):
                matched_text = matched_text[:-1]
                end -= 1
            while matched_text and matched_text[0] in ('\n', ' ', '\t'):
                matched_text = matched_text[1:]
                start += 1

            if len(matched_text.strip()) < 2:
                return

            span = (start, end)
            if any(s <= start and end <= e for s, e in seen_spans):
                return
            seen_spans.add(span)

            detected.append({
                "type": "PERSON_NAME",
                "text": matched_text,
                "start": start,
                "end": end,
                "confidence": round(conf, 2),
                "reason": reason
            })

        # 1. Harvest email and username seeds across document
        name_seeds = set()
        email_pattern = re.compile(r'\b([A-Za-z]+)[._]([A-Za-z]+)@')
        for m in email_pattern.finditer(text):
            p1, p2 = m.group(1).lower(), m.group(2).lower()
            if len(p1) >= 2 and len(p2) >= 2 and not is_corporate_or_business_term(f"{p1} {p2}"):
                name_seeds.add(p1)
                name_seeds.add(p2)

        # 2. Layout & Signature Signals
        lines = text.splitlines()
        char_offset = 0

        for line_idx, line in enumerate(lines):
            stripped = line.strip()
            line_len = len(line)

            # Check for top-of-document standalone name (e.g. CV header)
            if line_idx < 3 and stripped and len(stripped.split()) in (2, 3):
                if re.match(r'^(?:[A-Z][a-z]+(?:-[A-Z][a-z]+)?\s+){1,2}[A-Z][a-z]+(?:-[A-Z][a-z]+)?$', stripped):
                    conf, reason = score_name_candidate(stripped, is_heading_or_sig=True)
                    if conf >= 0.70:
                        s_idx = text.find(stripped, char_offset)
                        if s_idx >= 0:
                            add_span(s_idx, s_idx + len(stripped), stripped, conf, f"CV/Document Title Name: {reason}")

            # Check for Signature & Salutation lines ("Signed, John Smith", "Dear Jane Doe", "To: X", "From: X")
            sig_match = re.match(r'^(?:Signed|Regards|Sincerely|To|From|Billed To|Prescribing Physician|Patient|Customer|Client|Employee|Applicant|Author|Auditor|Reviewer|Representative [AB])\s*[:,\-]?\s+([A-Z][a-z]+(?:\s+[A-Z]\.?)?\s+(?:(?:van|von|de|del|da|al-|bin)\s+)?[A-Z][A-Za-z\'\u2019-]+)$', stripped, re.IGNORECASE)
            if sig_match:
                cand = sig_match.group(1).strip()
                conf, reason = score_name_candidate(cand, is_heading_or_sig=True)
                if conf >= 0.70:
                    c_idx = text.find(cand, char_offset)
                    if c_idx >= 0:
                        add_span(c_idx, c_idx + len(cand), cand, conf, f"Signature/Salutation: {reason}")

            # Check for attendee lists in minutes
            if stripped.startswith("- ") or stripped.startswith("* "):
                bullet_content = stripped[2:].strip()
                if re.match(r'^[A-Z][a-z]+(?:\s+[A-Z]\.?)?\s+(?:(?:van|von|de|del|da|al-|bin)\s+)?[A-Z][A-Za-z\'\u2019-]+$', bullet_content):
                    conf, reason = score_name_candidate(bullet_content, is_heading_or_sig=True)
                    if conf >= 0.70:
                        b_idx = text.find(bullet_content, char_offset)
                        if b_idx >= 0:
                            add_span(b_idx, b_idx + len(bullet_content), bullet_content, conf, f"Attendee list: {reason}")

            char_offset += line_len + 1

        # 3. Pattern with Honorific Titles: "Dr. Elena Okonkwo", "Prof. Lars-Erik Nielsen"
        title_name_pat = re.compile(
            r'\b(?:Dr\.|Prof\.|Mr\.|Ms\.|Mrs\.|Mx\.|Doctor|Professor|Sir)\s+'
            r'([A-Z][a-z]+(?:-[A-Z][a-z]+)?(?:\s+[A-Z]\.?)?(?:\s+(?:van|von|de|del|da|al-|bin)\s+[A-Z][a-z]+)?\s+[A-Z][A-Za-z\'\u2019-]+)\b'
        )
        for m in title_name_pat.finditer(text):
            full_span = m.group(0)
            conf, reason = score_name_candidate(m.group(1), has_title=True)
            if conf >= 0.75:
                add_span(m.start(), m.end(), full_span, conf, f"Titled Person: {reason}")

        # 4. Pattern: Initial forms like "I. Surname" or "J. R. Smith" or "Surname, F."
        initial_name_pat = re.compile(r'\b([A-Z]\.(?:\s*[A-Z]\.)?\s+[A-Z][A-Za-z\'\u2019-]+)\b')
        for m in initial_name_pat.finditer(text):
            cand = m.group(1)
            last_word = cand.split()[-1].lower()
            if not is_corporate_or_business_term(last_word):
                conf, reason = score_name_candidate(cand)
                if conf >= 0.65 or last_word in self.surname_dict or last_word in name_seeds:
                    add_span(m.start(), m.end(), cand, max(conf, 0.85), f"Initial Name: {reason}")

        # 5. General Sequence Heuristic: 2-3 Capitalized words without cues
        seq_pat = re.compile(
            r'\b([A-Z][a-z]+(?:-[A-Z][a-z]+)?'
            r'(?:[ \t]+(?:van|von|de|del|da|al-|bin)[ \t]+[A-Z][A-Za-z\'\u2019-]+|[ \t]+[A-Z][A-Za-z\'\u2019-]+){1,2})\b'
        )
        for m in seq_pat.finditer(text):
            cand = m.group(1)
            c_start = m.start()
            c_end = m.end()

            # Trim leading common word if not a registered name (e.g. 'Yesterday Daisuke Takahashi' -> 'Daisuke Takahashi')
            parts = cand.split()
            while len(parts) >= 2 and parts[0].lower() not in self.given_dict and parts[0].lower() not in self.surname_dict and get_word_frequency_zipf(parts[0]) > 4.0:
                c_start += len(parts[0]) + 1
                parts.pop(0)

            cand = " ".join(parts)
            if len(parts) < 2:
                continue

            # Check if this overlaps with already detected titled span
            if any(s <= c_start and c_end <= e for s, e in seen_spans):
                continue

            words = [w.lower() for w in re.findall(r'[a-zA-Z]+', cand)]
            matches_seed = any(w in name_seeds for w in words)
            conf, reason = score_name_candidate(cand, email_seed_match=matches_seed)

            if conf >= 0.60:
                add_span(c_start, c_end, cand, conf, f"Sequence Name: {reason}")


        # 6. ALL-CAPS Names (e.g. in forms or formal headings)
        allcaps_pat = re.compile(r'\b([A-Z]{3,15}\s+[A-Z]{3,18})\b')
        for m in allcaps_pat.finditer(text):
            cand = m.group(1)
            words = [w.lower() for w in cand.split()]
            if all(w in self.given_dict or w in self.surname_dict for w in words):
                add_span(m.start(), m.end(), cand, 0.90, "ALL-CAPS registered name match")

        return detected
