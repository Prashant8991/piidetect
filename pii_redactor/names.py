"""Person-name logic: cleaning candidate spans, and the document-wide name registry."""
import difflib
import re
from functools import lru_cache

from wordfreq import zipf_frequency

from .config import COMMON_WORD_ZIPF_MIN, INITIAL, ORG_WORDS, PARTICLES

def norm(t):
    return re.sub(r"[^a-z]", "", re.sub(r"['\u2019]s$", "", t.lower()))


def clean_tok(t):
    return t.strip(".,;:()[]{}\"'\u201c\u201d\u2018\u2019")


def raw_tok(t):
    return t.strip(",;:()[]{}\"'\u201c\u201d\u2018\u2019")

@lru_cache(maxsize=8192)
def is_common_word(token):
    freq = zipf_frequency(token, "en")
    if freq >= COMMON_WORD_ZIPF_MIN:
        return True
    if token.endswith("s") and len(token) > 3:
        if zipf_frequency(token[:-1], "en") >= COMMON_WORD_ZIPF_MIN:
            return True
    return False


def trim_person(text, s, e):
    """Trim org/role/number tokens off the edges of a candidate name; return (s,e) or None."""
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
    """Yield sub-spans of [s,e) that stay within one line/cell (no \n or \t)."""
    pos = s
    for piece in re.split(r"([\n\t])", text[s:e]):
        if piece not in ("\n", "\t") and piece.strip():
            yield pos, pos + len(piece)
        pos += len(piece)


def registry_from_seeds(all_seeds):
    names, initials = set(), set()
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
    if n not in memo:                                # tolerate 1-2 OCR slips (Osadebo, Szewezyk)
        memo[n] = bool(difflib.get_close_matches(n, long_names, n=1, cutoff=0.86))
    return memo[n]


def registry_spans(text, names):
    """Mark every capitalised token whose normalised form is a known name; extend over initials."""
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
