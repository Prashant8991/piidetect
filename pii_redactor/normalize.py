"""
PII Shield Normalization Layer
Handles Unicode NFKC, full-width ASCII conversion, zero-width stripping,
de-obfuscation ([at], (dot), spaced-out characters), and exact character offset mapping
back to original text so replacement never clips or breaks tokens.
"""

import re
import unicodedata
from typing import Tuple, List, Dict, Any, Optional

# Zero-width and invisible control characters to strip
ZERO_WIDTH_CHARS = {'\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad', '\u200e', '\u200f', '\u2060'}

# OCR Character confusion map for numeric/identifier context
OCR_NUMERIC_HOMOGLYPHS = {
    'O': '0', 'o': '0',
    'l': '1', 'I': '1', '|': '1',
    'S': '5', 's': '5',
    'B': '8',
    'Z': '2', 'z': '2'
}

def normalize_text_with_map(text: str) -> Tuple[str, List[int]]:
    """
    Normalizes text (NFKC, full-width, zero-width) while building a monotonic
    index map where norm_to_orig[norm_idx] gives the exact index in original text.
    """
    if not text:
        return "", []

    norm_chars = []
    norm_to_orig = []

    for orig_idx, ch in enumerate(text):
        if ch in ZERO_WIDTH_CHARS:
            continue

        # Full-width to half-width / ASCII conversion
        nfkc_ch = unicodedata.normalize('NFKC', ch)
        if not nfkc_ch:
            continue

        # Normalize diverse whitespace/dashes to standard ASCII space or hyphen
        if ch in ('\u00a0', '\u2002', '\u2003', '\u2009', '\u3000'):
            nfkc_ch = ' '
        elif ch in ('\u2010', '\u2011', '\u2012', '\u2013', '\u2014', '\u2015', '\u2212'):
            nfkc_ch = '-'

        for sub_ch in nfkc_ch:
            norm_chars.append(sub_ch)
            norm_to_orig.append(orig_idx)

    # Add an ending sentinel for slice boundary mapping
    norm_to_orig.append(len(text))
    return "".join(norm_chars), norm_to_orig


def map_span_to_original(norm_start: int, norm_end: int, norm_to_orig: List[int], orig_len: int) -> Tuple[int, int]:
    """Maps a normalized text span (norm_start, norm_end) back to original text slice."""
    if not norm_to_orig:
        return norm_start, norm_end
    
    orig_start = norm_to_orig[min(norm_start, len(norm_to_orig) - 1)]
    orig_end = norm_to_orig[min(norm_end, len(norm_to_orig) - 1)]

    # Safeguard bounds
    orig_start = max(0, min(orig_start, orig_len))
    orig_end = max(orig_start, min(orig_end, orig_len))
    return orig_start, orig_end


# De-obfuscation patterns
AT_PATTERNS = re.compile(r'(?i)(?:\[at\]|\(at\)|\bat\b|_at_|\s*@\s*)')
DOT_PATTERNS = re.compile(r'(?i)(?:\[dot\]|\(dot\)|\bdot\b|_dot_|\s*\.\s*)')

def deobfuscate_contact_text(text: str) -> List[Dict[str, Any]]:
    """
    Finds obfuscated emails like "john dot doe at gmail dot com" or "user [at] domain (dot) com"
    and returns candidate deobfuscated entities with their spans in original text.
    """
    candidates = []
    
    # Pattern matching "X at Y dot Z" style obfuscation
    pattern = re.compile(
        r'(?i)\b([a-z0-9._%+-]+(?:\s+(?:dot|\[dot\]|\(dot\)|\.)\s+[a-z0-9._%+-]+)*)'
        r'\s*(?:\[at\]|\(at\)|\bat\b|_at_)\s*'
        r'([a-z0-9-]+(?:\s+(?:dot|\[dot\]|\(dot\)|\.)\s+[a-z0-9-]+)*'
        r'\s*(?:\[dot\]|\(dot\)|\bdot\b|_dot_|\.)\s*[a-z]{2,7})\b'
    )

    for m in pattern.finditer(text):
        raw_match = m.group(0)
        # Verify it resembles an email when normalized
        norm_email = AT_PATTERNS.sub('@', raw_match)
        norm_email = DOT_PATTERNS.sub('.', norm_email)
        norm_email = re.sub(r'\s+', '', norm_email)

        if '@' in norm_email and '.' in norm_email.split('@')[-1]:
            candidates.append({
                "type": "EMAIL",
                "text": raw_match,
                "normalized_value": norm_email,
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.94,
                "reason": "De-obfuscated email address"
            })

    # Pattern matching spaced-out digits (e.g. 5 5 5 - 1 2 3 - 4 5 6 7)
    spaced_phone_pat = re.compile(r'(?:\+\d\s*)?(?:\(?\s*\d\s*\d\s*\d\s*\)?[\s.-]*)?\d\s*\d\s*\d[\s.-]+\d\s*\d\s*\d\s*\d')
    for m in spaced_phone_pat.finditer(text):
        raw_val = m.group(0)
        digits = re.sub(r'\D', '', raw_val)
        if 7 <= len(digits) <= 15:
            # Check it's not a regular non-spaced number already caught
            if ' ' in raw_val.strip():
                candidates.append({
                    "type": "PHONE_NUMBER",
                    "text": raw_val,
                    "normalized_value": digits,
                    "start": m.start(),
                    "end": m.end(),
                    "confidence": 0.91,
                    "reason": "De-obfuscated spaced phone number"
                })

    return candidates


def apply_ocr_homoglyph_corrections(token: str) -> str:
    """Substitutes confusable OCR letters with digits when surrounded by numbers."""
    res = []
    for i, ch in enumerate(token):
        if ch in OCR_NUMERIC_HOMOGLYPHS:
            # Check context: are neighboring characters digits or punctuation?
            prev_is_digit = (i > 0 and token[i-1].isdigit())
            next_is_digit = (i < len(token) - 1 and token[i+1].isdigit())
            if prev_is_digit or next_is_digit:
                res.append(OCR_NUMERIC_HOMOGLYPHS[ch])
            else:
                res.append(ch)
        else:
            res.append(ch)
    return "".join(res)
