"""Regex rules for fixed-format identifiers and labelled fields (format-agnostic: works on plain text)."""
import re

from .config import DASH, INITIAL, NAME_TOK

PERSON_LABEL = re.compile(
    r"(?i:\b(?:name|full name|applicant|customer|client|employee|account holder|requestor|requester|signed by|"
    r"signature of|attested by|prepared by|owner)[ ]*:[ ]*(?:name[ ]*:[ ]*)?)"
    r"(%s(?:[ ]+(?:%s|%s)){1,3})" % (NAME_TOK, NAME_TOK, INITIAL)
)

RULES = [
    # (type, regex, group, score)
    ("EMAIL_ADDRESS", re.compile(r"[A-Za-z0-9._%+\-]+\s?@\s?[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}"), 0, 0.9),
    ("EMPLOYEE_ID", re.compile(r"(?<![A-Za-z])(?:EMP|DIR)[%s_]?\s?\d{4,5}(?!\d)" % DASH), 0, 0.9),
    ("VENDOR_ID", re.compile(r"(?<![A-Za-z])MER[%s]\s*[A-Z]{2}[%s]\s*\d{3,5}(?!\d)" % (DASH, DASH)), 0, 0.9),
    ("US_SSN", re.compile(r"(?<![\d-])\d{3}[%s ]\d{2}[%s ]\d{4}(?![\d-])" % (DASH, DASH)), 0, 0.85),
    ("US_SSN", re.compile(r"\bSSN\b[:\s]*([0-9OolI]{3}[^\w\n]{1,2}[0-9OolI]{2}[^\w\n]{1,2}[0-9OolI]{4})"), 1, 0.8),
    # field label followed by a value: redact the value even if OCR garbled it
    ("LABELLED_VALUE", re.compile(
        r"\b(?:DOB|D\.O\.B|Passport|PAN|Mobile|Phone|Tel|TIN|Aadhaar|SSN|Left)\b[:\s]+(\S*\d\S*(?:[ ]\S*\d\S*)?)"), 1, 0.65),
    ("IN_PAN", re.compile(r"(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])"), 0, 0.9),
    ("PL_PESEL", re.compile(r"(?<!\d)\d{6}[\dxX*]{5}(?![\dxX*])"), 0, 0.7),
    ("PASSPORT", re.compile(r"(?i:passport)[^A-Za-z0-9\n]{0,15}(?:(?i:no|number)\.?[:\s#]*)?([A-Z0-9]{1,2}\d{6,9})(?!\d)"), 1, 0.9),
    ("PASSPORT", re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{7}(?![A-Za-z0-9])"), 0, 0.6),
    ("TAX_ID", re.compile(r"(?i:\bTIN\b|tax\s+(?:id|identifier|number))[:\s#]*([0-9][0-9\-]{7,})"), 1, 0.8),
    ("IP_ADDRESS", re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"), 0, 0.8),
    ("IN_AADHAAR", re.compile(r"(?<!\d)[2-9]\d{3}\s\d{4}\s\d{4}(?!\d)"), 0, 0.7),
    ("PHONE_NUMBER", re.compile(r"\(\d{3}\)\s?\d{3}[%s ]\d{4}" % DASH), 0, 0.7),
    ("PHONE_NUMBER", re.compile(r"(?<![\d-])\d{3}-\d{3}-\d{4}(?![\d-])"), 0, 0.7),
    ("DATE_OF_BIRTH", re.compile(
        r"(?i:\bDOB\b|D\.O\.B\.?|date\s+of\s+birth|\bborn\b)[:,\s]*\(?"
        r"(\d{1,2}[ /.\-](?:[A-Za-z]{3,9}|\d{1,2})[ /.\-,]+\d{2,4}|[A-Za-z]{3,9}\.?\s+\d{1,2},?\s+\d{4})"), 1, 0.9),
    ("ACCOUNT_SUFFIX", re.compile(
        r"(?i:ending(?:\s+in)?|last\s+four\s+digits[^()]{0,80}\(|last\s+4[^()]{0,40}\()\s*(\d{4})(?!\d)"), 1, 0.8),
    ("ADDRESS", re.compile(
        r"\b\d{1,5}[ ]+(?:[A-Z][A-Za-z]*\.?[ ]+){1,3}(?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Court|Ct|Crescent|Drive|Dr|Boulevard|Blvd|Way|Place|Pl)\b\.?"
        r"(?:[ ]+(?:N|S|E|W|NE|NW|SE|SW)\b)?"
        r"(?:,?[ ]*(?:Apartment|Apt|Suite|Ste|Unit|Flat)[ ]*\w+)?"
        r"(?:[ ,|]+[A-Z][a-z]+(?:[ ][A-Z][a-z]+)?,?[ ]*[A-Z]{2}[ ]*\d{5}(?:-\d{4})?)?"), 0, 0.8),
    ("IBAN", re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?(?![A-Za-z0-9])"), 0, 0.85),
    ("ACCOUNT_NUMBER", re.compile(
        r"(?i:\b(?:a/c|acct?|account|iban|card)\b\.?[ ]*(?:no\.?|number|num|#)?[ ]*:?[ ]*)([A-Z0-9][A-Z0-9 \-]{6,30}[A-Z0-9])(?![A-Za-z0-9])"), 1, 0.75),
    ("BANK_CODE", re.compile(
        r"(?i:(?:branch[ ]+code|swift(?:[ ]+code)?|\bbic\b|ifsc(?:[ ]+code)?|sort[ ]+code|routing(?:[ ]+(?:number|no\.?))?)[ ]*[:#\-]?[ ]*)([A-Z0-9][A-Z0-9\-]{5,13})(?![A-Za-z0-9])"), 1, 0.7),
    ("ADDRESS", re.compile(r"(?i:\b(?:address|addr|residing at|resides at|home address|mailing address)[ ]*:)[ ]*([^\n\t]{6,110})"), 1, 0.8),
    ("ADDRESS", re.compile(r"\b[A-Z][a-z]+(?:[ ][A-Z][a-z]+)?,[ ]*[A-Z]{2}[ ]+\d{5}(?:-\d{4})?\b"), 0, 0.7),
    ("PERSON", PERSON_LABEL, 1, 0.9),
    ("PERSON", re.compile(
        r"(?i:\b(?:yours[ ]+(?:faithfully|sincerely|truly)|sincerely|regards|best[ ]+regards|kind[ ]+regards)[ ]*,?)\s+"
        r"(%s(?:[ ]+(?:%s|%s)){1,3})" % (NAME_TOK, NAME_TOK, INITIAL)), 1, 0.85),
    ("PERSON", re.compile(r"\b(?:Ms|Mr|Mrs|Mx|Dr|Miss)\.?\s+(%s(?:\s+%s)?)" % (NAME_TOK, NAME_TOK)), 1, 0.8),
    ("PERSON", re.compile(r"(?i:\b(?:husband|wife|spouse|partner|son|daughter|brother|sister|father|mother),)\s+(%s(?:\s+%s){1,2})" % (NAME_TOK, NAME_TOK)), 1, 0.8),
]
PHONE_INTL = re.compile(r"(?<![\w+])\+\d{1,3}[ \t]*(?:\(\d{1,5}\)|\d{1,5})(?:[ .\-\n]*\d{2,5}){1,4}(?!\d)")
PHONE_CTX = re.compile(r"(?i:(?:mobile|phone|tel|call|contact|direct line)[^\n\d+(]{0,12})(\(?\d{2,4}\)?[ .\-]\d{3,4}[ .\-]\d{3,4})(?!\d)")
CARD = re.compile(r"(?<![\d-])(?:\d[ \-]?){13,19}(?!\d)")
NAME_BEFORE_ID = re.compile(
    r"((?:(?:%s|%s)[ ]+){1,3}%s)[ ]*(?:,[ ]*)?\(?[ ]*(?:EMP|DIR|MER)[%s]" % (NAME_TOK, INITIAL, NAME_TOK, DASH))


def phone_spans(text):
    out = []
    for m in PHONE_INTL.finditer(text):
        s, e = m.start(), m.end()
        digits = lambda a, b: len(re.sub(r"\D", "", text[a:b]))
        while digits(s, e) > 14:                       # greedy overshoot: drop trailing groups
            cut = max(text.rfind(" ", s, e), text.rfind("\n", s, e), text.rfind("-", s, e))
            if cut <= s:
                break
            e = cut
        if digits(s, e) >= 8:
            out.append((s, e))
    for m in PHONE_CTX.finditer(text):
        out.append((m.start(1), m.end(1)))
    return out
