"""Checksum validators: they turn loose regex matches into precise detections."""
import re

def verhoeff_ok(num: str) -> bool:
    d = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
         [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
         [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
    p = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
         [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
    c = 0
    for i, ch in enumerate(reversed(num)):
        if not ch.isdigit():
            return False
        c = d[c][p[i % 8][int(ch)]]
    return c == 0


def iban_ok(raw: str) -> bool:
    clean = raw.replace(" ", "").replace("-", "").upper()
    if not 15 <= len(clean) <= 34 or not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", clean):
        return False
    r = clean[4:] + clean[:4]
    try:
        return int("".join(str(int(c, 36)) for c in r)) % 97 == 1
    except ValueError:
        return False


def luhn_ok(num: str) -> bool:
    digits = re.sub(r'\D', '', num)
    if not digits:
        return False
    s, alt = 0, False
    for ch in reversed(digits):
        n = int(ch)
        if alt:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        s += n
        alt = not alt
    return s % 10 == 0


def orcid_checksum_ok(orcid_str: str) -> bool:
    digits = orcid_str.replace('-', '').replace(' ', '').upper()
    if len(digits) != 16:
        return False
    base = digits[:15]
    check = digits[15]
    total = 0
    for ch in base:
        if not ch.isdigit():
            return False
        total = (total + int(ch)) * 2
    rem = total % 11
    result = (12 - rem) % 11
    expected = 'X' if result == 10 else str(result)
    return check == expected
