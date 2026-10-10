"""Checksum validators: they turn loose regex matches into precise detections."""
import re

def verhoeff_ok(num):
    d = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
         [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
         [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
    p = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
         [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = d[c][p[i % 8][int(ch)]]
    return c == 0


def iban_ok(raw):
    if not 15 <= len(raw) <= 34 or not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", raw):
        return False
    r = raw[4:] + raw[:4]
    return int("".join(str(int(c, 36)) for c in r)) % 97 == 1


def luhn_ok(num):
    s, alt = 0, False
    for ch in reversed(num):
        n = int(ch)
        if alt:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        s += n
        alt = not alt
    return s % 10 == 0
