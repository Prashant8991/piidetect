"""Smoke test: every planted PII string must be gone from the redacted DOCX/PPTX, harmless text must survive."""
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pii_redactor.pipeline import run

HERE = os.path.dirname(os.path.abspath(__file__))
PII = ["Raghavan", "Priya", "Deshmukh", "Okonjo", "Abdul", "Lindqvist", "Vorstermann", "acme-test", "40318", "41488",
       "AQBPR7741L", "900-55-2043", "555-0147", "98452", "GL28", "5014", "C Street", "Ashwood", "07302", "14 July 1991"]
MUST_SURVIVE = ["no personal data"]


def all_xml_text(path):
    z, out = zipfile.ZipFile(path), []
    for n in z.namelist():
        if n.endswith((".xml", ".rels")):
            out.append(z.read(n).decode("utf8", "ignore"))
    return "\n".join(out)


def check(path):
    out = os.path.join(HERE, "out_" + os.path.basename(path))
    run(path, out, os.path.join(HERE, "log_" + os.path.basename(path) + ".txt"), verify=True)
    blob = all_xml_text(out)
    missed = [p for p in PII if p in blob]
    lost = [m for m in MUST_SURVIVE if m.lower() not in blob.lower()]
    print(f"== {os.path.basename(path)}: still present={missed} | lost harmless text={lost}")
    return not missed and not lost


if __name__ == "__main__":
    ok = all([check(os.path.join(HERE, f)) for f in ("sample.docx", "sample.pptx")])
    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)
