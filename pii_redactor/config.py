"""Settings and vocabulary shared by every module. Edit this file to tune behaviour."""
import re

OCR_DPI = 220                 # render resolution used for PDF pages / OCR
IMG_DPI = 150                 # assumed resolution of images embedded in DOCX/PPTX
PAD = 1.2                     # redaction box padding (pt)
MIN_IMG_PT = 60               # PDF: ignore embedded images smaller than this (pt)
MIN_IMG_PX = (32, 12000)      # DOCX/PPTX: skip images with a side < 32px or area < 12000px
CHUNK_PARAS = 60              # DOCX/PPTX: paragraphs per detection unit
COMMON_WORD_ZIPF_MIN = 3.0    # Exclude words occurring at least once per thousand words from name propagation.

# Organisation addresses that are NOT personal data (substring match)
ORG_ALLOW = ["245 Hudson Street"]

# Presidio built-in detectors used as an extra safety net on top of our own rules
NET_ENTITIES = ["IBAN_CODE", "US_SSN", "US_ITIN", "US_PASSPORT", "IN_PAN", "IN_AADHAAR", "IN_VOTER",
                "IN_PASSPORT", "IP_ADDRESS", "CRYPTO", "EMAIL_ADDRESS"]

ORG_WORDS = {w.lower() for w in """
Cadence Mumbai Internal Confidential Financial Group Asset Management Capital Markets Limited
Services Private Europe Pte Inc Entity Regulator Policy Board Appendix Committee Risk Chief Head
Officer Framework Counsel Secretary Engineer Analyst Manager Director Administrator Auditor Privacy
Security Technology Operational Enterprise Information Internal Audit Compliance Conduct Credit
Market Liquidity Funding Executive Divisional Consumer Banking Investment Operations Global
Treasury Legal Reviewer Owner Author Approved Effective Classification Version Document Page
Section Figure Contingent Training Finance Data Third Party Staffing Analytics Screening
Federal Reserve Singapore India Kingdom United States London York Hoboken Jersey Krakow Bengaluru
Chennai Manila Hong Kong Sanctions Climate Strategic Reputational Policy Standard Procedure
Control Controls Issue Issues Incident Report Reporting Register Review Assurance Chair Member
Attestation Signature Received Scope Unit Contact Name Role Status Rating Expiry Target Weakness
Critical High Elevated Moderate Low IAM CRO CFO CISO CCO CPO CEO NED Level Manager Lead Deputy Sponsor Operator Independent Line The Branch Bank America Dear Sir Madam Yours Faithfully Sincerely Regards
Dated Request Account Transfer Deposit Phone Address Applicant Customer
Employee Employees Contact Owner Call Write Her His Their Our Please Note Scanned Name Email Mobile Tel
""".split()}
PARTICLES = {"de", "van", "von", "der", "bin", "al", "la", "da", "di", "del", "du", "le", "dos"}
MAILBOX_WORDS = {"board", "chair", "brc", "gerc", "orc", "remco", "info", "admin", "contact",
                 "support", "sales", "hr", "privacy", "legal", "audit", "risk", "noreply"}

DASH = "-\u2010\u2011\u2012\u2013\u2014\u2212"
NAME_TOK = r"[A-Z][A-Za-z'\u2019]*(?:[%s][A-Z]?[A-Za-z'\u2019]+)*" % DASH
INITIAL = r"[A-Z]\.(?:[%s][A-Z]\.)?" % DASH
