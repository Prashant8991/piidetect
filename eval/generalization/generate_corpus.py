"""
Optiv / Cadence PII Shield - Generalization Test Corpus Generator
Generates synthetic, ground-truth-annotated documents covering diverse formats:
Native PDF, Scanned PDF (with simulated raster noise), DOCX, PPTX, TXT, CSV.
Fully seeded and repeatable. No real PII.
"""

import os
import sys
import json
import random
import io
import argparse
from typing import Dict, List, Any, Tuple

# Libraries for document generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import fitz  # PyMuPDF
from PIL import Image, ImageDraw, ImageFilter
import docx
from pptx import Presentation
from pptx.util import Inches, Pt
import csv

# Permissive, synthetic name elements
FIRST_NAMES = [
    "Aarav", "Elena", "Liam", "Fatima", "Chen", "Katarzyna", "Mateo", "Ingrid",
    "Kwame", "Soraya", "Lars-Erik", "Chukwudi", "Mei-Ling", "Tariq", "Alejandro",
    "Siobhan", "Hassan", "Aiko", "Jean-Luc", "Zahra", "Dmitri", "Ananya", "Nia", "Bjorn"
]
SURNAMES = [
    "Okonkwo", "Lindqvist", "van der Meer", "Raghunathan", "Al-Mansoor", "Kowalska",
    "de Silva", "Nielsen", "O'Connor", "Bertucci", "Featherstone", "Nkemdirim",
    "Gomez", "Dubois", "Takahashi", "Petrov", "MacLeod", "Schumacher", "Bhattacharya"
]
TITLES = ["Dr.", "Prof.", "Mr.", "Ms.", "Mrs.", "Mx.", "Chief"]
PARTICLES = ["van", "von", "de", "del", "da", "bin", "al-"]

STREET_NAMES = ["Oakway Lane", "Highland Crescent", "Market Street", "Boulevard Saint-Germain", "Nehru Road", "Wilhelmstrasse", "Kingsway"]
CITIES = ["Zurich", "Toronto", "Edinburgh", "Singapore", "Stockholm", "Chicago", "Bengaluru", "Auckland"]

# Corporate / Look-alike non-PII vocabularies
COMPANIES = [
    "Apex Capital Management", "Federal Reserve System", "Optiv Security Inc",
    "Global Logistics Partners LLC", "Pacific Standard Bank", "Caledonian Trust Ltd",
    "Metropolitan Health Authority", "Horizon Data Systems Group"
]
DEPARTMENTS = ["Internal Audit", "Human Resources", "Information Security", "Enterprise Risk", "Operations", "Legal & Compliance"]
ROLES = ["Chief Information Officer", "Managing Director", "Senior Lead Auditor", "Lead Security Architect", "Data Protection Officer"]


class SyntheticCorpusGenerator:
    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def random_person(self, titled: bool = False, particle: bool = False, initial: bool = False) -> Dict[str, str]:
        first = self.rng.choice(FIRST_NAMES)
        last = self.rng.choice(SURNAMES)
        if particle:
            p = self.rng.choice(PARTICLES)
            last = f"{p} {last}"
        if initial:
            first = f"{first[0]}."
        title = self.rng.choice(TITLES) if titled else ""
        full = f"{title} {first} {last}".strip() if title else f"{first} {last}"
        return {
            "first": first,
            "last": last,
            "title": title,
            "full_name": full,
            "email_handle": f"{first.lower().replace('.', '')}.{last.lower().replace(' ', '')}"
        }

    def generate_phone(self) -> str:
        formats = [
            f"+1 (555) {self.rng.randint(100,999)}-{self.rng.randint(1000,9999)}",
            f"+44 20 {self.rng.randint(7000,7999)} {self.rng.randint(1000,9999)}",
            f"+49 30 {self.rng.randint(1000000,9999999)}",
            f"555.{self.rng.randint(100,999)}.{self.rng.randint(1000,9999)} ext. {self.rng.randint(10,99)}",
            f"+91 98{self.rng.randint(10000000,99999999)}"
        ]
        return self.rng.choice(formats)

    def generate_ids(self) -> Dict[str, str]:
        return {
            "ssn": f"{self.rng.randint(100,899):03d}-{self.rng.randint(10,99):02d}-{self.rng.randint(1000,9999):04d}",
            "custom_patient": f"PATIENT-{self.rng.randint(100,999)}",
            "custom_cust": f"CUST#{self.rng.randint(1000,9999)}",
            "custom_id_label": f"ID: {self.rng.randint(100000,999999)}",
            "custom_account": f"Account #{self.rng.randint(100000,999999)}",
            "custom_policy": f"Policy No. POL-{self.rng.randint(1000,9999)}",
            "orcid": f"0000-0002-{self.rng.randint(1000,9999)}-{self.rng.randint(1000,9999)}",
            "iban": f"GB{self.rng.randint(10,99):02d}MIDL400515{self.rng.randint(10000000,99999999):08d}"
        }

    def generate_all(self, output_dir: str) -> List[Dict[str, Any]]:
        os.makedirs(output_dir, exist_ok=True)
        manifest = []

        manifest.append(self._gen_academic_cv(output_dir))
        manifest.append(self._gen_executive_resume_docx(output_dir))
        manifest.append(self._gen_hospital_lab_report_pdf(output_dir))
        manifest.append(self._gen_vendor_invoice_pdf(output_dir))
        manifest.append(self._gen_bank_statement_pdf(output_dir))
        manifest.append(self._gen_hr_letter_docx(output_dir))
        manifest.append(self._gen_incident_report_txt(output_dir))
        manifest.append(self._gen_client_onboarding_pptx(output_dir))
        manifest.append(self._gen_medical_prescription_txt(output_dir))
        manifest.append(self._gen_tax_declaration_csv(output_dir))
        manifest.append(self._gen_customer_complaint_txt(output_dir))
        manifest.append(self._gen_nda_agreement_docx(output_dir))
        manifest.append(self._gen_meeting_minutes_txt(output_dir))
        manifest.append(self._gen_chat_transcript_txt(output_dir))
        manifest.append(self._gen_sales_receipt_txt(output_dir))
        manifest.append(self._gen_slide_deck_notes_pptx(output_dir))

        with open(os.path.join(output_dir, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        return manifest

    # 1. Academic CV (Native PDF)
    def _gen_academic_cv(self, out_dir: str) -> Dict[str, Any]:
        p = self.random_person(titled=True)
        ids = self.generate_ids()
        phone = self.generate_phone()
        email = f"{p['email_handle']}@stanford.example.edu"
        filename = "academic_cv.pdf"
        filepath = os.path.join(out_dir, filename)

        entities = [
            {"entity": "PERSON_NAME", "text": p["full_name"], "has_context": False},
            {"entity": "EMAIL", "text": email, "has_context": True},
            {"entity": "PHONE_NUMBER", "text": phone, "has_context": True},
            {"entity": "ORCID", "text": ids["orcid"], "has_context": True}
        ]
        must_not_redact = [
            "2018 - 2021", "2022-2027", "(2023)", "10.1038/s41586-020-2649-2",
            "Stanford University", "Department of Computer Science"
        ]

        doc = SimpleDocTemplate(filepath, pagesize=letter, rightMargin=54, leftMargin=54, topMargin=54, bottomMargin=54)
        styles = getSampleStyleSheet()
        story = [
            Paragraph(f"<b>{p['full_name']}</b>", styles['Title']),
            Paragraph(f"Department of Computer Science | Stanford University", styles['Normal']),
            Paragraph(f"Email: {email} | Phone: {phone} | ORCID: {ids['orcid']}", styles['Normal']),
            Spacer(1, 15),
            Paragraph("<b>Research Appointments</b>", styles['Heading2']),
            Paragraph("Associate Professor, Stanford University (2022-2027)", styles['Normal']),
            Paragraph("Postdoctoral Fellow, MIT (2018 - 2021)", styles['Normal']),
            Spacer(1, 10),
            Paragraph("<b>Selected Publications</b>", styles['Heading2']),
            Paragraph("1. Neural Representation Alignment. <i>Nature Machine Intelligence</i> (2023). DOI: 10.1038/s41586-020-2649-2", styles['Normal']),
            Paragraph("2. Algorithmic Bounds in Privacy Auditing. <i>IEEE S&P</i> (2021).", styles['Normal']),
        ]
        doc.build(story)

        gt = {"filename": filename, "format": "PDF", "source": "native", "entities": entities, "must_not_redact": must_not_redact}
        with open(os.path.join(out_dir, f"{filename}.json"), "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2)
        return gt

    # 2. Executive Resume (DOCX)
    def _gen_executive_resume_docx(self, out_dir: str) -> Dict[str, Any]:
        p = self.random_person(titled=False)
        phone = self.generate_phone()
        email = f"{p['email_handle']}@consulting.example.com"
        filename = "executive_resume.docx"
        filepath = os.path.join(out_dir, filename)

        entities = [
            {"entity": "PERSON_NAME", "text": p["full_name"], "has_context": False},
            {"entity": "EMAIL", "text": email, "has_context": True},
            {"entity": "PHONE_NUMBER", "text": phone, "has_context": True},
            {"entity": "CUSTOM_ID", "text": "ID: 492019", "has_context": True}
        ]
        must_not_redact = ["2016-2020", "2021-Present", "VP, Engineering", "Pacific Standard Bank"]

        doc = docx.Document()
        doc.add_heading(p["full_name"], level=0)
        p_contact = doc.add_paragraph(f"{email} | {phone} | ID: 492019")
        
        doc.add_heading("Professional Summary", level=1)
        doc.add_paragraph("Seasoned technology executive with 15+ years leading enterprise risk transformations.")

        doc.add_heading("Experience", level=1)
        doc.add_paragraph("VP, Engineering - Pacific Standard Bank (2021-Present)")
        doc.add_paragraph("Director of Software Engineering - Apex Capital (2016-2020)")
        
        # Add a table
        table = doc.add_table(rows=2, cols=2)
        table.cell(0, 0).text = "Security Clearance"
        table.cell(0, 1).text = "Level 4 Enterprise"
        table.cell(1, 0).text = "Notice Period"
        table.cell(1, 1).text = "30 Days"

        doc.save(filepath)

        gt = {"filename": filename, "format": "DOCX", "source": "native", "entities": entities, "must_not_redact": must_not_redact}
        with open(os.path.join(out_dir, f"{filename}.json"), "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2)
        return gt

    # 3. Hospital Lab Report (Scanned PDF with noise/blur)
    def _gen_hospital_lab_report_pdf(self, out_dir: str) -> Dict[str, Any]:
        patient = self.random_person(titled=False)
        doctor = self.random_person(titled=True)
        dob = f"1984-{self.rng.randint(1,12):02d}-{self.rng.randint(1,28):02d}"
        patient_id = f"PATIENT-{self.rng.randint(100,999)}"
        filename = "hospital_lab_report.pdf"
        filepath = os.path.join(out_dir, filename)

        entities = [
            {"entity": "PERSON_NAME", "text": patient["full_name"], "has_context": True},
            {"entity": "PERSON_NAME", "text": doctor["full_name"], "has_context": True},
            {"entity": "CUSTOM_ID", "text": patient_id, "has_context": True},
            {"entity": "DOB", "text": dob, "has_context": True}
        ]
        must_not_redact = ["Metropolitan Health Authority", "Hematology Panel", "Reference Range 4.5-11.0", "120/80 mmHg"]

        # Create image with PIL
        img = Image.new("RGB", (800, 1050), color=(250, 248, 245))
        draw = ImageDraw.Draw(img)

        draw.text((50, 40), "METROPOLITAN HEALTH AUTHORITY - CLINICAL LAB REPORT", fill=(20, 20, 20))
        draw.line([(50, 65), (750, 65)], fill=(80, 80, 80), width=2)

        draw.text((50, 85), f"Patient Name: {patient['full_name']}", fill=(10, 10, 10))
        draw.text((50, 110), f"Patient ID: {patient_id}", fill=(10, 10, 10))
        draw.text((50, 135), f"DOB: {dob}", fill=(10, 10, 10))
        draw.text((50, 160), f"Attending Physician: {doctor['full_name']}", fill=(10, 10, 10))

        draw.line([(50, 190), (750, 190)], fill=(120, 120, 120), width=1)
        draw.text((50, 210), "TEST: Complete Blood Count & Hematology Panel", fill=(20, 20, 20))
        draw.text((50, 240), "White Blood Cell Count: 6.8 K/uL (Reference Range 4.5-11.0)", fill=(30, 30, 30))
        draw.text((50, 265), "Blood Pressure Reading: 120/80 mmHg", fill=(30, 30, 30))
        draw.text((50, 290), "Status: Clinically Normal. No further evaluation required.", fill=(30, 30, 30))

        # Add scan artifacts: slight blur and noise
        img = img.filter(ImageFilter.GaussianBlur(radius=0.6))
        
        # Save as single-page PDF
        img.save(filepath, "PDF", resolution=100.0)

        gt = {"filename": filename, "format": "PDF", "source": "ocr", "entities": entities, "must_not_redact": must_not_redact}
        with open(os.path.join(out_dir, f"{filename}.json"), "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2)
        return gt

    # 4. Vendor Invoice (Native PDF)
    def _gen_vendor_invoice_pdf(self, out_dir: str) -> Dict[str, Any]:
        cust = self.random_person(titled=False)
        cust_id = f"CUST#{self.rng.randint(1000,9999)}"
        ids = self.generate_ids()
        filename = "vendor_invoice.pdf"
        filepath = os.path.join(out_dir, filename)

        entities = [
            {"entity": "PERSON_NAME", "text": cust["full_name"], "has_context": True},
            {"entity": "CUSTOM_ID", "text": cust_id, "has_context": True},
            {"entity": "IBAN", "text": ids["iban"], "has_context": True}
        ]
        must_not_redact = ["INV-2024-8891", "$4,850.00", "20%", "Global Logistics Partners LLC"]

        doc = SimpleDocTemplate(filepath, pagesize=letter)
        styles = getSampleStyleSheet()
        story = [
            Paragraph("<b>INVOICE - Global Logistics Partners LLC</b>", styles['Title']),
            Spacer(1, 10),
            Paragraph(f"Invoice Number: INV-2024-8891 | Date: October 10, 2024", styles['Normal']),
            Paragraph(f"Billed To: {cust['full_name']} ({cust_id})", styles['Normal']),
            Paragraph(f"Wire Remittance IBAN: {ids['iban']}", styles['Normal']),
            Spacer(1, 15),
            Table([
                ["Item Description", "Quantity", "Rate", "Total"],
                ["Cloud Migration Audit", "1", "$4,000.00", "$4,000.00"],
                ["Tax (VAT)", "20%", "-", "$850.00"],
                ["Grand Total", "", "", "$4,850.00"]
            ], style=[
                ('GRID', (0,0), (-1,-1), 1, colors.grey),
                ('BACKGROUND', (0,0), (-1,0), colors.lightgrey)
            ])
        ]
        doc.build(story)

        gt = {"filename": filename, "format": "PDF", "source": "native", "entities": entities, "must_not_redact": must_not_redact}
        with open(os.path.join(out_dir, f"{filename}.json"), "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2)
        return gt

    # 5. Bank Statement (Native PDF)
    def _gen_bank_statement_pdf(self, out_dir: str) -> Dict[str, Any]:
        holder = self.random_person(titled=False)
        acct_no = f"Account #{self.rng.randint(100000,999999)}"
        addr = f"{self.rng.randint(10,999)} {self.rng.choice(STREET_NAMES)}, {self.rng.choice(CITIES)}"
        filename = "bank_statement.pdf"
        filepath = os.path.join(out_dir, filename)

        entities = [
            {"entity": "PERSON_NAME", "text": holder["full_name"], "has_context": False},
            {"entity": "CUSTOM_ID", "text": acct_no, "has_context": True},
            {"entity": "ADDRESS", "text": addr, "has_context": False}
        ]
        must_not_redact = ["Pacific Standard Bank", "01/09/2024 - 30/09/2024", "$12,450.80", "Sort Code 40-12-88"]

        doc = SimpleDocTemplate(filepath, pagesize=letter)
        styles = getSampleStyleSheet()
        story = [
            Paragraph("<b>PACIFIC STANDARD BANK</b>", styles['Title']),
            Paragraph("Monthly Statement of Account | Period: 01/09/2024 - 30/09/2024", styles['Normal']),
            Spacer(1, 10),
            Paragraph(f"<b>{holder['full_name']}</b>", styles['Normal']),
            Paragraph(f"{addr}", styles['Normal']),
            Paragraph(f"{acct_no} | Sort Code 40-12-88", styles['Normal']),
            Spacer(1, 15),
            Paragraph("Ending Balance: $12,450.80", styles['Normal'])
        ]
        doc.build(story)

        gt = {"filename": filename, "format": "PDF", "source": "native", "entities": entities, "must_not_redact": must_not_redact}
        with open(os.path.join(out_dir, f"{filename}.json"), "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2)
        return gt

    # 6. HR Disciplinary Letter (DOCX)
    def _gen_hr_letter_docx(self, out_dir: str) -> Dict[str, Any]:
        emp = self.random_person(titled=False)
        mgr = self.random_person(titled=True)
        emp_id = f"EMP-{self.rng.randint(10000,99999)}"
        filename = "hr_disciplinary_letter.docx"
        filepath = os.path.join(out_dir, filename)

        entities = [
            {"entity": "PERSON_NAME", "text": emp["full_name"], "has_context": False},
            {"entity": "EMPLOYEE_ID", "text": emp_id, "has_context": True},
            {"entity": "PERSON_NAME", "text": mgr["full_name"], "has_context": True}
        ]
        must_not_redact = ["Human Resources Department", "Section 4.2 Standard Operating Procedure"]

        doc = docx.Document()
        doc.add_heading("STRICTLY PRIVATE & CONFIDENTIAL", level=1)
        doc.add_paragraph(f"To: {emp['full_name']} (Employee ID: {emp_id})")
        doc.add_paragraph("From: Human Resources Department")
        doc.add_paragraph("Subject: Confirmation of Performance Discussion")
        doc.add_paragraph("In accordance with Section 4.2 Standard Operating Procedure, this letter confirms our discussion regarding information classification controls.")
        doc.add_paragraph(f"Signed,\n{mgr['full_name']}\nLead HR Business Partner")
        doc.save(filepath)

        gt = {"filename": filename, "format": "DOCX", "source": "native", "entities": entities, "must_not_redact": must_not_redact}
        with open(os.path.join(out_dir, f"{filename}.json"), "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2)
        return gt

    # 7. Incident Report Log (TXT)
    def _gen_incident_report_txt(self, out_dir: str) -> Dict[str, Any]:
        user = "j_doe99"
        ip = f"192.168.{self.rng.randint(1,254)}.{self.rng.randint(1,254)}"
        filename = "incident_report.txt"
        filepath = os.path.join(out_dir, filename)

        entities = [
            {"entity": "USER_ID", "text": f"user={user}", "has_context": True},
            {"entity": "IP_ADDRESS", "text": ip, "has_context": False}
        ]
        must_not_redact = ["SEC-INC-2024-001", "Port 443", "nginx/1.24.0", "SHA-256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]

        content = f"""INCIDENT REPORT: SEC-INC-2024-001
Status: Triaged
Timestamp: 2024-10-10T14:32:01Z
Component: Edge Reverse Proxy nginx/1.24.0 on Port 443
Audit Payload Hash: SHA-256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Connection established from {ip} with authenticated user={user}.
Session terminated after exceeding rate limits.
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        gt = {"filename": filename, "format": "TXT", "source": "native", "entities": entities, "must_not_redact": must_not_redact}
        with open(os.path.join(out_dir, f"{filename}.json"), "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2)
        return gt

    # 8. Client Onboarding (PPTX)
    def _gen_client_onboarding_pptx(self, out_dir: str) -> Dict[str, Any]:
        lead = self.random_person(titled=False)
        phone = self.generate_phone()
        email = f"{lead['email_handle']}@partner.example.com"
        filename = "client_onboarding.pptx"
        filepath = os.path.join(out_dir, filename)

        entities = [
            {"entity": "PERSON_NAME", "text": lead["full_name"], "has_context": False},
            {"entity": "PHONE_NUMBER", "text": phone, "has_context": True},
            {"entity": "EMAIL", "text": email, "has_context": True}
        ]
        must_not_redact = ["Tier 1 Client Onboarding", "Enterprise SLA: 99.99%", "Risk & Assurance Working Group"]

        prs = Presentation()
        # Slide 1: Title
        slide = prs.slides.add_slide(prs.slide_layouts[0])
        slide.shapes.title.text = "Tier 1 Client Onboarding"
        slide.placeholders[1].text = "Risk & Assurance Working Group\nEnterprise SLA: 99.99%"

        # Slide 2: Directory Table
        slide2 = prs.slides.add_slide(prs.slide_layouts[5])
        slide2.shapes.title.text = "Key Project Contacts"
        rows, cols = 2, 3
        table_shape = slide2.shapes.add_table(rows, cols, Inches(1), Inches(2), Inches(8), Inches(2))
        table = table_shape.table
        table.cell(0, 0).text = "Role"
        table.cell(0, 1).text = "Contact Person"
        table.cell(0, 2).text = "Mobile / Email"
        table.cell(1, 0).text = "Engagement Lead"
        table.cell(1, 1).text = lead["full_name"]
        table.cell(1, 2).text = f"{phone} | {email}"

        prs.save(filepath)

        gt = {"filename": filename, "format": "PPTX", "source": "native", "entities": entities, "must_not_redact": must_not_redact}
        with open(os.path.join(out_dir, f"{filename}.json"), "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2)
        return gt

    # 9. Medical Prescription (TXT)
    def _gen_medical_prescription_txt(self, out_dir: str) -> Dict[str, Any]:
        p = self.random_person(titled=False)
        doc_name = self.random_person(titled=True)
        filename = "medical_prescription.txt"
        filepath = os.path.join(out_dir, filename)

        entities = [
            {"entity": "PERSON_NAME", "text": p["full_name"], "has_context": True},
            {"entity": "PERSON_NAME", "text": doc_name["full_name"], "has_context": True},
            {"entity": "CUSTOM_ID", "text": "Policy No. POL-8902", "has_context": True}
        ]
        must_not_redact = ["Amoxicillin 500mg", "Rx# 99401", "Take 1 capsule every 8 hours"]

        content = f"""PRESCRIPTION ORDER - Rx# 99401
Prescribing Physician: {doc_name['full_name']}
Patient: {p['full_name']}
Insurance: Policy No. POL-8902

Medication: Amoxicillin 500mg
Directions: Take 1 capsule every 8 hours with water.
Refills: 0
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        gt = {"filename": filename, "format": "TXT", "source": "native", "entities": entities, "must_not_redact": must_not_redact}
        with open(os.path.join(out_dir, f"{filename}.json"), "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2)
        return gt

    # 10. Tax Declaration (CSV)
    def _gen_tax_declaration_csv(self, out_dir: str) -> Dict[str, Any]:
        taxpayer = self.random_person(titled=False)
        ids = self.generate_ids()
        addr = f"{self.rng.randint(10,999)} {self.rng.choice(STREET_NAMES)}"
        filename = "tax_declaration.csv"
        filepath = os.path.join(out_dir, filename)

        entities = [
            {"entity": "PERSON_NAME", "text": taxpayer["full_name"], "has_context": True},
            {"entity": "SSN", "text": ids["ssn"], "has_context": True},
            {"entity": "ADDRESS", "text": addr, "has_context": True}
        ]
        must_not_redact = ["Form 1040-EZ", "Tax Year 2023", "84000.00", "0.22"]

        rows = [
            ["Form", "Tax Year", "Taxpayer Name", "SSN", "Address", "Gross Income", "Marginal Rate"],
            ["Form 1040-EZ", "Tax Year 2023", taxpayer["full_name"], ids["ssn"], addr, "84000.00", "0.22"]
        ]
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(rows)

        gt = {"filename": filename, "format": "CSV", "source": "native", "entities": entities, "must_not_redact": must_not_redact}
        with open(os.path.join(out_dir, f"{filename}.json"), "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2)
        return gt

    # 11. Customer Complaint with Obfuscated Email (TXT)
    def _gen_customer_complaint_txt(self, out_dir: str) -> Dict[str, Any]:
        cust = self.random_person(titled=False)
        # Obfuscated email: e.g. "john dot doe at gmail dot com"
        obfuscated_email = f"{cust['first'].lower()} dot {cust['last'].lower().replace(' ', '')} at gmail dot com"
        phone = self.generate_phone()
        filename = "customer_complaint.txt"
        filepath = os.path.join(out_dir, filename)

        entities = [
            {"entity": "PERSON_NAME", "text": cust["full_name"], "has_context": False},
            {"entity": "EMAIL", "text": obfuscated_email, "has_context": True},
            {"entity": "PHONE_NUMBER", "text": phone, "has_context": True}
        ]
        must_not_redact = ["Ticket #CAS-88120", "Order #ORD-991204", "Product SKU: PROD-4410", "48 hours"]

        content = f"""Customer Feedback Log
Case Reference: Ticket #CAS-88120
Related Order: Order #ORD-991204 regarding Product SKU: PROD-4410

Complaint submitted by {cust['full_name']}.
Customer requested response to {obfuscated_email} or mobile {phone}.
Issue: Item was delayed beyond the guaranteed 48 hours delivery window.
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        gt = {"filename": filename, "format": "TXT", "source": "native", "entities": entities, "must_not_redact": must_not_redact}
        with open(os.path.join(out_dir, f"{filename}.json"), "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2)
        return gt

    # 12. NDA Agreement (DOCX)
    def _gen_nda_agreement_docx(self, out_dir: str) -> Dict[str, Any]:
        party_a = self.random_person(titled=False)
        party_b = self.random_person(titled=False)
        filename = "nda_agreement.docx"
        filepath = os.path.join(out_dir, filename)

        entities = [
            {"entity": "PERSON_NAME", "text": party_a["full_name"], "has_context": True},
            {"entity": "PERSON_NAME", "text": party_b["full_name"], "has_context": True}
        ]
        must_not_redact = ["Apex Capital Management", "Horizon Data Systems Group", "3 years", "State of New York"]

        doc = docx.Document()
        doc.add_heading("MUTUAL NON-DISCLOSURE AGREEMENT", level=0)
        doc.add_paragraph("This Agreement is entered into by and between Apex Capital Management and Horizon Data Systems Group.")
        doc.add_paragraph(f"Representative A: {party_a['full_name']}")
        doc.add_paragraph(f"Representative B: {party_b['full_name']}")
        doc.add_paragraph("The confidentiality obligations herein shall remain in effect for a period of 3 years under the laws of the State of New York.")
        doc.save(filepath)

        gt = {"filename": filename, "format": "DOCX", "source": "native", "entities": entities, "must_not_redact": must_not_redact}
        with open(os.path.join(out_dir, f"{filename}.json"), "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2)
        return gt

    # 13. Meeting Minutes (TXT)
    def _gen_meeting_minutes_txt(self, out_dir: str) -> Dict[str, Any]:
        att1 = self.random_person(titled=False)
        att2 = self.random_person(titled=False)
        att3 = self.random_person(titled=False)
        filename = "meeting_minutes.txt"
        filepath = os.path.join(out_dir, filename)

        entities = [
            {"entity": "PERSON_NAME", "text": att1["full_name"], "has_context": False},
            {"entity": "PERSON_NAME", "text": att2["full_name"], "has_context": False},
            {"entity": "PERSON_NAME", "text": att3["full_name"], "has_context": False}
        ]
        must_not_redact = ["Board Risk Committee", "Q3 2024 Strategic Review", "Action Item 3.1"]

        content = f"""Board Risk Committee - Meeting Minutes
Session: Q3 2024 Strategic Review
Date: October 10, 2024

Attendees:
- {att1['full_name']}
- {att2['full_name']}
- {att3['full_name']}

Discussion Notes:
Reviewed capital adequacy framework. Action Item 3.1 assigned to committee leads.
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        gt = {"filename": filename, "format": "TXT", "source": "native", "entities": entities, "must_not_redact": must_not_redact}
        with open(os.path.join(out_dir, f"{filename}.json"), "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2)
        return gt

    # 14. Chat Transcript (TXT)
    def _gen_chat_transcript_txt(self, out_dir: str) -> Dict[str, Any]:
        speaker = self.random_person(titled=False)
        phone = self.generate_phone()
        filename = "chat_transcript.txt"
        filepath = os.path.join(out_dir, filename)

        entities = [
            {"entity": "PERSON_NAME", "text": speaker["full_name"], "has_context": False},
            {"entity": "PHONE_NUMBER", "text": phone, "has_context": False}
        ]
        must_not_redact = ["10:14 AM", "10:15 AM", "Sprint 42", "jira.example.internal"]

        content = f"""[10:14 AM] {speaker['full_name']}: Morning team, updating Sprint 42 tasks on jira.example.internal.
[10:15 AM] Alex: Sounds good. Can someone ring me on {phone} once the build finishes?
[10:16 AM] {speaker['full_name']}: Sure, will do.
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        gt = {"filename": filename, "format": "TXT", "source": "native", "entities": entities, "must_not_redact": must_not_redact}
        with open(os.path.join(out_dir, f"{filename}.json"), "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2)
        return gt

    # 15. Sales Receipt (TXT)
    def _gen_sales_receipt_txt(self, out_dir: str) -> Dict[str, Any]:
        cust = self.random_person(titled=False)
        card_last4 = f"{self.rng.randint(1000,9999)}"
        filename = "sales_receipt.txt"
        filepath = os.path.join(out_dir, filename)

        entities = [
            {"entity": "PERSON_NAME", "text": cust["full_name"], "has_context": True},
            {"entity": "CREDIT_CARD", "text": f"Visa ending in {card_last4}", "has_context": True}
        ]
        must_not_redact = ["Subtotal: $45.00", "Tax: $3.82", "Total: $48.82", "Store #108"]

        content = f"""CUSTOMER RECEIPT - Store #108
Customer: {cust['full_name']}
Payment Method: Visa ending in {card_last4}
Auth Code: 994012

Subtotal: $45.00
Tax: $3.82
Total: $48.82
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        gt = {"filename": filename, "format": "TXT", "source": "native", "entities": entities, "must_not_redact": must_not_redact}
        with open(os.path.join(out_dir, f"{filename}.json"), "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2)
        return gt

    # 16. Slide Deck Notes (PPTX)
    def _gen_slide_deck_notes_pptx(self, out_dir: str) -> Dict[str, Any]:
        speaker = self.random_person(titled=False)
        phone = self.generate_phone()
        filename = "slide_deck_notes.pptx"
        filepath = os.path.join(out_dir, filename)

        entities = [
            {"entity": "PERSON_NAME", "text": speaker["full_name"], "has_context": True},
            {"entity": "PHONE_NUMBER", "text": phone, "has_context": True}
        ]
        must_not_redact = ["Confidential Strategy Briefing", "FY2025 Targets"]

        prs = Presentation()
        slide = prs.slides.add_slide(prs.slide_layouts[0])
        slide.shapes.title.text = "Confidential Strategy Briefing"
        slide.placeholders[1].text = "FY2025 Targets"

        notes_slide = slide.notes_slide
        text_frame = notes_slide.notes_text_frame
        text_frame.text = f"Presenter briefing notes: Co-presenter is {speaker['full_name']}. In case of audio failure, dial {phone}."

        prs.save(filepath)

        gt = {"filename": filename, "format": "PPTX", "source": "native", "entities": entities, "must_not_redact": must_not_redact}
        with open(os.path.join(out_dir, f"{filename}.json"), "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2)
        return gt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic generalization test corpus.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--split", type=str, default="dev", choices=["dev", "test", "fresh_test"], help="Dataset split")
    parser.add_argument("--out", type=str, default=None, help="Output directory")

    args = parser.parse_args()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    target_dir = args.out if args.out else os.path.join(base_dir, "data", args.split)

    generator = SyntheticCorpusGenerator(seed=args.seed)
    docs = generator.generate_all(target_dir)
    print(f"Successfully generated {len(docs)} documents in '{target_dir}' (Split: {args.split}, Seed: {args.seed})")
