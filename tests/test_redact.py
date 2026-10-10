"""End-to-end redaction tests on generated documents. All data is fictitious."""
import fitz
import pytest

import redact
from pii import Anonymizer

SAMPLE = [
    "Gutachten Nr. 2026-001",
    "Auftraggeber: Erika Musterfrau",
    "Musterstraße 12, 10115 Berlin",
    "Telefon 030 12345678",
    "E-Mail erika@example.com",
    "Reparaturkosten netto 1.234,56 EUR",
]


def make_pdf():
    doc = fitz.open()
    page = doc.new_page()
    for i, line in enumerate(SAMPLE):
        page.insert_text((72, 90 + i * 20), line, fontsize=11)
    doc.set_metadata({"author": "Erika Musterfrau"})
    data = doc.tobytes()
    doc.close()
    return data


def test_pdf_text_is_really_removed():
    out, info = redact.redact_pdf(make_pdf(), Anonymizer(), deep=False)
    doc = fitz.open(stream=out, filetype="pdf")
    text = doc[0].get_text()
    for secret in ("Musterfrau", "Musterstraße", "12345678", "erika@example.com"):
        assert secret not in text
    assert "10115 Berlin" in text
    assert "1.234,56" in text
    assert not (doc.metadata or {}).get("author")
    assert info["areas"] >= 4


def test_svg_text_replaced_and_metadata_dropped():
    svg = (b'<svg xmlns="http://www.w3.org/2000/svg"><title>Erika Musterfrau</title>'
           b'<text x="0" y="10">Herr Max Mustermann</text></svg>')
    out, info = redact.redact_svg(svg, Anonymizer())
    assert b"Mustermann" not in out and b"<title>" not in out
    assert info["areas"] == 1


def test_short_label():
    assert redact.short_label("[PERSON 12]") == "[P12]"


def test_unsupported_extension():
    with pytest.raises(ValueError):
        redact.process("notes.docx", b"x", Anonymizer())


def test_out_name_is_sanitized():
    assert redact._out_name("../../evil name.pdf", "pdf") == "evil_name_anonymized.pdf"
