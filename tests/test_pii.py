"""Rule tests for pii.py. All names, numbers and addresses are fictitious."""
from pii import Anonymizer


def kinds(text, **kw):
    return [(h["kind"], h["raw"]) for h in Anonymizer(**kw).find(text)]


def test_salutation_person_gets_placeholder():
    a = Anonymizer()
    out = a.apply_to_text("Sehr geehrter Herr Mustermann, danke.")
    assert "Mustermann" not in out
    assert "[PERSON 1]" in out


def test_same_name_same_placeholder_across_calls():
    a = Anonymizer()
    first = a.apply_to_text("Halter: Erika Musterfrau")
    second = a.apply_to_text("Frau Erika Musterfrau ruft an.")
    assert "[PERSON 1]" in first and "[PERSON 1]" in second
    assert a.report()["persons"] == 1


def test_free_standing_known_first_name():
    assert ("person", "Thomas Beispiel") in kinds("Ansprechpartner ist Thomas Beispiel heute.")


def test_email_phone_iban():
    text = "Mail max@example.com, Tel. 030 12345678, IBAN DE89 3704 0044 0532 0130 00"
    found = dict((k, v) for k, v in kinds(text))
    assert found["email"] == "max@example.com"
    assert "12345678" in found["phone"]
    assert found["iban"].startswith("DE89")


def test_street_removed_postcode_city_kept():
    a = Anonymizer()
    out = a.apply_to_text("Musterstraße 12, 10115 Berlin")
    assert "Musterstraße" not in out
    assert "10115 Berlin" in out


def test_plate_keeps_city_and_suffix():
    a = Anonymizer()
    out = a.apply_to_text("Kennzeichen B-XY 1234E")
    assert "B-XX ####E" in out


def test_plate_city_can_be_masked():
    out = Anonymizer(keep_plate_city=False).apply_to_text("Kennzeichen B-XY 1234E")
    assert "X-XX ####E" in out


def test_inspection_date_is_not_a_plate():
    assert not any(k == "plate" for k, _ in kinds("Nächste HU 05/2027 fällig"))


def test_vin_keeps_last_four():
    out = Anonymizer().apply_to_text("FIN WVWZZZ1JZXW000001")
    assert "#############0001" in out


def test_dob_only_via_label():
    text = "Geb.-Datum: 01.01.1970, Schadentag 15.03.2026"
    found = kinds(text)
    assert ("gebdatum", "01.01.1970") in found
    assert not any(v == "15.03.2026" for _, v in found)


def test_amounts_and_stopwords_untouched():
    text = "Reparaturkosten netto 1.234,56 EUR, Mercedes Benz, Fahrzeug Halter Versicherung"
    assert Anonymizer().apply_to_text(text) == text


def test_tax_number_and_case_number():
    found = dict(kinds("Steuer-Nr. 12/345/67890, Schadennummer: AB-2026-0042"))
    assert found["steuer"] == "12/345/67890"
    assert found["caseno"] == "AB-2026-0042"


def test_extra_names_from_llm_hook():
    a = Anonymizer()
    out = a.apply_to_text("Zeugin war Quirina Zett aus dem Nachbarhaus.", extra_names=["Quirina Zett"])
    assert "Quirina" not in out
