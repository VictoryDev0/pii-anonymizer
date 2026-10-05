"""
PII detection and masking for German business documents (focus: vehicle claims and
expert reports, but the rules are generic enough for most German paperwork).

Pure functions, no IO, so the same logic is testable and shared by the PDF, image and SVG paths.

Core idea: `Anonymizer.find(text)` returns hits as (start, end, kind, replacement). The redaction
engines map these character spans onto bounding boxes (PDF words or OCR words) and black them out.

Partial anonymization by design:
  - persons       -> consistent placeholders [PERSON 1], [PERSON 2] ... (stable across a batch)
  - licence plate -> B-XY 1234E  ->  B-XX ####E   (city code and E/H suffix are kept)
  - VIN           -> only the last 4 characters are kept
  - address       -> street + house number removed, postcode + city kept
  - amounts, dates, technical text -> left unchanged
"""
import re
import unicodedata

# ---------------------------------------------------------------- character classes ----
U = "A-ZÄÖÜ"
L = "a-zäöüß"
NAME_PART = rf"[{U}][{L}]+(?:[-'][{U}]?[{L}]+)*"

# ---------------------------------------------------------------- first-name list ----
# Compact list of common first names in Germany (DE/TR/RU/AR/PL). Catches free-standing
# names without a salutation. Kept small on purpose: only matches when a surname follows.
FIRST_NAMES = set("""
andreas anna anne annette antonio arda armin arthur aylin ayse barbara bastian
benjamin bernd birgit bjoern boris brigitte bruno burak carmen caroline christian christiane
christina christoph claudia clemens daniel daniela david deniz dennis dieter dirk dominik dora
dorothea eberhard edith elena elif elisabeth elke emil emine emma emre enes erdal erhan erik
erkan ernst esra eva fabian fatih fatma felix ferdinand florian frank franziska friedrich fritz
gabriele georg gerd gerhard gisela goran guenter guido gunnar hakan hamza hanna hannah hans
harald hasan heiko heike heinrich heinz helga helmut henning herbert hermann hilde hubert hueseyin
ibrahim igor ilona ines ingo ingrid irina irmgard isabel ismail jan jana jasmin jens jessica joachim
johann johanna johannes jonas josef juergen julia julian juliane jutta kai karin karl karsten
katharina kathrin katja kerstin kevin klaus konstantin kurt lars laura lena leon leonie lisa lothar
luca lucas ludwig luis lukas maik maike manfred manuel marc marcel marco margarete maria marie
marina mario marion mark markus marlene martin martina mathias matthias max maximilian mehmet melanie
melis melissa michael michaela michel mike milan mirko miriam monika murat mustafa nadine natalia
natascha nicole niklas nils norbert olaf oliver omar orhan oskar osman ozan patrick paul peter petra
philipp pia rainer ralf ramazan rebecca regina reinhard renate rene ricardo richard rita robert
roland rolf ronald rosa rudolf ruediger ruslan sabine sabrina sandra sarah sascha sebastian selin
serkan sergej silke silvia simon sonja sophia sophie stefan stefanie stephan stephanie sven svenja
tanja tatjana theo thomas tim timo tobias tolga torsten udo ulf ulrich ulrike ursula uwe vadim
valentin vera veronika viktor vladimir volker walter werner wilhelm wolfgang yasemin yusuf yvonne
zeynep
""".split())

# Words that are never a name (suppress false positives in technical text)
STOPWORDS = set("""
gutachten schaden fahrzeug halter versicherung kalkulation reparatur werkstatt kosten betrag summe
netto brutto mehrwertsteuer umsatzsteuer wertminderung nutzungsausfall abtretung honorar rechnung
sachverstaendiger sachverständiger ingenieur diplom herstellung erstzulassung laufleistung typ modell
mercedes benz volkswagen audi bmw opel ford renault peugeot citroen skoda seat toyota nissan mazda
hyundai kia volvo porsche tesla fiat dacia mitsubishi suzuki honda jeep land rover mini smart
berlin hamburg muenchen münchen koeln köln frankfurt stuttgart duesseldorf düsseldorf leipzig dresden
bremen hannover nuernberg nürnberg essen dortmund bochum wuppertal bielefeld bonn muenster münster
januar februar maerz märz april mai juni juli august september oktober november dezember
montag dienstag mittwoch donnerstag freitag samstag sonntag
strasse straße platz weg allee damm gasse ring ufer chaussee nord sued süd ost west
seite anlage position pos stueck stück stunde stunden arbeitswert arbeitswerte lackierung
front heck links rechts vorne hinten oben unten aussen außen innen
gmbh mbh kg ohg ag ug haftungsbeschraenkt haftungsbeschränkt eingetragen amtsgericht
herr herrn frau hr fr dr prof dipl ing bsc msc med rer nat jur firma familie fam
""".split())

# ---------------------------------------------------------------- patterns ----
# Order = priority. Earlier hits win on overlap.
PATTERNS = [
    # --- unambiguous identifiers ----------------------------------------------------
    # Date of birth FIRST: ordinary dates are deliberately kept (date of loss, first
    # registration, appointments), but a date of birth is personal data and must go.
    # It is detected only via the field label, never via the date format.
    # `da[a-zä]*` instead of "datum": OCR regularly misreads the label on forms
    # ("Geb.-Daum", "Geb.-Dat.").
    ("gebdatum", re.compile(
        r"(?i:\b(?:geb\.?[- ]?da[a-zä]*\.?|geburtstag|geboren(?:[ \t]+am)?|geb\.[ \t]*am))"
        r"[ \t]*:?[ \t]*(?:[|_\-]*[ \t]*)?(\d{1,2}\.[ \t]?\d{1,2}\.[ \t]?\d{2,4})")),
    ("email",   re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("iban",    re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b")),
    # The BIC is part of the bank details; keeping it while the IBAN is redacted would be
    # inconsistent. Two routes: via the field label and via the German BIC pattern.
    ("bic",     re.compile(r"(?i:\bBIC(?:[- ]?Code)?)[ \t]*:?[ \t]*([A-Z]{4}[A-Z0-9]{4,7})")),
    ("bic",     re.compile(r"\b[A-Z]{4}DE[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")),
    ("vin",     re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")),
    ("phone",   re.compile(r"(?<![\d/])(?:\+49[ /-]?|0)(?:\d[ /-]?){6,13}\d(?![\d/])")),
    ("steuer",  re.compile(r"\b(?:DE\d{9}|\d{2,3}/\d{3}/\d{4,5})\b")),
    # Second, format-independent rule via the field label: in footers OCR regularly drops a
    # slash ("12345/67890" read as "1234567890"), which defeats the format pattern above.
    ("steuer",  re.compile(
        r"(?i:\b(?:steuer[- ]?nr\.?|st\.?[- ]?nr\.?|ust[- ]?id[- ]?nr\.?"
        r"|umsatzsteuer[- ]?id(?:entifikationsnummer)?))[ \t]*:?[ \t]*([A-Z0-9][A-Z0-9./-]{4,})")),
    # --- numbers with a context label -----------------------------------------------
    # The i-flag applies ONLY to the label word on purpose; otherwise the value part would
    # also become case-insensitive and eat through ordinary running text.
    # Placed before the plate rule: values like "AB-2026-0042" would otherwise be half-claimed
    # as a licence plate.
    ("caseno",  re.compile(
        r"(?i:\b(?:schaden(?:s)?[- ]?(?:nummer|nr\.?)|versicherungsschein[- ]?(?:nummer|nr\.?)"
        r"|vorgangs[- ]?(?:nummer|nr\.?)|akten[- ]?zeichen|az\.?|gutachten[- ]?(?:nummer|nr\.?)"
        r"|kunden[- ]?(?:nummer|nr\.?)|policen[- ]?(?:nummer|nr\.?)))[ \t]*:?[ \t]*([A-Z0-9][A-Z0-9./\-]{3,})")),
    # Licence plate: must not be followed by / or . plus digit (otherwise it bites into dates
    # and inspection deadlines such as "HU 05/2027").
    ("plate",   re.compile(rf"\b[{U}]{{1,3}}[- ]?[{U}]{{1,2}}[- ]?\d{{1,4}}[ ]?[EH]?\b(?![/.]?\d)")),

    # --- address: street + house number (postcode/city are kept) ---------------------
    # All patterns stay within one line on purpose ([ \t] instead of \s); otherwise a hit
    # swallows the line break and drags following lines along.
    # The street word is sometimes a suffix ("Musterstraße 12"), sometimes a separate
    # capitalized word ("Beispieler Chaussee 7"), hence (?i:...) around the alternation.
    ("street",  re.compile(
        rf"\b{NAME_PART}(?:[ \t]{NAME_PART})?[ \t]*"
        rf"(?i:stra(?:ß|ss)e|str\.|weg|allee|platz|damm|gasse|ring|ufer|chaussee|pfad|steig|hof)"
        rf"[ \t]+\d{{1,4}}[ \t]?[a-zA-Z]?\b")),
    ("street",  re.compile(
        rf"\b{NAME_PART}(?i:stra(?:ß|ss)e|str\.|weg|allee|platz|damm|gasse|ring|ufer|chaussee)"
        rf"[ \t]+\d{{1,4}}[ \t]?[a-zA-Z]?\b")),

    # --- persons: salutation / title -------------------------------------------------
    # Space after the title is optional: letterheads often read "B.Sc.Max Mustermann" without one.
    ("person",  re.compile(
        rf"(?:Herrn?|Frau|Hr\.|Fr\.|Dr\.|Prof\.|Dipl\.-Ing\.|B\.Sc\.|M\.Sc\.|B\.Eng\.)[ \t]*"
        rf"(?:(?:Dr|Prof|med|rer|nat|jur|Ing)\.[- ]?)*"
        rf"({NAME_PART}(?:[ \t]+{NAME_PART}){{0,2}})")),

    # --- persons: field label --------------------------------------------------------
    ("person",  re.compile(
        r"(?i:\b(?:auftraggeber|gesch(?:ä|ae)digte(?:r|)|gesch(?:ä|ae)digten|halter(?:in)?|fahrer(?:in)?"
        r"|versicherungsnehmer(?:in)?|sch(?:ä|ae)diger|eigent(?:ü|ue)mer(?:in)?|mandant(?:in)?"
        r"|kunde|kundin|name|nachname|vorname|antragsteller(?:in)?|zeuge|zeugin|unterschrift))"
        rf"[ \t]*:?[ \t]*({NAME_PART}(?:[ \t]+{NAME_PART}){{1,2}})")),
]

# Free-standing first name + surname (only if the first name is in the list)
RE_NAMEPAIR = re.compile(rf"\b({NAME_PART})[ \t]+({NAME_PART}(?:[ \t]+{NAME_PART})?)\b")


def _norm(w: str) -> str:
    """Lowercase without diacritics, for matching against the word lists."""
    w = unicodedata.normalize("NFKD", w.lower())
    w = "".join(c for c in w if not unicodedata.combining(c))
    return w.replace("ß", "ss")


# Abbreviations the plate pattern would otherwise catch by mistake (HU 05/2027, AW 12, DIN 1234)
PLATE_BLOCK = {"din", "iso", "vin", "kfz", "hu", "au", "aw", "mwst", "ust", "ez", "km", "ps",
               "kw", "nr", "az", "pos", "stk", "abs", "art", "bgb", "stvo", "zpo", "eur", "usd"}


def _plausible_plate(s: str) -> bool:
    m = re.match(rf"^([{U}]{{1,3}})[- ]?([{U}]{{1,2}})[- ]?(\d{{1,4}})[ ]?([EH])?$", s.strip())
    if not m:
        return False
    city, letters, digits, _suf = m.groups()
    # Check the city code alone and city+letters: "HU 05" splits into city='H', letters='U';
    # only the combination exposes the abbreviation.
    if _norm(city) in PLATE_BLOCK or _norm(city + letters) in PLATE_BLOCK:
        return False
    return 1 <= len(digits) <= 4


class Anonymizer:
    """Holds the placeholder mapping so the same name gets the same label across the whole batch."""

    KIND_LABELS = {
        "person": "Name", "street": "Address", "email": "Email", "phone": "Phone",
        "iban": "Bank details", "bic": "Bank details", "vin": "VIN",
        "plate": "Licence plate", "caseno": "Case number", "steuer": "Tax number",
        "gebdatum": "Date of birth",
    }

    def __init__(self, keep_plate_city=True, keep_vin_tail=True):
        self.keep_plate_city = keep_plate_city
        self.keep_vin_tail = keep_vin_tail
        self._persons = {}      # normalized name -> "[PERSON n]"
        self._by_kind = {}      # kind -> {value: placeholder}
        self.counts = {}

    # ---------------------------------------------------------------- replacements ----
    def _person_label(self, raw: str) -> str:
        key = _norm(re.sub(r"\s+", " ", raw.strip()))
        if key not in self._persons:
            self._persons[key] = f"[PERSON {len(self._persons) + 1}]"
        return self._persons[key]

    def _generic_label(self, kind: str, raw: str) -> str:
        d = self._by_kind.setdefault(kind, {})
        key = _norm(raw)
        if key not in d:
            tag = {"email": "EMAIL", "phone": "PHONE", "iban": "IBAN", "bic": "BIC",
                   "caseno": "CASE", "steuer": "TAX-ID", "street": "ADDRESS",
                   "gebdatum": "DOB"}.get(kind, kind.upper())
            d[key] = f"[{tag} {len(d) + 1}]"
        return d[key]

    # Mask characters are ASCII on purpose: the PDF base-14 fonts render characters such as
    # a bullet as "?".
    def _mask_plate(self, raw: str) -> str:
        m = re.match(rf"^([{U}]{{1,3}})([- ]?)([{U}]{{1,2}})([- ]?)(\d{{1,4}})([ ]?)([EH])?$", raw.strip())
        if not m:
            return "[PLATE]"
        city, s1, letters, s2, digits, s3, suf = m.groups()
        if not self.keep_plate_city:
            city = "X" * len(city)
        return f"{city}{s1}{'X' * len(letters)}{s2}{'#' * len(digits)}{s3 or ''}{suf or ''}"

    def _mask_vin(self, raw: str) -> str:
        return ("#" * 13 + raw[-4:]) if self.keep_vin_tail else "[VIN]"

    def replacement(self, kind: str, raw: str) -> str:
        if kind == "person":
            return self._person_label(raw)
        if kind == "plate":
            return self._mask_plate(raw)
        if kind == "vin":
            return self._mask_vin(raw)
        return self._generic_label(kind, raw)

    # ---------------------------------------------------------------- detection ----
    def find(self, text: str, extra_names=None):
        """Find PII in `text`. Returns a list of dicts with start/end/kind/raw/replacement.

        `extra_names`: additional names (e.g. from the optional LLM pass) that are treated
        as persons even when no rule matches.
        """
        hits = []
        taken = [False] * (len(text) + 1)

        def claim(a, b, kind, raw):
            if a < 0 or b > len(text) or b <= a:
                return
            if any(taken[a:b]):
                return
            for i in range(a, b):
                taken[i] = True
            hits.append({"start": a, "end": b, "kind": kind, "raw": raw,
                         "replacement": self.replacement(kind, raw)})

        # 1) extra names first; they are explicitly confirmed
        for name in sorted(extra_names or [], key=len, reverse=True):
            name = name.strip()
            if len(name) < 3:
                continue
            for m in re.finditer(re.escape(name), text):
                claim(m.start(), m.end(), "person", name)

        # 2) rules in priority order
        for kind, rx in PATTERNS:
            for m in rx.finditer(text):
                # group 1 = the sensitive part (the label itself stays visible)
                if m.groups():
                    a, b, raw = m.start(1), m.end(1), m.group(1)
                else:
                    a, b, raw = m.start(), m.end(), m.group(0)
                if kind == "plate" and not _plausible_plate(raw):
                    continue
                if kind == "person" and any(_norm(p) in STOPWORDS for p in raw.split()):
                    continue
                if kind == "phone" and len(re.sub(r"\D", "", raw)) < 7:
                    continue
                claim(a, b, kind, raw)

        # 3) free-standing first name + surname
        for m in RE_NAMEPAIR.finditer(text):
            first, rest = m.group(1), m.group(2)
            if _norm(first) in FIRST_NAMES and not any(_norm(p) in STOPWORDS for p in rest.split()):
                claim(m.start(), m.end(), "person", m.group(0))

        hits.sort(key=lambda h: h["start"])
        return hits

    # ---------------------------------------------------------------- report ----
    def note(self, kind: str):
        """Count one area that was actually redacted.

        Kept separate from `find()` on purpose: in PDFs the same hit is found twice (text
        layer + verification OCR) but redacted once. We count what ends up visible.
        """
        self.counts[kind] = self.counts.get(kind, 0) + 1

    def apply_to_text(self, text: str, extra_names=None, count=True) -> str:
        """Replace PII in plain text (used for SVG and text previews)."""
        hits = self.find(text, extra_names)
        out, last = [], 0
        for h in hits:
            out.append(text[last:h["start"]])
            out.append(h["replacement"])
            last = h["end"]
            if count:
                self.note(h["kind"])
        out.append(text[last:])
        return "".join(out)

    def report(self):
        return {
            "total": sum(self.counts.values()),
            "by_kind": {self.KIND_LABELS.get(k, k): v for k, v in sorted(self.counts.items())},
            "persons": len(self._persons),
        }
