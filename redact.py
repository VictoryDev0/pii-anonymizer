"""
Redaction engines for PDF, raster images and SVG.

For PDFs with a text layer the redaction is real (PyMuPDF `apply_redactions`): the text under
the bar is removed from the document. Drawing a black rectangle on top (as pypdf/reportlab
would) leaves the text selectable and copyable.

Scanned pages and images are analysed with OCR (Tesseract, local) and the pixels are
overwritten; the output no longer contains the original text anywhere.
"""
import io
import os
import re

import fitz  # PyMuPDF
from PIL import Image, ImageDraw, ImageFilter, ImageFont, ImageOps

try:
    import pytesseract
    HAVE_OCR = True
except Exception:                                        # pragma: no cover
    pytesseract = None
    HAVE_OCR = False

OCR_LANG = os.environ.get("ANON_OCR_LANG", "deu+eng")
OCR_MIN_CONF = int(os.environ.get("ANON_OCR_MIN_CONF", "35"))
# Below this amount of extractable text a PDF page counts as a scan and goes to the OCR path.
TEXT_PAGE_MIN_CHARS = 25
SCAN_DPI = int(os.environ.get("ANON_SCAN_DPI", "200"))


# ---------------------------------------------------------------- Span → Box ----
def _lines_from_words(words):
    """words: [{text, box, line}] -> [(line_text, [(start, end, box), ...])]"""
    lines = {}
    for w in words:
        lines.setdefault(w["line"], []).append(w)
    out = []
    for key in sorted(lines):
        ws = lines[key]
        text, spans, pos = "", [], 0
        for i, w in enumerate(ws):
            if i:
                text += " "
                pos += 1
            spans.append((pos, pos + len(w["text"]), w["box"]))
            text += w["text"]
            pos += len(w["text"])
        out.append((text, spans))
    return out


def _hits_to_boxes(words, anon, extra_names=None):
    """Find PII line by line. Returns [(box, replacement, kind)], box = (x0,y0,x1,y1)."""
    result = []
    for text, spans in _lines_from_words(words):
        if not text.strip():
            continue
        for h in anon.find(text, extra_names):
            covered = [b for (s, e, b) in spans if s < h["end"] and e > h["start"]]
            if not covered:
                continue
            x0 = min(b[0] for b in covered)
            y0 = min(b[1] for b in covered)
            x1 = max(b[2] for b in covered)
            y1 = max(b[3] for b in covered)
            result.append(((x0, y0, x1, y1), h["replacement"], h["kind"]))
    return result


def _visual_lines(words, tol=0.6):
    """Group words from any source into visual lines by their vertical position on the page.

    Needed for filled-in forms: the field label sits in the scanned background (readable only
    via OCR) while the entered value lives in the text layer. Looked at separately, neither
    source sees "Geb.-Datum: 01.01.1970"; only after merging can the label-based rules fire.
    """
    if not words:
        return []
    ws = sorted(words, key=lambda w: (w["box"][1] + w["box"][3]) / 2)
    lines, cur = [], [ws[0]]
    cy = (ws[0]["box"][1] + ws[0]["box"][3]) / 2
    ch = max(4.0, ws[0]["box"][3] - ws[0]["box"][1])
    for w in ws[1:]:
        wy = (w["box"][1] + w["box"][3]) / 2
        if abs(wy - cy) <= ch * tol:
            cur.append(w)
        else:
            lines.append(cur)
            cur, cy = [w], wy
            ch = max(4.0, w["box"][3] - w["box"][1])
    lines.append(cur)
    out = []
    for i, ln in enumerate(lines):
        for w in sorted(ln, key=lambda w: w["box"][0]):
            out.append({**w, "line": ("v", i)})
    return out


def merge_sources(text_words, ocr_words):
    """Merge the text layer with those OCR words that have no counterpart there (i.e. exist
    only in the scan) into shared visual lines."""
    extra = [w for w in ocr_words if not any(_overlaps(w["box"], t["box"]) for t in text_words)]
    return _visual_lines(text_words + extra)


def _overlaps(a, b) -> bool:
    """Rough overlap of two boxes; detects the same hit coming from text layer and OCR."""
    ix = min(a[2], b[2]) - max(a[0], b[0])
    iy = min(a[3], b[3]) - max(a[1], b[1])
    if ix <= 0 or iy <= 0:
        return False
    inter = ix * iy
    small = min((a[2] - a[0]) * (a[3] - a[1]), (b[2] - b[0]) * (b[3] - b[1])) or 1
    return inter / small > 0.35


# ---------------------------------------------------------------- PDF ----
def _pdf_page_words(page):
    out = []
    for x0, y0, x1, y1, word, blk, line, _no in page.get_text("words"):
        if word.strip():
            out.append({"text": word, "box": (x0, y0, x1, y1), "line": (blk, line)})
    return out


RE_LABEL = re.compile(r"^\[([A-ZÄÖÜ-]+)[ -]?(\d*)\]$")


def short_label(label: str) -> str:
    """[PERSON 12] -> [P12], for narrow bars where the full placeholder does not fit."""
    m = RE_LABEL.match(label)
    return f"[{m.group(1)[0]}{m.group(2)}]" if m else label


def _draw_label(page, rect, label):
    """Center the placeholder inside the redacted area; fall back to the short form."""
    r = fitz.Rect(*rect)
    for text in (label, short_label(label)):
        size = min(9.0, max(3.6, r.height * 0.72))
        while size >= 3.6:
            if fitz.get_text_length(text, fontname="helv", fontsize=size) <= r.width - 1.5:
                page.insert_textbox(r, text, fontname="helv", fontsize=size,
                                    color=(1, 1, 1), align=fitz.TEXT_ALIGN_CENTER)
                return
            size -= 0.4


def redact_pdf(data: bytes, anon, extra_names=None, llm_hook=None, deep=True):
    """Return (pdf_bytes, info).

    `deep=True` additionally OCRs text pages, because reports regularly contain a text layer
    AND embedded photos/scans with names in them.
    `llm_hook(text) -> [names]` is optional (LLM assist).
    """
    src = fitz.open(stream=data, filetype="pdf")
    scanned_pages, boxes_total = 0, 0
    scale = 72.0 / SCAN_DPI

    # The optional LLM pass needs the full text once up front.
    if llm_hook:
        whole = "\n".join(p.get_text() for p in src)
        if len(whole.strip()) < TEXT_PAGE_MIN_CHARS * max(1, src.page_count) and HAVE_OCR:
            whole = "\n".join(_ocr_text(_render(p)) for p in src)
        extra_names = list(extra_names or []) + list(llm_hook(whole) or [])

    # --- phase 1: collect hits while the text is still in the document -----------------
    text_hits, scan_pages = {}, {}
    for page in src:
        words = _pdf_page_words(page)
        if len("".join(w["text"] for w in words)) >= TEXT_PAGE_MIN_CHARS:
            hits = _hits_to_boxes(words, anon, extra_names)
            if deep and HAVE_OCR:
                # Verification OCR catches names in embedded photos/scans. Hits already found
                # in the text layer are dropped by position; otherwise the same area would be
                # counted twice.
                ocr_raw = _ocr_words(_render(page))
                ocr = [{**w, "box": tuple(v * scale for v in w["box"])} for w in ocr_raw]
                candidates = _hits_to_boxes(ocr, anon, extra_names)
                # Second pass over both sources combined: catches form fields whose label is
                # in the scan and whose value is in the text layer.
                candidates += _hits_to_boxes(merge_sources(words, ocr), anon, extra_names)
                for box, label, kind in candidates:
                    if not any(_overlaps(box, h[0]) for h in hits):
                        hits.append((box, label, kind))
            text_hits[page.number] = hits
        else:
            scanned_pages += 1
            img, n = redact_image_obj(_render(page), anon, extra_names)
            buf = io.BytesIO()
            img.save(buf, format="PNG", optimize=True)
            scan_pages[page.number] = buf.getvalue()
            boxes_total += n

    # --- phase 2: real redaction on text pages ------------------------------------------
    for num, hits in text_hits.items():
        page = src[num]
        for box, _label, kind in hits:
            page.add_redact_annot(fitz.Rect(*box) + (-1, -1, 1, 1), fill=(0, 0, 0))
            anon.note(kind)
            boxes_total += 1
        if hits:
            page.apply_redactions()

    # --- phase 3: build the output document and draw placeholder labels -----------------
    out = fitz.open()
    for num in range(src.page_count):
        if num in scan_pages:
            rect = src[num].rect
            newp = out.new_page(width=rect.width, height=rect.height)
            newp.insert_image(newp.rect, stream=scan_pages[num])
        else:
            out.insert_pdf(src, from_page=num, to_page=num)
            for box, label, _kind in text_hits.get(num, []):
                _draw_label(out[-1], box, label)

    out.set_metadata({})
    try:
        out.del_xml_metadata()
    except Exception:
        pass
    res = out.tobytes(garbage=4, deflate=True, clean=True)
    info = {"pages": src.page_count, "scanned_pages": scanned_pages, "areas": boxes_total}
    src.close()
    out.close()
    return res, info


def _render(page):
    pm = page.get_pixmap(matrix=fitz.Matrix(SCAN_DPI / 72, SCAN_DPI / 72), alpha=False)
    return Image.open(io.BytesIO(pm.tobytes("png"))).convert("RGB")


# ---------------------------------------------------------------- images ----
# Below this width Tesseract reads small print unreliably (phone numbers and emails slip
# through). We OCR an upscaled copy and map the coordinates back; the output image keeps
# its original size.
OCR_MIN_WIDTH = int(os.environ.get("ANON_OCR_MIN_WIDTH", "1700"))


def _prep(img):
    """Grayscale + contrast stretch + light sharpening. Noticeably improves recall on grey
    fax/photocopy scans, where Tesseract otherwise misreads digits as letters."""
    g = ImageOps.autocontrast(img.convert("L"), cutoff=1)
    return g.filter(ImageFilter.UnsharpMask(radius=1.4, percent=140, threshold=2))


def _ocr_pass(src, factor, out, pass_id=0):
    d = pytesseract.image_to_data(src, lang=OCR_LANG, output_type=pytesseract.Output.DICT)
    for i, txt in enumerate(d["text"]):
        if not txt or not txt.strip():
            continue
        try:
            conf = float(d["conf"][i])
        except (TypeError, ValueError):
            conf = -1
        if conf < OCR_MIN_CONF:
            continue
        x, y, w, h = d["left"][i], d["top"][i], d["width"][i], d["height"][i]
        if factor != 1.0:
            x, y, w, h = x / factor, y / factor, w / factor, h / factor
        # Each pass returns all of its words; do not deduplicate here. Otherwise the second
        # pass loses a word mid-line and a multi-word hit like "Max Mustermann" falls apart.
        # Deduplication happens later on the finished areas (_overlaps).
        # pass_id is part of the line key; otherwise lines from both passes would merge
        # into meaningless mixed text.
        out.append({"text": txt, "box": (x, y, x + w, y + h),
                    "line": (pass_id, d["block_num"][i], d["par_num"][i], d["line_num"][i])})


def _ocr_words(img):
    if not HAVE_OCR:
        return []
    factor = 1.0
    src = img
    if img.width < OCR_MIN_WIDTH:
        factor = min(3.0, OCR_MIN_WIDTH / max(1, img.width))
        src = img.resize((int(img.width * factor), int(img.height * factor)), Image.LANCZOS)
    out = []
    _ocr_pass(_prep(src), factor, out, pass_id=0)
    # Second pass on the raw image: preprocessing usually helps but can erode thin type.
    # Whatever only this pass finds is added.
    _ocr_pass(src, factor, out, pass_id=1)
    return out


def _dedupe_boxes(hits):
    """Merge overlapping areas from the two OCR passes.

    Merging (instead of dropping one) matters: if one pass reads only "B.Sc.Max" and the
    other "B.Sc.Max Mustermann", the smaller box must not win, or the surname would stay
    visible. The union always covers both.
    """
    kept = []
    for box, label, kind in hits:
        for i, (kbox, klabel, kkind) in enumerate(kept):
            if _overlaps(box, kbox):
                kept[i] = ((min(box[0], kbox[0]), min(box[1], kbox[1]),
                            max(box[2], kbox[2]), max(box[3], kbox[3])),
                           klabel if len(klabel) >= len(label) else label, kkind)
                break
        else:
            kept.append((box, label, kind))
    return kept


def _ocr_text(img):
    if not HAVE_OCR:
        return ""
    try:
        return pytesseract.image_to_string(img, lang=OCR_LANG)
    except Exception:
        return ""


def _font(size):
    for p in ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
              "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
              "/System/Library/Fonts/Helvetica.ttc"):
        if os.path.exists(p):
            try:
                return ImageFont.truetype(p, size)
            except Exception:
                continue
    return ImageFont.load_default()


def redact_image_obj(img: Image.Image, anon, extra_names=None):
    """Black out PII areas directly in the pixels. Returns (image, count)."""
    words = _ocr_words(img)
    hits = _dedupe_boxes(_hits_to_boxes(words, anon, extra_names))
    if not hits:
        return img, 0
    draw = ImageDraw.Draw(img)
    for (x0, y0, x1, y1), label, kind in hits:
        anon.note(kind)
        pad = max(2, int((y1 - y0) * 0.12))
        box = (x0 - pad, y0 - pad, x1 + pad, y1 + pad)
        draw.rectangle(box, fill=(0, 0, 0))
        h, w = box[3] - box[1], box[2] - box[0]
        f = _font(max(9, int(h * 0.68)))
        for text in (label, short_label(label)):
            try:
                tw = draw.textlength(text, font=f)
            except Exception:
                tw = len(text) * h * 0.5
            if tw <= w - 4:
                draw.text((box[0] + (w - tw) / 2, box[1] + h * 0.12),
                          text, fill=(255, 255, 255), font=f)
                break
    return img, len(hits)


def redact_image(data: bytes, anon, extra_names=None, llm_hook=None, fmt=None):
    img = Image.open(io.BytesIO(data))
    img = img.convert("RGB") if img.mode not in ("RGB", "L") else img.convert("RGB")
    if llm_hook:
        extra_names = list(extra_names or []) + list(llm_hook(_ocr_text(img)) or [])
    img, n = redact_image_obj(img, anon, extra_names)
    buf = io.BytesIO()
    fmt = (fmt or "PNG").upper()
    if fmt in ("JPG", "JPEG"):
        img.save(buf, format="JPEG", quality=92, optimize=True)   # no EXIF
    else:
        img.save(buf, format="PNG", optimize=True)                # no metadata
    return buf.getvalue(), {"areas": n, "ocr": HAVE_OCR}


# ---------------------------------------------------------------- SVG ----
RE_SVG_TEXT = re.compile(r"(>)([^<>]+)(<)")
RE_SVG_META = re.compile(r"<(metadata|desc|title)\b.*?</\1>", re.S | re.I)


def redact_svg(data: bytes, anon, extra_names=None, llm_hook=None):
    """SVG text is real text in the XML, so it is replaced rather than covered."""
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        s = data.decode("latin-1")
    s = RE_SVG_META.sub("", s)

    if llm_hook:
        plain = " ".join(m.group(2) for m in RE_SVG_TEXT.finditer(s))
        extra_names = list(extra_names or []) + list(llm_hook(plain) or [])

    n = [0]

    def repl(m):
        inner = m.group(2)
        if not inner.strip() or len(inner.strip()) < 2:
            return m.group(0)
        new = anon.apply_to_text(inner, extra_names)
        if new != inner:
            n[0] += 1
        return m.group(1) + new + m.group(3)

    s = RE_SVG_TEXT.sub(repl, s)
    return s.encode("utf-8"), {"areas": n[0]}


# ---------------------------------------------------------------- Dispatcher ----
IMAGE_EXT = {"png", "jpg", "jpeg", "webp", "tif", "tiff", "bmp", "gif"}


def process(filename: str, data: bytes, anon, llm_hook=None):
    ext = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()
    if ext == "pdf":
        out, info = redact_pdf(data, anon, llm_hook=llm_hook)
        return out, "application/pdf", _out_name(filename, "pdf"), info
    if ext == "svg":
        out, info = redact_svg(data, anon, llm_hook=llm_hook)
        return out, "image/svg+xml", _out_name(filename, "svg"), info
    if ext in IMAGE_EXT:
        keep_jpeg = ext in ("jpg", "jpeg")
        out, info = redact_image(data, anon, llm_hook=llm_hook, fmt="JPEG" if keep_jpeg else "PNG")
        newext = "jpg" if keep_jpeg else "png"
        return out, f"image/{'jpeg' if keep_jpeg else 'png'}", _out_name(filename, newext), info
    raise ValueError(f"File type .{ext} is not supported")


def _out_name(filename: str, ext: str) -> str:
    base = filename.rsplit("/", 1)[-1]
    base = base.rsplit(".", 1)[0] if "." in base else base
    base = re.sub(r"[^A-Za-z0-9_.-]", "_", base)[:60]
    return f"{base}_anonymized.{ext}"
