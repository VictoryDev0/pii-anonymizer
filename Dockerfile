FROM python:3.12-slim

# tesseract = local OCR for scans and images, so processing stays entirely on this host.
# Without it only PDFs with a text layer can be handled.
# fonts-dejavu provides the font for the placeholder labels drawn on the bars.
RUN apt-get update && apt-get install -y --no-install-recommends \
        tesseract-ocr tesseract-ocr-deu tesseract-ocr-eng fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY anonymizer_service.py pii.py redact.py manage.py index.html ./

EXPOSE 8000
# EXACTLY ONE worker: finished files live in process memory (deliberately not on disk).
# With several workers a download can hit the wrong process and 404.
# Concurrency comes from threads; tesseract runs as a subprocess and does not block.
CMD ["gunicorn", "-b", "0.0.0.0:8000", "-w", "1", "--threads", "8", "--timeout", "600", \
     "--forwarded-allow-ips", "*", \
     "--access-logfile", "/data/access.log", \
     "--access-logformat", "%({x-forwarded-for}i)s %(t)s \"%(r)s\" %(s)s %(b)s \"%(a)s\"", \
     "anonymizer_service:app"]
