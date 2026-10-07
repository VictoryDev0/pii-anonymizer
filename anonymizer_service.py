"""
PII anonymizer: web service that redacts personal data in PDFs, images and SVGs.

Privacy principle: **originals are never written to disk.** Processing happens in memory,
results stay in memory for at most RESULT_TTL seconds and are then discarded. Only metadata
is logged (timestamp, tenant, file count, hit counts), never file names or contents.

Routes
  GET  /                      Landing page (access only via personal tenant link)
  GET  /c/<token>             Tenant access (login form, then the app)
  POST /c/<token>/login       Check password -> signed session cookie
  POST /api/anonymize         Upload (multipart, multiple files) -> job with report
  GET  /d/<job>/<idx>         Single anonymized file
  GET  /zip/<job>             All files of a job as ZIP
  POST /api/forget/<job>      Drop a job's results immediately
  GET  /admin                 Create/delete tenants (admin password)
  GET  /health
  GET  /api/monitor/activity  Usage summary for an external monitoring dashboard
"""
import hashlib
import hmac
import html
import io
import json
import os
import pathlib
import re
import secrets
import threading
import time
import zipfile
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, redirect, request, send_file

import redact
from pii import Anonymizer

HERE = pathlib.Path(__file__).resolve().parent
DATA = pathlib.Path(os.environ.get("DATA_DIR", "/data"))
DATA.mkdir(parents=True, exist_ok=True)

MAX_MB = int(os.environ.get("ANON_MAX_MB", "80"))
RESULT_TTL = int(os.environ.get("ANON_RESULT_TTL", "1800"))       # 30 minutes
SESSION_TTL = int(os.environ.get("ANON_SESSION_TTL", "43200"))    # 12 hours
ADMIN_PASS = os.environ.get("ANON_ADMIN_PASS", "")
MONITOR_KEY = os.environ.get("ANON_MONITOR_KEY", "")
COOKIE_SECURE = os.environ.get("ANON_COOKIE_SECURE", "1") == "1"
TRUST_PROXY = os.environ.get("ANON_TRUST_PROXY", "0") == "1"
BRAND = os.environ.get("ANON_BRAND", "PII Anonymizer")

# Optional LLM assist: any OpenAI-compatible chat completions endpoint.
LLM_BASE_URL = os.environ.get(
    "ANON_LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai")
LLM_API_KEY = os.environ.get("ANON_LLM_API_KEY", "")
LLM_MODEL = os.environ.get("ANON_LLM_MODEL", "gemini-2.5-flash-lite")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_MB * 1024 * 1024

# ---------------------------------------------------------------- secret & tenants ----
_SECRET_F = DATA / "secret"
if not _SECRET_F.exists():
    _SECRET_F.write_text(secrets.token_hex(32))
    try:
        _SECRET_F.chmod(0o600)
    except Exception:
        pass
SECRET = _SECRET_F.read_text().strip().encode()

_CLIENTS_F = DATA / "clients.json"
_lock = threading.Lock()


def clients():
    if not _CLIENTS_F.exists():
        return {}
    try:
        return json.loads(_CLIENTS_F.read_text())
    except Exception:
        return {}


def save_clients(d):
    tmp = _CLIENTS_F.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=1, ensure_ascii=False))
    tmp.replace(_CLIENTS_F)


def pw_hash(pw: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), SECRET, 120_000).hex()


def add_client(name: str, pw: str) -> str:
    """Create a tenant and return its access token."""
    d = clients()
    token = secrets.token_urlsafe(9)
    d[token] = {"name": name, "pw": pw_hash(pw), "created": datetime.now(timezone.utc).isoformat()}
    save_clients(d)
    return token


# ---------------------------------------------------------------- session cookie ----
def make_cookie(token: str) -> str:
    exp = int(time.time()) + SESSION_TTL
    payload = f"{token}.{exp}"
    sig = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{payload}.{sig}"


def check_cookie(raw: str, token: str) -> bool:
    try:
        tok, exp, sig = raw.rsplit(".", 2)
    except (ValueError, AttributeError):
        return False
    if not hmac.compare_digest(tok, token):
        return False
    if int(exp) < time.time():
        return False
    good = hmac.new(SECRET, f"{tok}.{exp}".encode(), hashlib.sha256).hexdigest()[:32]
    return hmac.compare_digest(sig, good)


def authed(token: str) -> bool:
    return check_cookie(request.cookies.get("anon_s", ""), token)


# ---------------------------------------------------------------- brute-force brake ----
_fails = {}


def throttled(ip: str) -> bool:
    _n, until = _fails.get(ip, (0, 0))
    return time.time() < until


def note_fail(ip: str):
    n, _ = _fails.get(ip, (0, 0))
    n += 1
    _fails[ip] = (n, time.time() + (600 if n >= 8 else 0))


def client_ip() -> str:
    if TRUST_PROXY:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.remote_addr or ""


# ---------------------------------------------------------------- job store (RAM) ----
_jobs = {}


def gc_jobs():
    now = time.time()
    with _lock:
        for jid in [j for j, v in _jobs.items() if now - v["ts"] > RESULT_TTL]:
            _jobs.pop(jid, None)


def _gc_loop():
    while True:
        time.sleep(120)
        try:
            gc_jobs()
        except Exception:
            pass


threading.Thread(target=_gc_loop, daemon=True).start()

# ---------------------------------------------------------------- event log ----
_EVENTS_F = DATA / "events.jsonl"


def log_event(kind, client="", extra=None):
    """Log metadata only: never file names, never contents."""
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "kind": kind,
           "client": client, "ip": client_ip()[:45], "ua": request.headers.get("User-Agent", "")[:120]}
    if extra:
        rec.update(extra)
    try:
        with _EVENTS_F.open("a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def recent_events(n=25):
    if not _EVENTS_F.exists():
        return []
    try:
        lines = _EVENTS_F.read_text().splitlines()[-n:]
        return [json.loads(x) for x in lines if x.strip()]
    except Exception:
        return []


# ---------------------------------------------------------------- LLM assist (optional) ----
def llm_names_hook(text: str):
    """Ask an LLM for person names the rules missed.

    Only called when the user ticks the checkbox; then text content leaves the server
    towards the configured LLM provider. Without the checkbox this never happens.
    """
    if not LLM_API_KEY or not text or len(text.strip()) < 20:
        return []
    import urllib.request
    body = {
        "model": LLM_MODEL,
        "temperature": 0,
        "messages": [
            {"role": "system", "content":
             "You extract person names from German business documents. Reply with a JSON "
             "array of strings only. Include only names of natural persons, exactly as they "
             "appear in the text. NO companies, NO insurers, NO vehicle brands, NO places, "
             "NO authorities."},
            {"role": "user", "content": text[:120_000]},
        ],
    }
    req = urllib.request.Request(
        LLM_BASE_URL.rstrip("/") + "/chat/completions",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {LLM_API_KEY}"})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            out = json.loads(r.read().decode())
        content = out["choices"][0]["message"]["content"]
        m = re.search(r"\[.*\]", content, re.S)
        names = json.loads(m.group(0)) if m else []
        return [n for n in names if isinstance(n, str) and 2 < len(n) < 80]
    except Exception:
        return []


# ---------------------------------------------------------------- pages ----
def page(name):
    return (HERE / name).read_text(encoding="utf-8")


LOGIN_HTML = """<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Anonymizer - sign in</title>
<style>
body{margin:0;font:16px/1.6 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
background:linear-gradient(135deg,#16243a,#27406b);color:#1f2733;min-height:100vh;
display:flex;align-items:center;justify-content:center;padding:20px}
.box{background:#fff;border-radius:16px;padding:32px 30px;max-width:380px;width:100%;
box-shadow:0 18px 50px rgba(10,20,40,.35)}
h1{margin:0 0 4px;font-size:20px;color:#16243a}
p{margin:0 0 20px;color:#5b6675;font-size:14px}
input{width:100%;padding:12px 14px;border:1px solid #dfe4ec;border-radius:9px;font-size:16px;margin:0 0 12px}
button{width:100%;padding:12px;border:0;border-radius:9px;background:#16243a;color:#fff;
font-size:15px;font-weight:700;cursor:pointer}
button:hover{background:#27406b}
.err{background:#fbe7ea;border:1px solid #f1c3cb;color:#b2243a;border-radius:9px;
padding:9px 12px;font-size:13.5px;margin:0 0 14px}
.f{margin-top:16px;font-size:12px;color:#9aa3b0;text-align:center}
</style>
<div class="box">
  <h1>__TITLE__</h1>
  <p>Please enter your password.</p>
  __ERR__
  <form method="post" action="/c/__TOKEN__/login">
    <input type="password" name="pw" placeholder="Password" autofocus autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
  <div class="f">__BRAND__ · processed on this server only</div>
</div>"""


def _login(token, c, err="", status=200):
    return Response(LOGIN_HTML.replace("__TOKEN__", token)
                    .replace("__TITLE__", html.escape(c["name"]))
                    .replace("__BRAND__", html.escape(BRAND))
                    .replace("__ERR__", f"<div class='err'>{err}</div>" if err else ""),
                    status=status, mimetype="text/html")


@app.get("/")
def root():
    return Response(
        "<!doctype html><meta charset='utf-8'><title>Anonymizer</title>"
        "<div style=\"font:16px/1.6 -apple-system,sans-serif;max-width:520px;margin:16vh auto;"
        f"padding:0 22px;color:#1f2733\"><h1 style='color:#16243a'>{html.escape(BRAND)}</h1>"
        "<p>This service is only reachable through a personal access link. "
        "Please use the link you were given.</p></div>",
        mimetype="text/html")


@app.get("/health")
def health():
    return jsonify(ok=True, ocr=redact.HAVE_OCR, clients=len(clients()), jobs=len(_jobs))


@app.get("/c/<token>")
def client_page(token):
    c = clients().get(token)
    if not c:
        return Response("Access link not found.", status=404)
    if not authed(token):
        log_event("open_login", c["name"])
        return _login(token, c)
    log_event("open_app", c["name"])
    body = (page("index.html").replace("__TOKEN__", token)
            .replace("__CLIENT__", html.escape(c["name"])).replace("__BRAND__", html.escape(BRAND)))
    return Response(body, mimetype="text/html")


@app.post("/c/<token>/login")
def client_login(token):
    c = clients().get(token)
    if not c:
        return Response("Access link not found.", status=404)
    ip = client_ip()
    if throttled(ip):
        return _login(token, c, "Too many attempts. Please try again in 10 minutes.", 429)
    if not hmac.compare_digest(pw_hash(request.form.get("pw", "")), c["pw"]):
        note_fail(ip)
        log_event("login_fail", c["name"])
        return _login(token, c, "Wrong password.", 401)
    log_event("login_ok", c["name"])
    r = redirect(f"/c/{token}")
    r.set_cookie("anon_s", make_cookie(token), max_age=SESSION_TTL,
                 httponly=True, secure=COOKIE_SECURE, samesite="Lax")
    return r


# ---------------------------------------------------------------- processing ----
@app.post("/api/anonymize")
def api_anonymize():
    token = request.form.get("token", "")
    c = clients().get(token)
    if not c or not authed(token):
        return jsonify(error="not signed in"), 403

    files = request.files.getlist("files")
    if not files:
        return jsonify(error="no files"), 400

    use_llm = request.form.get("llm", "") == "1"
    keep_city = request.form.get("keep_city", "1") == "1"
    keep_vin = request.form.get("keep_vin", "1") == "1"
    hook = llm_names_hook if use_llm else None

    # One Anonymizer for the whole batch -> same name = same placeholder,
    # even across several documents.
    anon = Anonymizer(keep_plate_city=keep_city, keep_vin_tail=keep_vin)
    results, errors = [], []
    t0 = time.time()

    for f in files:
        name = f.filename or "file"
        try:
            data = f.read()
            if not data:
                errors.append({"file": name, "error": "empty file"})
                continue
            out, mime, outname, info = redact.process(name, data, anon, llm_hook=hook)
            results.append({"name": outname, "mime": mime, "bytes": out, "info": info})
        except ValueError as e:
            errors.append({"file": name, "error": str(e)})
        except Exception as e:                                   # pragma: no cover
            errors.append({"file": name, "error": f"processing failed ({type(e).__name__})"})
        finally:
            del f

    if not results:
        log_event("fail", c["name"], {"files": len(files)})
        return jsonify(error="No file could be processed.", details=errors), 422

    job = secrets.token_urlsafe(12)
    with _lock:
        _jobs[job] = {"ts": time.time(), "token": token, "files": results}
    gc_jobs()

    rep = anon.report()
    log_event("anonymize", c["name"], {
        "files": len(results), "hits": rep["total"], "persons": rep["persons"],
        "llm": use_llm, "seconds": round(time.time() - t0, 1)})

    return jsonify(
        job=job,
        files=[{"name": r["name"], "size": len(r["bytes"]), "info": r["info"]} for r in results],
        report=rep,
        errors=errors,
        expires_minutes=RESULT_TTL // 60,
        ocr=redact.HAVE_OCR)


GONE_HTML = """<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>No longer available</title>
<div style="font:16px/1.6 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
max-width:520px;margin:14vh auto;padding:0 22px;color:#1f2733">
<h1 style="color:#16243a;font-size:21px;margin:0 0 10px">This file is gone</h1>
<p>For privacy reasons anonymized files are deleted automatically <b>__TTL__ minutes</b> after
processing. After that the download link is invalid.</p>
<p>Just upload the source file again; it only takes a few seconds.</p>
<p style="margin-top:22px"><a href="__BACK__" style="display:inline-block;padding:11px 18px;
border-radius:9px;background:#16243a;color:#fff;text-decoration:none;font-weight:700">
Back to the anonymizer</a></p></div>"""


def _gone(token=""):
    return Response(GONE_HTML.replace("__BACK__", f"/c/{token}" if token else "/")
                    .replace("__TTL__", str(RESULT_TTL // 60)),
                    status=404, mimetype="text/html")


def _job_guard(job):
    gc_jobs()
    j = _jobs.get(job)
    if not j or not authed(j["token"]):
        return None
    return j


@app.get("/d/<job>/<int:idx>")
def download_one(job, idx):
    j = _job_guard(job)
    if not j or idx >= len(j["files"]):
        return _gone(request.cookies.get("anon_s", "").split(".")[0])
    f = j["files"][idx]
    return send_file(io.BytesIO(f["bytes"]), mimetype=f["mime"],
                     as_attachment=True, download_name=f["name"])


@app.get("/zip/<job>")
def download_zip(job):
    j = _job_guard(job)
    if not j:
        return _gone(request.cookies.get("anon_s", "").split(".")[0])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in j["files"]:
            z.writestr(f["name"], f["bytes"])
    buf.seek(0)
    return send_file(buf, mimetype="application/zip", as_attachment=True,
                     download_name="anonymized.zip")


@app.post("/api/forget/<job>")
def forget(job):
    with _lock:
        j = _jobs.get(job)
        if j and authed(j["token"]):
            _jobs.pop(job, None)
    return jsonify(ok=True)


# ---------------------------------------------------------------- admin ----
ADMIN_HTML = """<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Anonymizer - tenants</title>
<style>
body{font:15px/1.6 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#f5f7fa;
color:#1f2733;margin:0;padding:30px 22px}
.w{max-width:820px;margin:0 auto}
h1{color:#16243a;font-size:22px;margin:0 0 18px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;
box-shadow:0 1px 3px rgba(20,40,80,.08);font-size:14px;margin:0 0 22px}
th{background:#eaf0fb;color:#16243a;text-align:left;padding:9px 12px}
td{padding:9px 12px;border-bottom:1px solid #e7ebf1;vertical-align:middle}
input,button{font:inherit;padding:9px 12px;border-radius:8px;border:1px solid #dfe4ec}
button{background:#16243a;color:#fff;border:0;font-weight:700;cursor:pointer}
code{background:#f1f5f9;padding:2px 7px;border-radius:5px;font-size:12.5px;word-break:break-all}
.card{background:#fff;border-radius:12px;padding:18px 20px;box-shadow:0 1px 3px rgba(20,40,80,.08)}
</style><div class="w">
<h1>Manage tenants</h1>
__TABLE__
<div class="card"><b>Create tenant</b>
<form method="post" action="/admin/new" style="display:flex;gap:9px;margin-top:11px;flex-wrap:wrap">
  <input type="hidden" name="k" value="__K__">
  <input name="name" placeholder="Name (e.g. Example Claims Office)" required style="flex:2;min-width:200px">
  <input name="pw" placeholder="Password" required style="flex:1;min-width:150px">
  <button type="submit">Create</button>
</form></div></div>"""


def _admin_ok():
    return ADMIN_PASS and hmac.compare_digest(request.values.get("k", ""), ADMIN_PASS)


@app.get("/admin")
def admin():
    if not _admin_ok():
        return Response("forbidden", status=403)
    base = request.url_root.rstrip("/")
    k = html.escape(request.values.get("k", ""), quote=True)
    rows = ["<table><tr><th>Tenant</th><th>Link</th><th>Created</th><th></th></tr>"]
    for tok, c in sorted(clients().items(), key=lambda kv: kv[1].get("created", "")):
        rows.append(
            f"<tr><td><b>{html.escape(c['name'])}</b></td><td><code>{base}/c/{tok}</code></td>"
            f"<td>{c.get('created','')[:10]}</td>"
            f"<td><form method='post' action='/admin/del' onsubmit=\"return confirm('Delete tenant?')\">"
            f"<input type='hidden' name='k' value='{k}'>"
            f"<input type='hidden' name='token' value='{tok}'>"
            f"<button style='background:#b2243a'>Delete</button></form></td></tr>")
    rows.append("</table>")
    if len(rows) == 2:
        rows = ["<p style='color:#5b6675'>No tenants yet.</p>"]
    return Response(ADMIN_HTML.replace("__TABLE__", "".join(rows)).replace("__K__", k),
                    mimetype="text/html")


@app.post("/admin/new")
def admin_new():
    if not _admin_ok():
        return Response("forbidden", status=403)
    name = (request.form.get("name") or "").strip()[:60]
    pw = request.form.get("pw") or ""
    if not name or len(pw) < 4:
        return Response("Name and password (min. 4 characters) required.", status=400)
    add_client(name, pw)
    return redirect(f"/admin?k={request.form.get('k','')}")


@app.post("/admin/del")
def admin_del():
    if not _admin_ok():
        return Response("forbidden", status=403)
    d = clients()
    d.pop(request.form.get("token", ""), None)
    save_clients(d)
    return redirect(f"/admin?k={request.form.get('k','')}")


# ---------------------------------------------------------------- monitor ----
@app.get("/api/monitor/activity")
def monitor():
    """Usage summary (counts and timestamps only) for an external monitoring dashboard."""
    if not MONITOR_KEY:
        return jsonify(ok=False, error="not configured"), 503
    if not hmac.compare_digest(request.args.get("key", ""), MONITOR_KEY):
        return jsonify(ok=False, error="forbidden"), 401
    ev = recent_events(200)
    runs = [e for e in ev if e.get("kind") == "anonymize"]
    opens = [e for e in ev if e.get("kind") in ("open_app", "open_login")]
    last = ev[-1] if ev else None
    return jsonify(
        ok=True,
        total_events=len(ev),
        last_activity_ts=last["ts"] if last else None,
        files_processed=sum(r.get("files", 0) for r in runs),
        runs=len(runs),
        opens_total=len(opens),
        last_run=({"ts": runs[-1]["ts"], "files": runs[-1].get("files", 0),
                   "hits": runs[-1].get("hits", 0)} if runs else None),
        recent=ev[-12:])


@app.errorhandler(413)
def too_large(_e):
    return jsonify(error=f"File too large. The limit is {MAX_MB} MB per upload."), 413


if __name__ == "__main__":
    app.run(host=os.environ.get("ANON_BIND", "127.0.0.1"),
            port=int(os.environ.get("ANON_PORT", "8000")), debug=False)
