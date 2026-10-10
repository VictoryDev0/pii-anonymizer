"""Smoke tests for the Flask service (auth flow + upload)."""
import io

import fitz
import pytest


@pytest.fixture()
def client(monkeypatch):
    import anonymizer_service as svc
    monkeypatch.setattr(svc, "COOKIE_SECURE", False)
    svc.app.config["TESTING"] = True
    token = svc.add_client("Test Tenant", "secret-pw")
    return svc.app.test_client(), token


def test_login_and_anonymize(client):
    c, token = client
    assert c.get(f"/c/{token}").status_code == 200
    assert c.post(f"/c/{token}/login", data={"pw": "wrong"}).status_code == 401
    r = c.post(f"/c/{token}/login", data={"pw": "secret-pw"})
    assert r.status_code == 302

    doc = fitz.open()
    doc.new_page().insert_text((72, 90), "Herr Max Mustermann, max@example.com", fontsize=11)
    pdf = doc.tobytes()
    r = c.post("/api/anonymize", data={"token": token, "files": (io.BytesIO(pdf), "a.pdf")},
               content_type="multipart/form-data")
    assert r.status_code == 200, r.json
    body = r.json
    assert body["report"]["total"] >= 2
    dl = c.get(f"/d/{body['job']}/0")
    assert dl.status_code == 200
    assert b"Mustermann" not in fitz.open(stream=dl.data, filetype="pdf")[0].get_text().encode()


def test_anonymize_requires_login(client):
    c, token = client
    r = c.post("/api/anonymize", data={"token": token})
    assert r.status_code == 403
