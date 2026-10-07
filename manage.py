"""
Small admin CLI for the anonymizer.

    python manage.py add-client "Example Claims Office" --pw "change-me"
    python manage.py list-clients

Inside the container:

    docker compose exec anonymizer python manage.py add-client "Example Office" --pw "..."

Uses the same DATA_DIR (secret + clients.json) as the running service.
"""
import argparse
import os

import anonymizer_service as svc


def main():
    ap = argparse.ArgumentParser(description="Manage anonymizer tenants")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add-client", help="create a tenant and print its access path")
    a.add_argument("name")
    a.add_argument("--pw", required=True)
    sub.add_parser("list-clients", help="list tenants")
    args = ap.parse_args()

    base = os.environ.get("ANON_PUBLIC_URL", "http://localhost:8000").rstrip("/")
    if args.cmd == "add-client":
        if len(args.pw) < 4:
            ap.error("password must have at least 4 characters")
        token = svc.add_client(args.name.strip()[:60], args.pw)
        print(f"{base}/c/{token}")
    else:
        for tok, c in svc.clients().items():
            print(f"{c.get('created', '')[:10]}  {c['name']:<40} {base}/c/{tok}")


if __name__ == "__main__":
    main()
