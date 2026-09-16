"""
Standalone BioTime connection diagnostic — bypasses the Flask app entirely.

Run directly using the project's venv (so `requests` is available):

    venv\\Scripts\\python diagnose_biotime.py https://biotime.example.com admin secret   (Windows)
    venv/bin/python diagnose_biotime.py https://biotime.example.com admin secret         (Linux)

Authenticates against BioTime's token endpoint and fetches one page of
transactions, printing the raw JSON so the real field/endpoint names for
your BioTime version can be confirmed before trusting them in the scheduled
sync (see app/services/biotime_service.py).
"""
import json
import sys

import requests

from app.services.biotime_service import TOKEN_ENDPOINT, TRANSACTIONS_ENDPOINT, _authenticate


def main(base_url, username, password):
    print(f"\n--- Authenticating against {base_url}{TOKEN_ENDPOINT} ---")
    try:
        token = _authenticate(base_url, username, password)
        print(f"AUTH: OK — token: {token[:12]}...")
    except Exception as e:
        print(f"AUTH: FAILED — {type(e).__name__}: {e}")
        return

    print(f"\n--- Fetching one page from {base_url}{TRANSACTIONS_ENDPOINT} ---")
    try:
        resp = requests.get(
            f"{base_url.rstrip('/')}{TRANSACTIONS_ENDPOINT}",
            headers={"Authorization": f"JWT {token}"},
            params={"page_size": 5},
            timeout=15,
        )
        print(f"HTTP {resp.status_code}")
        print(json.dumps(resp.json(), indent=2)[:4000])
    except Exception as e:
        print(f"FETCH: FAILED — {type(e).__name__}: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Usage: python {sys.argv[0]} <base_url> <username> <password>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3])
