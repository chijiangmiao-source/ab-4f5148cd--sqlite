#!/usr/bin/env python3
"""API/HTTP smoke for the archive snapshot review service.

Submits the valid multi-level snapshot and every crafted violation scenario
to a running service, checks the health endpoint, verifies that the HTML page
shows the same first-violation evidence as the JSON API, and confirms that a
failed review clears the previous success conclusion.

Exits 0 when every check passes, 1 otherwise.
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import fixtures  # noqa: E402
from app.fixtures import valid_snapshot  # noqa: E402

BASE = os.environ.get("AUDIT_BASE_URL", "http://127.0.0.1:8080")

_failures = []


def check(name, ok, extra=""):
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{extra}]" if extra and not ok else ""))
    if not ok:
        _failures.append(name)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def get(path):
    try:
        with urllib.request.urlopen(BASE + path, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def post_json(payload):
    req = urllib.request.Request(
        BASE + "/api/audit",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def post_form(fields):
    req = urllib.request.Request(
        BASE + "/",
        data=urllib.parse.urlencode(fields).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def main():
    print(f"smoke against {BASE}")
    try:
        status, body = get("/health")
    except urllib.error.URLError as exc:
        check("health endpoint", False, f"unreachable: {exc}")
        print("\n1 failure(s)")
        return 1
    ok = status == 200 and json.loads(body).get("status") == "ok"
    check("health endpoint", ok, f"status={status}")

    status, body = get("/")
    check("review page loads", status == 200 and b'audit-form' in body)

    # --- valid multi-level snapshot with a cross-page BLOB -----------------
    data, root = valid_snapshot()
    status, res = post_json({"snapshot_b64": b64(data), "root_page": root})
    check("valid snapshot accepted", status == 200 and res.get("verdict") == "accepted",
          f"status={status} error={res.get('error')}")
    pages = res.get("pages", [])
    owners = [p["page"] for p in pages]
    check("unique page ownership", len(owners) == len(set(owners)))
    kinds = {p["page"]: p["kind"] for p in pages}
    check(
        "overflow chain owned",
        kinds.get(6) == "overflow" and kinds.get(7) == "overflow"
        and res["summary"]["overflow_chains"] == 1,
        f"kinds={kinds}",
    )
    check(
        "rowid ranges reported",
        res["summary"].get("rowid_min") == 1 and res["summary"].get("rowid_max") == 12,
        f"summary={res.get('summary')}",
    )
    status, last = get("/api/audit/last")
    check("last verdict stored", status == 200 and json.loads(last)["verdict"] == "accepted")

    # --- crafted violations: API and page must show the same first evidence --
    scenarios = fixtures.invalid_scenarios()
    for name, (snap, root_page, code, page, offset) in scenarios.items():
        status, res = post_json({"snapshot_b64": b64(snap), "root_page": root_page})
        err = res.get("error") or {}
        ok = (
            status == 422
            and res.get("verdict") == "rejected"
            and err.get("code") == code
            and err.get("page") == page
            and err.get("offset") == offset
        )
        check(f"{name}: api rejects with first evidence", ok,
              f"status={status} err={err}")
        status, html_text = post_form(
            {"snapshot_b64": b64(snap), "root_page": str(root_page)}
        )
        ok = (
            status == 422
            and f'id="error-code"><code>{code}</code>' in html_text
            and f'id="error-page">{page}<' in html_text
            and f'id="error-offset">{offset}<' in html_text
        )
        check(f"{name}: page shows same evidence", ok, f"status={status}")

    # --- a failed review clears the earlier success conclusion -------------
    status, last = get("/api/audit/last")
    last = json.loads(last)
    check(
        "failed review cleared stored success",
        status == 200
        and last.get("verdict") == "rejected"
        and last["error"]["code"] == scenarios["bad_magic"][2],
        f"last={last.get('error')}",
    )

    print(f"\n{len(_failures)} failure(s)" if _failures else "\nall smoke checks passed")
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
