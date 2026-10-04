"""HTTP service for archive snapshot review.

Endpoints
---------
GET  /                      reviewer web page
GET  /api/health            liveness probe
POST /api/verify            submit {snapshot: <base64>, root_page: <int>}
GET  /api/submission/<id>   fetch a stored verdict by submission id
GET  /view/<id>             reviewer page preloaded with a submission

Only the Python standard library is used.
"""

from __future__ import annotations

import base64
import binascii
import json
import threading
import time
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Tuple
from urllib.parse import urlparse

from .verifier import (MAX_SNAPSHOT_BYTES, verify_snapshot)

_MAX_BODY = int(MAX_SNAPSHOT_BYTES * 1.4) + 4096  # base64 overhead + JSON


class SubmissionStore:
    """Keeps recent verdicts so reviewers can re-open a submission."""

    def __init__(self, capacity: int = 64) -> None:
        self._lock = threading.Lock()
        self._items: Dict[str, dict] = {}
        self._order = []
        self._capacity = capacity

    def put(self, record: dict) -> str:
        sid = uuid.uuid4().hex
        record = dict(record)
        record["submission_id"] = sid
        with self._lock:
            self._items[sid] = record
            self._order.append(sid)
            for stale in self._order[:-self._capacity]:
                self._items.pop(stale, None)
            del self._order[:-self._capacity]
        return sid

    def get(self, sid: str) -> dict | None:
        with self._lock:
            rec = self._items.get(sid)
            return dict(rec) if rec else None


STORE = SubmissionStore()


def evaluate_payload(body: bytes) -> Tuple[dict, HTTPStatus]:
    try:
        req = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _error("BAD_JSON", "request body must be UTF-8 JSON",
                      HTTPStatus.BAD_REQUEST)
    if not isinstance(req, dict):
        return _error("BAD_REQUEST", "request must be a JSON object",
                      HTTPStatus.BAD_REQUEST)

    b64 = req.get("snapshot")
    if not isinstance(b64, str) or not b64:
        return _error("MISSING_SNAPSHOT",
                      "'snapshot' must be a non-empty Base64 string",
                      HTTPStatus.BAD_REQUEST)
    try:
        image = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        return _error("BAD_BASE64",
                      "'snapshot' is not valid Base64",
                      HTTPStatus.BAD_REQUEST)
    if not image:
        return _error("EMPTY_SNAPSHOT", "decoded snapshot is empty",
                      HTTPStatus.BAD_REQUEST)
    if len(image) > MAX_SNAPSHOT_BYTES:
        return _error("SNAPSHOT_TOO_LARGE",
                      f"snapshot is {len(image)} bytes; limit is "
                      f"{MAX_SNAPSHOT_BYTES} (512 KiB)",
                      HTTPStatus.REQUEST_ENTITY_TOO_LARGE)

    root = req.get("root_page")
    if isinstance(root, bool) or not isinstance(root, int):
        return _error("BAD_ROOT_PAGE",
                      "'root_page' must be an integer page number",
                      HTTPStatus.BAD_REQUEST)
    if root < 1:
        return _error("BAD_ROOT_PAGE",
                      "'root_page' must be >= 1", HTTPStatus.BAD_REQUEST)

    report = verify_snapshot(image, root)
    payload = {
        "submitted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "snapshot_bytes": len(image),
        "report": report.to_dict(),
    }
    sid = STORE.put(payload)
    payload["submission_id"] = sid
    status = HTTPStatus.OK if report.accepted else HTTPStatus.UNPROCESSABLE_ENTITY
    return payload, status


def _error(code: str, message: str, status: HTTPStatus) -> Tuple[dict, HTTPStatus]:
    return {
        "submission_id": None,
        "report": None,
        "error": {"code": code, "message": message},
    }, status


_PAGE_HTML = None  # loaded lazily from static file


def _page_html() -> bytes:
    global _PAGE_HTML
    if _PAGE_HTML is None:
        import pathlib
        _PAGE_HTML = (pathlib.Path(__file__).with_name("web")
                      .joinpath("index.html").read_bytes())
    return _PAGE_HTML


def _esc(text: object) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _ssr_summary(rec: dict) -> str:
    """Server-rendered evidence block so the first violation is visible and
    greppable without executing any JavaScript."""
    r = rec.get("report") or {}
    accepted = r.get("accepted")
    verdict = "ACCEPTED" if accepted else "REJECTED"
    cls = "ok" if accepted else "bad"
    parts = [
        f'<section class="card"><div class="verdict {cls}" '
        f'id="ssr-verdict" data-verdict="{verdict}">{verdict}</div>',
        '<div class="kv">',
        f'<div>submission id</div><div class="mono">{_esc(rec.get("submission_id"))}</div>',
        f'<div>page size / pages</div><div>{_esc(r.get("page_size"))} / '
        f'{_esc(r.get("page_count"))}</div>',
        f'<div>table root page</div><div>{_esc(r.get("root_page"))}</div>',
    ]
    rng = r.get("row_key_range")
    parts.append(
        "<div>row key range</div><div class=\"mono\" id=\"ssr-rowkeyrange\">"
        + (_esc(f"{rng[0]} … {rng[1]}") if rng else "—") + "</div>")
    pages = r.get("pages") or []
    roles: dict = {}
    for p in pages:
        roles[p["owner_role"]] = roles.get(p["owner_role"], 0) + 1
    parts.append(
        '<div>unique ownership</div><div class="mono">'
        + _esc(", ".join(f"{k}={v}" for k, v in sorted(roles.items())))
        + f" (total {len(pages)})</div>")
    v = r.get("first_violation")
    if v:
        raw = v.get("raw_byte")
        raw_txt = ("0x%02X" % raw) if isinstance(raw, int) else "—"
        parts.append(
            '</div><h2>首个违规证据 · first violation</h2>'
            '<div class="violation-box mono" id="ssr-violation" '
            f'data-code="{_esc(v.get("code"))}" '
            f'data-page="{_esc(v.get("page"))}" '
            f'data-offset="{_esc(v.get("offset"))}" '
            f'data-raw-byte="{_esc(raw_txt)}">'
            f'<div><code>{_esc(v.get("code"))}</code></div>'
            f'<div>{_esc(v.get("message"))}</div>'
            f'<div class="muted">location: <b>{_esc(v.get("location"))}</b>'
            f' · page <b>{_esc(v.get("page"))}</b> · offset '
            f'<b>{_esc(v.get("offset"))}</b></div>'
            f'<div class="muted">first raw byte: '
            f'<span class="badge-raw">{_esc(raw_txt)}</span></div></div>')
    else:
        parts.append(
            '</div><div class="ok-note mono" id="ssr-violation" '
            'data-code="">No violation — b-tree pages, overflow payload and '
            "free chain are pairwise disjoint.</div>")
    parts.append("</section>")
    return "".join(parts)


class Handler(BaseHTTPRequestHandler):
    server_version = "StarborneReview/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
        return

    # ------------------------------------------------------------------ GET

    def do_GET(self) -> None:  # noqa: N802 - stdlib API
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/" or path == "/index.html":
            html = (_page_html()
                    .replace(b"__INITIAL_SUMMARY__", b"")
                    .replace(b"__INITIAL_SUBMISSION__", b""))
            self._send(HTTPStatus.OK, "text/html; charset=utf-8", html)
            return
        if path == "/api/health":
            self._send_json(HTTPStatus.OK, {
                "status": "ok",
                "service": "starborne-snapshot-review",
                "max_snapshot_bytes": MAX_SNAPSHOT_BYTES,
            })
            return
        if path.startswith("/api/submission/"):
            sid = path.rsplit("/", 1)[-1]
            rec = STORE.get(sid)
            if rec is None:
                self._send_json(HTTPStatus.NOT_FOUND,
                                {"error": {"code": "NOT_FOUND",
                                           "message": "unknown submission id"}})
                return
            self._send_json(HTTPStatus.OK, rec)
            return
        if path.startswith("/view/"):
            sid = path.rsplit("/", 1)[-1]
            rec = STORE.get(sid)
            if rec is None:
                self._send_json(HTTPStatus.NOT_FOUND,
                                {"error": "unknown submission id"})
                return
            embedded = json.dumps(rec, ensure_ascii=False).replace(
                "<", "\\u003c")
            html = (_page_html()
                    .replace(b"__INITIAL_SUMMARY__",
                             _ssr_summary(rec).encode("utf-8"), 1)
                    .replace(b"__INITIAL_SUBMISSION__",
                             embedded.encode("utf-8"), 1))
            self._send(HTTPStatus.OK, "text/html; charset=utf-8", html)
            return
        self._send_json(HTTPStatus.NOT_FOUND,
                        {"error": {"code": "NOT_FOUND",
                                   "message": f"no route for {path}"}})

    # ----------------------------------------------------------------- POST

    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/api/verify":
            self._send_json(HTTPStatus.NOT_FOUND,
                            {"error": {"code": "NOT_FOUND",
                                       "message": "use POST /api/verify"}})
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            self._send_json(HTTPStatus.BAD_REQUEST,
                            _error("EMPTY_BODY", "empty request body",
                                   HTTPStatus.BAD_REQUEST)[0])
            return
        if length > _MAX_BODY:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                _error("BODY_TOO_LARGE",
                       f"request exceeds encoded size limit {_MAX_BODY}",
                       HTTPStatus.REQUEST_ENTITY_TOO_LARGE)[0])
            return
        body = self.rfile.read(length)
        payload, status = evaluate_payload(body)
        self._send_json(status, payload)

    # --------------------------------------------------------------- helpers

    def _send(self, status: HTTPStatus, ctype: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: HTTPStatus, obj: dict) -> None:
        self._send(status, "application/json",
                   json.dumps(obj, ensure_ascii=False).encode("utf-8"))


def build_server(host: str = "0.0.0.0", port: int = 8080) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Snapshot review service")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    httpd = build_server(args.host, args.port)
    print(f"snapshot review service listening on {args.host}:{args.port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
