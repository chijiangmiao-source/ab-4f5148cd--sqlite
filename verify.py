#!/usr/bin/env python3
"""One-shot verification gate.

Runs, in order:

1. byte-compilation of every Python source (build check);
2. the full unittest suite, including the page-ownership scenarios;
3. an HTTP/API smoke test against a freshly started server:
   - GET  /api/health
   - POST the legal multi-level / cross-page-BLOB snapshot (ACCEPTED) and
     observe unique ownership, overflow chains and row-key ranges;
   - POST each corruption (shared overflow page, ancestor back-pointer /
     key-bound conflict, live page on the free trunk chain) and confirm the
     API JSON and the reviewer HTML page expose the *same* first violation
     evidence (code + page + offset + raw byte) as the direct verifier.

Exits 0 only if every stage passes; non-zero otherwise.
"""

from __future__ import annotations

import base64
import compileall
import json
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app.server import build_server  # noqa: E402
from app.snapshot_builder import build_scenario_bundle  # noqa: E402
from app.verifier import verify_snapshot  # noqa: E402


def section(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def stage_compile() -> bool:
    section("[1/3] build check: byte-compiling sources")
    ok = compileall.compile_dir(str(ROOT / "app"), quiet=1, maxlevels=10)
    ok = compileall.compile_dir(str(ROOT / "tests"), quiet=1) and ok
    print("compileall:", "PASS" if ok else "FAIL")
    return ok


def stage_tests() -> bool:
    section("[2/3] code tests: page-ownership coverage")
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests",
         "-t", ".", "-v"],
        cwd=ROOT)
    print("unittest:", "PASS" if proc.returncode == 0 else "FAIL")
    return proc.returncode == 0


class SmokeClient:
    def __init__(self, base: str) -> None:
        self.base = base

    def _request(self, method: str, path: str, body: bytes | None = None,
                 ctype: str = "application/json"):
        req = urllib.request.Request(
            self.base + path, data=body, method=method,
            headers={"Content-Type": ctype} if body is not None else {})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), dict(exc.headers)

    def get(self, path: str):
        return self._request("GET", path)

    def post_json(self, path: str, obj: dict):
        status, raw, _ = self._request(
            "POST", path, json.dumps(obj).encode())
        return status, json.loads(raw)


def stage_smoke() -> bool:
    section("[3/3] API/HTTP smoke: health, submissions, evidence parity")
    external = __import__("os").environ.get("STARBORNE_BASE_URL")
    if external:
        base = external.rstrip("/")
        server = None
        thread = None
    else:
        server = build_server("127.0.0.1", 0)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
    client = SmokeClient(base)
    failures: list[str] = []

    def check(cond: bool, label: str) -> None:
        print(("  PASS  " if cond else "  FAIL  ") + label)
        if not cond:
            failures.append(label)

    try:
        print(f"  target: {base}")
        # wait for readiness
        for _ in range(100):
            try:
                client.get("/api/health")
                break
            except OSError:
                time.sleep(0.1)
        else:
            check(False, "server did not become ready")
            return False

        status, raw, _ = client.get("/api/health")
        health = json.loads(raw)
        check(status == 200 and health.get("status") == "ok",
              f"GET /api/health -> 200 ok (got {status})")

        status, body, _ = client.get("/")
        check(status == 200 and b"\xe6\x98\x9f\xe8\xbd\xbd\xe5\xbd\x92\xe6\xa1\xa3" in body,
              "GET / serves reviewer page")

        bundle = build_scenario_bundle()
        image, root, _ = bundle["valid"]
        direct = verify_snapshot(image, root)

        status, submitted = client.post_json("/api/verify", {
            "snapshot": base64.b64encode(image).decode(),
            "root_page": root})
        rep = submitted["report"]
        check(status == 200 and rep["accepted"],
              "valid multi-level + cross-page BLOB snapshot ACCEPTED")
        # Persist the accepted submission too, so the no-JS page can be read.
        ok_sid = submitted["submission_id"]
        ok_status, ok_html, _ = client.get(f"/view/{ok_sid}")
        range_text = "1 … 1400".encode()
        check(ok_status == 200
              and b'id="ssr-verdict" data-verdict="ACCEPTED"' in ok_html
              and range_text in ok_html,
              "accepted submission page renders ACCEPTED + row range "
              "without JavaScript")
        check(rep["row_key_range"] == [1, 1400],
              f"row key range 1..1400 (got {rep['row_key_range']})")
        roles = sorted({p["owner_role"] for p in rep["pages"]})
        check({"table-interior", "table-leaf", "overflow"} <= set(roles),
              f"unique ownership roles present: {roles}")
        page_ids = [p["page"] for p in rep["pages"]]
        check(len(page_ids) == len(set(page_ids)),
              "every touched page has exactly one owner")
        check(len(rep["overflow_chains"]) > 0
              and all(len(c) >= 1 for c in rep["overflow_chains"]),
              f"{len(rep['overflow_chains'])} overflow chain(s), each non-empty")
        longest = max((len(c) for c in rep["overflow_chains"]), default=0)
        check(longest >= 2,
              f"cross-page BLOB present: longest overflow chain spans "
              f"{longest} page(s)")
        # subtree ranges sanity: root spans full range
        root_range = next(s for s in rep["subtree_ranges"]
                          if s["page"] == rep["root_page"])
        check((root_range["rowid_min"], root_range["rowid_max"]) == (1, 1400),
              "root subtree range encloses all row keys")

        print("\n  -- rejection scenarios: direct vs API vs page --")
        for scenario in ("shared_overflow", "ancestor_backpointer",
                         "key_bounds", "live_on_freelist"):
            mut_image, mut_root, expected = bundle[scenario]
            direct_v = verify_snapshot(mut_image, mut_root).first_violation
            direct_tuple = (direct_v.code, direct_v.location.page,
                            direct_v.location.offset, direct_v.raw_byte)
            exp_tuple = (expected["code"], expected["page"],
                         expected["offset"], expected["raw_byte"])
            check(direct_tuple == exp_tuple,
                  f"[{scenario}] direct verifier evidence "
                  f"{exp_tuple}")

            status, body = client.post_json("/api/verify", {
                "snapshot": base64.b64encode(mut_image).decode(),
                "root_page": mut_root})
            api_v = body["report"]["first_violation"]
            api_tuple = (api_v["code"], api_v["page"],
                         api_v["offset"], api_v["raw_byte"])
            check(status == 422 and api_tuple == exp_tuple,
                  f"[{scenario}] API 422 + evidence {api_tuple}")

            sid = body["submission_id"]
            page_status, html, _ = client.get(f"/view/{sid}")
            marker = b'id="initial-submission" type="application/json">'
            embedded = json.loads(
                html[html.index(marker) + len(marker):
                     html.index(b"</script>", html.index(marker))].decode())
            page_v = embedded["report"]["first_violation"]
            page_tuple = (page_v["code"], page_v["page"],
                          page_v["offset"], page_v["raw_byte"])
            check(page_status == 200 and page_tuple == exp_tuple,
                  f"[{scenario}] /view page evidence {page_tuple}")
            check(api_tuple == page_tuple == direct_tuple,
                  f"[{scenario}] API == page == direct verifier")

            # Server-rendered evidence must be present WITHOUT JavaScript:
            # grep the raw HTML for the same code/page/offset/raw byte.
            raw_txt = ("0x%02X" % expected["raw_byte"]
                       if expected["raw_byte"] is not None else "—")
            ssr_markers = (
                f'data-code="{expected["code"]}"'.encode(),
                f'data-page="{expected["page"]}"'.encode(),
                f'data-offset="{expected["offset"]}"'.encode(),
                f'data-raw-byte="{raw_txt}"'.encode(),
                b'id="ssr-verdict" data-verdict="REJECTED"',
            )
            check(all(m in html for m in ssr_markers),
                  f"[{scenario}] raw HTML (no JS) shows identical SSR "
                  "evidence block")

        # stale success must be cleared: fresh id carries REJECTED verdict
        status, bad_body = client.post_json("/api/verify", {
            "snapshot": base64.b64encode(bundle["shared_overflow"][0]).decode(),
            "root_page": bundle["shared_overflow"][1]})
        check(status == 422 and not bad_body["report"]["accepted"]
              and bad_body["submission_id"] != submitted["submission_id"],
              "rejected resubmission gets a fresh REJECTED verdict "
              "(no stale ACCEPTED conclusion)")
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=5)

    print("\nsmoke:", "PASS" if not failures else f"FAIL ({len(failures)})")
    return not failures


def main() -> int:
    results = [stage_compile(), stage_tests(), stage_smoke()]
    section("RESULT")
    if all(results):
        print("ALL STAGES PASSED")
        return 0
    print("FAILURES PRESENT")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
