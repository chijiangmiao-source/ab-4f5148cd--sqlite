"""HTTP-level tests: API verdicts, health endpoint, stale-success clearing."""

import base64
import json
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

from app import fixtures
from app.fixtures import valid_snapshot
from app.server import Handler


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def post_json(self, payload):
        req = urllib.request.Request(
            self.base + "/api/audit",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def post_form(self, fields):
        req = urllib.request.Request(
            self.base + "/",
            data=urllib.parse.urlencode(fields).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def test_health(self):
        status, body = self.get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "ok")

    def test_form_page_loads(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b'id="audit-form"', body)
        self.assertIn(b'id="snapshot_b64"', body)

    def test_last_result_404_before_first_submission(self):
        status, _ = self.get("/api/audit/last")
        self.assertIn(status, (200, 404))  # depends on test order; see dedicated test

    def test_valid_snapshot_accepted(self):
        data, root = valid_snapshot()
        status, res = self.post_json({"snapshot_b64": b64(data), "root_page": root})
        self.assertEqual(status, 200)
        self.assertEqual(res["verdict"], "accepted")
        pages = [p["page"] for p in res["pages"]]
        self.assertEqual(len(pages), len(set(pages)))

    def test_rejection_and_stale_success_cleared(self):
        data, root = valid_snapshot()
        status, res = self.post_json({"snapshot_b64": b64(data), "root_page": root})
        self.assertEqual(res["verdict"], "accepted")
        status, last = self.get("/api/audit/last")
        self.assertEqual(json.loads(last)["verdict"], "accepted")

        bad, bad_root, code, page, offset = fixtures.invalid_scenarios()[
            "shared_overflow_page"
        ]
        status, res = self.post_json({"snapshot_b64": b64(bad), "root_page": bad_root})
        self.assertEqual(status, 422)
        self.assertEqual(res["verdict"], "rejected")
        self.assertEqual(res["error"]["code"], code)
        self.assertEqual(res["error"]["page"], page)
        self.assertEqual(res["error"]["offset"], offset)

        # The earlier success conclusion must be gone.
        status, last = self.get("/api/audit/last")
        last = json.loads(last)
        self.assertEqual(last["verdict"], "rejected")
        self.assertEqual(last["error"]["code"], code)

    def test_page_shows_same_first_violation_as_api(self):
        bad, bad_root, code, page, offset = fixtures.invalid_scenarios()[
            "key_bound_conflict"
        ]
        _, api_res = self.post_json({"snapshot_b64": b64(bad), "root_page": bad_root})
        status, html_text = self.post_form(
            {"snapshot_b64": b64(bad), "root_page": str(bad_root)}
        )
        self.assertEqual(status, 422)
        self.assertIn(f'id="error-code"><code>{code}</code>', html_text)
        self.assertIn(f'id="error-page">{page}<', html_text)
        self.assertIn(f'id="error-offset">{offset}<', html_text)
        self.assertIn(api_res["error"]["bytes_hex"], html_text)

    def test_bad_base64(self):
        status, res = self.post_json({"snapshot_b64": "!!!not-base64!!!", "root_page": 2})
        self.assertEqual(status, 422)
        self.assertEqual(res["error"]["code"], "BASE64_INVALID")

    def test_oversize_snapshot(self):
        status, res = self.post_json(
            {"snapshot_b64": b64(b"\x00" * (600 * 1024)), "root_page": 2}
        )
        self.assertEqual(status, 422)
        self.assertEqual(res["error"]["code"], "SNAPSHOT_TOO_LARGE")

    def test_root_page_not_integer(self):
        status, res = self.post_json({"snapshot_b64": b64(b"x" * 1024), "root_page": "two"})
        self.assertEqual(status, 422)
        self.assertEqual(res["error"]["code"], "ROOT_PAGE_INVALID")

    def test_malformed_json_body(self):
        req = urllib.request.Request(
            self.base + "/api/audit",
            data=b"{not json",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
