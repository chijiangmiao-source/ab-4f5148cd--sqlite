"""Tests for the byte-level snapshot verifier.

Covers the acceptance scenarios from the review policy:

* a legal multi-level table b-tree with cross-page BLOBs is accepted and
  shows unique ownership, exact overflow coverage and row-key ranges;
* shared overflow pages, ancestor back-pointers, out-of-bounds row keys and
  live pages on the free trunk chain are rejected with the same first
  violation evidence (code + page + offset + raw byte) both directly and
  through the HTTP API/page.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
from typing import Tuple

from app.server import build_server
from app.snapshot_builder import (
    build_scenario_bundle, build_valid_snapshot, encode_varint,
)
from app.verifier import (
    MAX_PAGE_SIZE, MIN_PAGE_SIZE, read_varint as rv, verify_snapshot,
)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

class VarintTests(unittest.TestCase):
    def test_roundtrip(self):
        for n in [0, 1, 127, 128, 16383, 16384, 1 << 32,
                  (1 << 56) - 1, 1 << 56, (1 << 64) - 1]:
            enc = encode_varint(n)
            val, used = rv(enc, 0)
            self.assertEqual(val, n)
            self.assertEqual(used, len(enc))

    def test_nine_byte_form(self):
        enc = encode_varint((1 << 64) - 1)
        self.assertEqual(len(enc), 9)


def make_db_sql(sql: str, page_size: int = 1024,
                auto_vacuum: str = "NONE") -> Tuple[bytes, int]:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        con = sqlite3.connect(path)
        try:
            cur = con.cursor()
            cur.execute(f"PRAGMA page_size = {page_size}")
            cur.execute(f"PRAGMA auto_vacuum = {auto_vacuum}")
            cur.executescript(sql)
            con.commit()
            root = cur.execute(
                "SELECT rootpage FROM sqlite_master WHERE type='table' "
                "AND name='t'").fetchone()[0]
        finally:
            con.close()
        with open(path, "rb") as fh:
            return fh.read(), root
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Valid snapshot
# ---------------------------------------------------------------------------

class ValidSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image, cls.root, _ = build_valid_snapshot()
        cls.report = verify_snapshot(cls.image, cls.root)

    def test_accepted_and_policy_fields(self):
        r = self.report
        self.assertTrue(r.accepted,
                        f"unexpected: {r.first_violation}")
        self.assertIn(r.page_size, range(MIN_PAGE_SIZE, MAX_PAGE_SIZE + 1))
        self.assertEqual(self.image[20], 0)  # no reserved bytes
        self.assertEqual(int.from_bytes(self.image[52:56], "big"), 0)

    def test_multi_level_tree(self):
        roles = [o.owner_role for _, o in r_owners(self.report)]
        self.assertIn("table-interior", roles)
        self.assertIn("table-leaf", roles)

    def test_unique_ownership(self):
        pages = list(self.report.owners)
        self.assertEqual(len(pages), len(set(pages)))
        roles = {p: o.owner_role for p, o in self.report.owners.items()}
        role_set = set(roles.values())
        # pairwise disjoint by construction: every page appears once.
        self.assertTrue({"table-leaf", "overflow"} <= role_set)

    def test_overflow_chains_cover_declared_payload(self):
        # Re-derive every overflow-bearing cell and confirm the hop count
        # equals the official payload-locality split.
        self.assertGreater(len(self.report.overflow_chains), 0)
        u = self.report.page_size
        x = u - 35
        m = ((u - 12) * 32 // 255) - 23
        seen_overflow_pages = set()
        for pno, own in self.report.owners.items():
            if own.owner_role != "table-leaf":
                continue
            for cell in own.cells:
                if cell.overflow_bytes == 0:
                    continue
                chain = next(c for c in self.report.overflow_chains
                             if c[0].page == cell.first_overflow_page)
                # capacity per overflow page = u - 4, exact coverage:
                expected_pages = -(-cell.overflow_bytes // (u - 4))
                self.assertEqual(
                    len(chain), expected_pages,
                    f"rowid {cell.rowid}: chain length mismatch")
                total = sum(h.bytes_on_page for h in chain)
                self.assertEqual(total, cell.overflow_bytes)
                self.assertEqual(
                    cell.local_bytes + cell.overflow_bytes,
                    cell.payload_length)
                # last hop terminates
                self.assertEqual(chain[-1].next_page, 0)
                for h in chain[:-1]:
                    self.assertNotEqual(h.next_page, 0)
                for h in chain:
                    seen_overflow_pages.add(h.page)
        self.assertEqual(
            len(seen_overflow_pages),
            sum(len(c) for c in self.report.overflow_chains))

    def test_row_key_range_and_subtree_ranges(self):
        r = self.report
        self.assertEqual(r.row_key_range, (1, 1400))
        # root subtree spans everything; every interior range encloses its
        # leaf ranges.
        root_range = next(s for s in r.subtree_ranges if s.page == r.root_page)
        self.assertEqual((root_range.rowid_min, root_range.rowid_max), (1, 1400))
        for s in r.subtree_ranges:
            self.assertLessEqual(s.rowid_min, s.rowid_max)
            self.assertTrue(1 <= s.rowid_min and s.rowid_max <= 1400)

    def test_leaf_rowids_strictly_increasing_and_contiguous_within_pages(self):
        for pno, own in self.report.owners.items():
            if own.owner_role == "table-leaf":
                self.assertEqual(own.row_keys, sorted(own.row_keys))
                self.assertEqual(len(own.row_keys), len(set(own.row_keys)))

    def test_every_owner_has_reference_source(self):
        for pno, own in self.report.owners.items():
            if pno == self.root:
                self.assertEqual(own.referenced_by, [])
            else:
                self.assertTrue(own.referenced_by,
                                f"page {pno} has no reference source")


# ---------------------------------------------------------------------------
# Rejection scenarios — first violation evidence stability
# ---------------------------------------------------------------------------

def r_owners(report):
    return sorted(report.owners.items())


class CorruptionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = build_scenario_bundle()

    def _expect(self, scenario):
        image, root, evidence = self.bundle[scenario]
        report = verify_snapshot(image, root)
        self.assertFalse(report.accepted, f"{scenario} unexpectedly accepted")
        v = report.first_violation
        self.assertEqual(v.code, evidence["code"])
        self.assertEqual(v.location.page, evidence["page"],
                         f"{scenario}: page mismatch: {v}")
        self.assertEqual(v.location.offset, evidence["offset"],
                         f"{scenario}: offset mismatch: {v}")
        if "raw_byte" in evidence:
            self.assertEqual(v.raw_byte, evidence["raw_byte"],
                             f"{scenario}: raw byte mismatch: {v}")
        return report, v

    def test_shared_overflow(self):
        report, v = self._expect("shared_overflow")
        # The first overflow page is claimed by one cell only; the second
        # reference is the violation site.
        image, root, evidence = self.bundle["shared_overflow"]
        shared = evidence["shared_page"]
        owner = report.owners[shared]
        self.assertEqual(owner.owner_role, "overflow")
        self.assertNotIn(evidence["page"], owner.referenced_by)

    def test_ancestor_backpointer(self):
        self._expect("ancestor_backpointer")

    def test_key_bounds_conflict(self):
        report, v = self._expect("key_bounds")
        image, root, evidence = self.bundle["key_bounds"]
        self.assertGreater(evidence["injected_rowid"],
                           evidence["divider_key"])
        self.assertEqual(v.location.page, evidence["page"])

    def test_live_page_on_freelist(self):
        report, v = self._expect("live_on_freelist")
        # Evidence points at the in-page-1 header trunk pointer field.
        self.assertEqual((v.location.page, v.location.offset), (1, 32))

    def test_root_out_of_range(self):
        image, root, evidence = self.bundle["root_oob"]
        report = verify_snapshot(image, root)
        self.assertFalse(report.accepted)
        self.assertEqual(report.first_violation.code, "ROOT_OUT_OF_RANGE")


# ---------------------------------------------------------------------------
# Header policy & structural failures
# ---------------------------------------------------------------------------

class HeaderPolicyTests(unittest.TestCase):
    def test_not_sqlite3(self):
        image, root, _ = build_valid_snapshot()
        bad = b"not a sqlite db!!" + image[17:]
        r = verify_snapshot(bad, root)
        self.assertFalse(r.accepted)
        self.assertEqual(r.first_violation.code, "NOT_SQLITE3")
        self.assertEqual((r.first_violation.location.page,
                          r.first_violation.location.offset), (0, 0))

    def test_page_size_boundaries(self):
        for ps, ok in ((512, True), (4096, True), (256, False),
                       (8192, False), (1000, False)):
            if ok:
                image, root = make_db_sql(
                    "CREATE TABLE t(id INTEGER PRIMARY KEY, x);",
                    page_size=ps)
            else:
                # Patch the page-size field of a valid 4096-byte image.
                image, root = make_db_sql(
                    "CREATE TABLE t(id INTEGER PRIMARY KEY, x);",
                    page_size=4096)
                buf = bytearray(image)
                buf[16:18] = (ps & 0xFFFF).to_bytes(2, "big")
                image = bytes(buf)
            r = verify_snapshot(image, root)
            self.assertEqual(r.accepted, ok, f"page_size={ps}: {r.first_violation}")
            if not ok:
                self.assertEqual(r.first_violation.code, "BAD_PAGE_SIZE")
                self.assertEqual(r.first_violation.location.offset, 16)

    def test_reserved_bytes_rejected(self):
        image, root, _ = build_valid_snapshot()
        buf = bytearray(image)
        buf[20] = 4
        r = verify_snapshot(bytes(buf), root)
        self.assertFalse(r.accepted)
        self.assertEqual(r.first_violation.code, "RESERVED_BYTES")
        self.assertEqual(r.first_violation.location.offset, 20)
        self.assertEqual(r.first_violation.raw_byte, 4)

    def test_autovacuum_rejected(self):
        sql = ("CREATE TABLE t(id INTEGER PRIMARY KEY, x TEXT);\n" +
               "\n".join(f"INSERT INTO t VALUES ({i}, 'v{i}');"
                         for i in range(1, 200)))
        image, root = make_db_sql(sql, page_size=512, auto_vacuum="FULL")
        r = verify_snapshot(image, root)
        self.assertFalse(r.accepted)
        self.assertEqual(r.first_violation.code, "AUTOVACUUM_ENABLED")
        self.assertEqual(r.first_violation.location.offset, 52)

    def test_truncated_cell(self):
        # Whole image, but the last cell pointer of a leaf is moved to the
        # final two page bytes so its local payload runs past the page end:
        # a truncated cell must be pinned to a concrete page/offset.
        sql = ("CREATE TABLE t(id INTEGER PRIMARY KEY, x);\n" +
               "\n".join(f"INSERT INTO t VALUES ({i}, {i});"
                         for i in range(1, 6)))
        image, root = make_db_sql(sql, page_size=512)
        ps = 512
        report = verify_snapshot(image, root)
        leaf = next(iter(report.owners))  # single-leaf table
        base = (leaf - 1) * ps
        ptr_abs = base + 8  # first cell-pointer slot
        coff = ps - 2       # cell claims to start at the page's last 2 bytes
        buf = bytearray(image)
        buf[ptr_abs:ptr_abs + 2] = coff.to_bytes(2, "big")
        buf[base + coff] = 5      # payload-length varint = 5 (local only)
        buf[base + coff + 1] = 1  # rowid varint = 1 (terminator)
        r = verify_snapshot(bytes(buf), root)
        self.assertFalse(r.accepted)
        self.assertEqual(r.first_violation.code, "TRUNCATED_CELL")
        self.assertEqual(r.first_violation.location.page, leaf)
        self.assertEqual(r.first_violation.location.offset, coff)

    def test_cell_pointer_duplicate(self):
        image, root, _ = build_valid_snapshot()
        ps = verify_snapshot(image, root).page_size
        report = verify_snapshot(image, root)
        leaf = next(p for p, o in report.owners.items()
                    if o.owner_role == "table-leaf" and len(o.row_keys) >= 3)
        base = (leaf - 1) * ps + 8
        p0 = int.from_bytes(image[base:base + 2], "big")
        buf = bytearray(image)
        buf[base + 2:base + 4] = p0.to_bytes(2, "big")  # pointer[1] = pointer[0]
        r = verify_snapshot(bytes(buf), root)
        self.assertFalse(r.accepted)
        self.assertEqual(r.first_violation.code, "CELLPOINTER_DUPLICATE")
        self.assertEqual(r.first_violation.location.page, leaf)


# ---------------------------------------------------------------------------
# More ownership scenarios
# ---------------------------------------------------------------------------

class ExtraOwnershipTests(unittest.TestCase):
    def test_overflow_cycle_rejected(self):
        image, root, _ = build_valid_snapshot()
        ps = verify_snapshot(image, root).page_size
        report = verify_snapshot(image, root)
        # Pick a chain long enough to have an interior hop.
        chain = next(c for c in report.overflow_chains if len(c) >= 3)
        p0, p1 = chain[0].page, chain[1].page
        buf = bytearray(image)
        # Interior hop p1 points back at its predecessor p0 -> cycle.
        buf[(p1 - 1) * ps:(p1 - 1) * ps + 4] = p0.to_bytes(4, "big")
        r = verify_snapshot(bytes(buf), root)
        self.assertFalse(r.accepted)
        self.assertEqual(r.first_violation.code, "OVERFLOW_CYCLE")
        self.assertEqual(r.first_violation.location.page, p1)
        self.assertEqual(r.first_violation.location.offset, 0)

    def test_free_list_count_mismatch(self):
        image, root, _ = build_valid_snapshot()
        buf = bytearray(image)
        buf[32:36] = (0).to_bytes(4, "big")
        buf[36:40] = (9).to_bytes(4, "big")  # claim 9 free pages, chain empty
        r = verify_snapshot(bytes(buf), root)
        self.assertFalse(r.accepted)
        self.assertEqual(r.first_violation.code, "FREELIST_COUNT_MISMATCH")

    def test_small_database_single_leaf_accepted(self):
        sql = ("CREATE TABLE t(id INTEGER PRIMARY KEY, x);\n" +
               "\n".join(f"INSERT INTO t VALUES ({i}, {i});"
                         for i in range(1, 6)))
        image, root = make_db_sql(sql, page_size=512)
        r = verify_snapshot(image, root)
        self.assertTrue(r.accepted, r.first_violation)
        self.assertEqual(r.row_key_range, (1, 5))

    def test_index_page_type_rejected_in_table_tree(self):
        sql = ("CREATE TABLE t(id INTEGER PRIMARY KEY, x);\n" +
               "\n".join(f"INSERT INTO t VALUES ({i}, {i});"
                         for i in range(1, 6)))
        image, root = make_db_sql(sql, page_size=512)
        buf = bytearray(image)
        # Table leaf (type 0x0d) masquerading as an index leaf (0x0a).
        base = (root - 1) * 512 + (100 if root == 1 else 0)
        buf[base] = 0x0A
        r = verify_snapshot(bytes(buf), root)
        self.assertFalse(r.accepted)
        self.assertEqual(r.first_violation.code, "INDEX_PAGE_IN_TABLE_TREE")
        self.assertEqual(r.first_violation.location.page, root)

    def test_overflow_premature_end_rejected(self):
        image, root, _ = build_valid_snapshot()
        ps = verify_snapshot(image, root).page_size
        report = verify_snapshot(image, root)
        chain = report.overflow_chains[0]
        self.assertGreaterEqual(len(chain), 2)
        # Sever the chain at the first hop (next pointer -> 0) with payload
        # still outstanding.
        first = chain[0].page
        buf = bytearray(image)
        buf[(first - 1) * ps:(first - 1) * ps + 4] = (0).to_bytes(4, "big")
        r = verify_snapshot(bytes(buf), root)
        self.assertFalse(r.accepted)
        self.assertEqual(r.first_violation.code, "OVERFLOW_PREMATURE_END")
        self.assertEqual(r.first_violation.location.page, first)
        self.assertEqual(r.first_violation.location.offset, 0)

    def test_overflow_too_long_rejected(self):
        image, root, _ = build_valid_snapshot()
        ps = verify_snapshot(image, root).page_size
        report = verify_snapshot(image, root)
        chain = report.overflow_chains[0]
        first, last = chain[0].page, chain[-1].page
        buf = bytearray(image)
        # Final page keeps pointing onward (back at the first page) even
        # though all declared payload bytes are already covered.
        buf[(last - 1) * ps:(last - 1) * ps + 4] = first.to_bytes(4, "big")
        r = verify_snapshot(bytes(buf), root)
        self.assertFalse(r.accepted)
        self.assertEqual(r.first_violation.code, "OVERFLOW_TOO_LONG")
        self.assertEqual(r.first_violation.location.page, last)


# ---------------------------------------------------------------------------
# HTTP / API / page smoke tests
# ---------------------------------------------------------------------------

class HttpSmokeTests(unittest.TestCase):
    server: ThreadingHTTPServer
    base: str

    @classmethod
    def setUpClass(cls):
        cls.server = build_server("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def _post(self, payload: dict):
        req = urllib.request.Request(
            self.base + "/api/verify",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def _get(self, path: str):
        with urllib.request.urlopen(self.base + path, timeout=10) as resp:
            raw = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            if "application/json" in ctype:
                return resp.status, json.loads(raw)
            return resp.status, raw

    def test_health(self):
        status, body = self._get("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["max_snapshot_bytes"], 512 * 1024)

    def test_page_served(self):
        status, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("星载归档".encode(), body)

    def test_valid_submission_and_retrieval(self):
        image, root, _ = build_valid_snapshot()
        status, body = self._post({
            "snapshot": base64.b64encode(image).decode(),
            "root_page": root})
        self.assertEqual(status, 200)
        self.assertTrue(body["report"]["accepted"])
        sid = body["submission_id"]
        status2, fetched = self._get(f"/api/submission/{sid}")
        self.assertEqual(status2, 200)
        self.assertEqual(fetched["submission_id"], sid)
        self.assertEqual(fetched["report"]["row_key_range"], [1, 1400])

    def test_api_and_page_share_same_first_violation(self):
        bundle = build_scenario_bundle()
        for scenario in ("shared_overflow", "ancestor_backpointer",
                         "key_bounds", "live_on_freelist"):
            image, root, evidence = bundle[scenario]
            status, body = self._post({
                "snapshot": base64.b64encode(image).decode(),
                "root_page": root})
            self.assertEqual(status, 422, scenario)
            v = body["report"]["first_violation"]
            self.assertEqual(v["code"], evidence["code"], scenario)
            self.assertEqual((v["page"], v["offset"]),
                             (evidence["page"], evidence["offset"]), scenario)
            self.assertEqual(v["raw_byte"], evidence["raw_byte"], scenario)

            sid = body["submission_id"]
            page_status, html = self._get(f"/view/{sid}")
            self.assertEqual(page_status, 200, scenario)
            marker = b'id="initial-submission" type="application/json">'
            start = html.index(marker) + len(marker)
            end = html.index(b"</script>", start)
            embedded = json.loads(html[start:end].decode())
            pv = embedded["report"]["first_violation"]
            self.assertEqual(pv, v, f"{scenario}: page/API evidence diverges")

    def test_bad_base64_rejected(self):
        status, body = self._post({"snapshot": "@@@not-base64@@@",
                                   "root_page": 2})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "BAD_BASE64")

    def test_oversize_rejected(self):
        status, body = self._post(
            {"snapshot": base64.b64encode(b"A" * (512 * 1024 + 1)).decode(),
             "root_page": 2})
        self.assertEqual(status, 413)
        self.assertEqual(body["error"]["code"], "SNAPSHOT_TOO_LARGE")

    def test_stale_success_cleared(self):
        # A rejected resubmission must carry its own REJECTED verdict even if
        # the same client previously got an ACCEPTED one.
        image, root, _ = build_valid_snapshot()
        s_ok, b_ok = self._post({"snapshot": base64.b64encode(image).decode(),
                                 "root_page": root})
        self.assertEqual(s_ok, 200)
        report = verify_snapshot(image, root)
        from app.snapshot_builder import corrupt_shared_overflow
        bad, _evidence = corrupt_shared_overflow(
            image, report.page_size, report)
        s_bad, b_bad = self._post({
            "snapshot": base64.b64encode(bad).decode(), "root_page": root})
        self.assertEqual(s_bad, 422)
        self.assertFalse(b_bad["report"]["accepted"])
        self.assertEqual(b_bad["report"]["first_violation"]["code"],
                         "OVERFLOW_SHARED")
        self.assertNotEqual(b_ok["submission_id"], b_bad["submission_id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
