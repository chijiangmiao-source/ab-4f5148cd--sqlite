"""Deterministic SQLite snapshot builders for tests, demo data and HTTP smoke.

Every scenario is built byte-by-byte so tests know the exact page number and
file offset of the first violation the auditor must report.
"""

from __future__ import annotations

from .sqlite_audit import SQLITE_MAGIC, table_leaf_local

PAGE_SIZE = 1024
PAGE_COUNT = 12
ROOT_PAGE = 2

# Rowid of the row that carries the cross-page BLOB in the valid snapshot.
BLOB_ROWID = 7
BLOB_LEN = 2500
BLOB_LOCAL, _ = table_leaf_local(BLOB_LEN, PAGE_SIZE)  # 460 local bytes


def encode_varint(value: int) -> bytes:
    value &= (1 << 64) - 1
    if value <= 0x7F:
        return bytes([value])
    if value >> 56:  # 9-byte form: eight 7-bit groups plus a full byte
        out = bytearray(9)
        out[8] = value & 0xFF
        v = value >> 8
        for i in range(7, -1, -1):
            out[i] = 0x80 | (v & 0x7F)
            v >>= 7
        return bytes(out)
    groups = []
    v = value
    while True:
        groups.append(v & 0x7F)
        v >>= 7
        if not v:
            break
    out = bytearray()
    for i, group in enumerate(reversed(groups)):
        out.append(group | (0x80 if i < len(groups) - 1 else 0))
    return bytes(out)


class SnapshotBuilder:
    def __init__(self, page_size: int = PAGE_SIZE, page_count: int = PAGE_COUNT):
        self.page_size = page_size
        self.page_count = page_count
        self.pages: dict[int, bytearray] = {}
        self.freelist_head = 0
        self.freelist_count = 0
        self.header_patches: dict[int, bytes] = {}

    def page(self, pgno: int) -> bytearray:
        return self.pages.setdefault(pgno, bytearray(self.page_size))

    def patch_header(self, offset: int, data: bytes):
        self.header_patches[offset] = bytes(data)

    def add_table_leaf(self, pgno, rows, overflow_heads=None, first_page=False):
        """rows: [(rowid, payload)] in pointer-array order.

        Returns {rowid: {"ptr": rel, "overflow_ptr": rel|None}} with offsets
        relative to the start of the page.
        """
        overflow_heads = overflow_heads or {}
        page = self.page(pgno)
        hdr = 100 if first_page else 0
        page[hdr] = 0x0D
        page[hdr + 3 : hdr + 5] = len(rows).to_bytes(2, "big")
        top = self.page_size
        ptrs = []
        info = {}
        for rowid, payload in rows:
            local, spills = table_leaf_local(len(payload), self.page_size)
            cell = encode_varint(len(payload)) + encode_varint(rowid) + payload[:local]
            if spills:
                cell += overflow_heads[rowid].to_bytes(4, "big")
            top -= len(cell)
            page[top : top + len(cell)] = cell
            ptrs.append(top)
            info[rowid] = {
                "ptr": top,
                "overflow_ptr": (top + len(cell) - 4) if spills else None,
            }
        page[hdr + 5 : hdr + 7] = top.to_bytes(2, "big")
        for i, ptr in enumerate(ptrs):
            page[hdr + 8 + 2 * i : hdr + 10 + 2 * i] = ptr.to_bytes(2, "big")
        return info

    def add_table_interior(self, pgno, keys, children, first_page=False):
        """keys: divider keys; children: len(keys)+1 child page numbers."""
        assert len(children) == len(keys) + 1
        page = self.page(pgno)
        hdr = 100 if first_page else 0
        page[hdr] = 0x05
        page[hdr + 3 : hdr + 5] = len(keys).to_bytes(2, "big")
        page[hdr + 8 : hdr + 12] = children[-1].to_bytes(4, "big")
        top = self.page_size
        ptrs = []
        for i, key in enumerate(keys):
            cell = children[i].to_bytes(4, "big") + encode_varint(key)
            top -= len(cell)
            page[top : top + len(cell)] = cell
            ptrs.append(top)
        page[hdr + 5 : hdr + 7] = top.to_bytes(2, "big")
        for i, ptr in enumerate(ptrs):
            page[hdr + 12 + 2 * i : hdr + 14 + 2 * i] = ptr.to_bytes(2, "big")
        return {"ptrs": ptrs, "right_ptr_offset": hdr + 8}

    def add_overflow_chain(self, start_pgno, data: bytes, next_overrides=None):
        """Write `data` across consecutive overflow pages; returns page list."""
        per_page = self.page_size - 4
        pages = []
        off = 0
        pgno = start_pgno
        while off < len(data):
            chunk = data[off : off + per_page]
            off += len(chunk)
            nxt = pgno + 1 if off < len(data) else 0
            page = self.page(pgno)
            page[0:4] = nxt.to_bytes(4, "big")
            page[4 : 4 + len(chunk)] = chunk
            pages.append(pgno)
            pgno += 1
        for target, nxt in (next_overrides or {}).items():
            self.page(target)[0:4] = nxt.to_bytes(4, "big")
        return pages

    def add_freelist_trunk(self, pgno, next_trunk, leaves):
        page = self.page(pgno)
        page[0:4] = next_trunk.to_bytes(4, "big")
        page[4:8] = len(leaves).to_bytes(4, "big")
        for i, leaf in enumerate(leaves):
            page[8 + 4 * i : 12 + 4 * i] = leaf.to_bytes(4, "big")

    def build(self) -> bytes:
        data = bytearray(self.page_size * self.page_count)
        for pgno, page in self.pages.items():
            base = (pgno - 1) * self.page_size
            data[base : base + self.page_size] = page
        # 100-byte database header (written last: page 1 content starts at 100).
        data[0:16] = SQLITE_MAGIC
        data[16:18] = self.page_size.to_bytes(2, "big")
        data[18] = 1  # file format write version: legacy rollback journal
        data[19] = 1  # file format read version
        data[20] = 0  # reserved bytes per page
        data[21] = 64  # max embedded payload fraction
        data[22] = 32  # min embedded payload fraction
        data[23] = 32  # leaf payload fraction
        data[24:28] = (1).to_bytes(4, "big")  # file change counter
        data[28:32] = self.page_count.to_bytes(4, "big")
        data[32:36] = self.freelist_head.to_bytes(4, "big")
        data[36:40] = self.freelist_count.to_bytes(4, "big")
        data[40:44] = (1).to_bytes(4, "big")  # schema cookie
        data[44:48] = (4).to_bytes(4, "big")  # schema format number
        data[56:60] = (1).to_bytes(4, "big")  # text encoding: UTF-8
        data[92:96] = (1).to_bytes(4, "big")  # version-valid-for
        data[96:100] = (3_040_001).to_bytes(4, "big")  # sqlite version number
        for offset, blob in self.header_patches.items():
            data[offset : offset + len(blob)] = blob
        return bytes(data)


def blob_payload() -> bytes:
    return bytes((i * 7 + 3) % 256 for i in range(BLOB_LEN))


def _base_builder():
    """The valid snapshot as a builder plus layout metadata for tweaking.

    Layout (page size 1024, 12 pages):
      1  sqlite_master leaf (outside the audited tree)
      2  table root (interior)         rowids 1..12
      3  table leaf                    rowids 1..4
      4  table leaf                    rowids 5..8, rowid 7 carries the BLOB
      5  table leaf                    rowids 9..12
      6,7 overflow pages of rowid 7
      8  freelist trunk -> leaves 9,10
      11 table interior                rowids 1..8
      12 unreferenced zero page
    """
    b = SnapshotBuilder()
    blob = blob_payload()
    meta = {"blob": blob}
    meta["master"] = b.add_table_leaf(
        1, [(1, b"sqlite-master placeholder record")], first_page=True
    )
    meta["leaf3"] = b.add_table_leaf(3, [(i, b"tm-%04d" % i) for i in (1, 2, 3, 4)])
    meta["leaf4"] = b.add_table_leaf(
        4,
        [(5, b"tm-0005"), (6, b"tm-0006"), (BLOB_ROWID, blob), (8, b"tm-0008")],
        overflow_heads={BLOB_ROWID: 6},
    )
    meta["overflow"] = b.add_overflow_chain(6, blob[BLOB_LOCAL:])
    meta["leaf5"] = b.add_table_leaf(
        5, [(i, b"tm-%04d" % i) for i in (9, 10, 11, 12)]
    )
    meta["interior11"] = b.add_table_interior(11, [4], [3, 4])
    meta["root"] = b.add_table_interior(2, [8], [11, 5])
    b.add_freelist_trunk(8, 0, [9, 10])
    b.freelist_head = 8
    b.freelist_count = 3
    return b, meta


def valid_snapshot():
    """Multi-level table b-tree with a cross-page BLOB and a freelist."""
    b, _ = _base_builder()
    return b.build(), ROOT_PAGE


def invalid_scenarios():
    """name -> (snapshot, root_page, expected_code, expected_page, expected_offset).

    Offsets are absolute file offsets of the first violation evidence.
    """
    scenarios = {}

    # Shared overflow page: rowid 10 on leaf 5 reuses overflow head page 6.
    b, meta = _base_builder()
    blob2 = bytes((i * 13 + 1) % 256 for i in range(BLOB_LEN))
    info5 = b.add_table_leaf(
        5,
        [(9, b"tm-0009"), (10, blob2), (11, b"tm-0011"), (12, b"tm-0012")],
        overflow_heads={10: 6},
    )
    scenarios["shared_overflow_page"] = (
        b.build(),
        ROOT_PAGE,
        "PAGE_OWNERSHIP_CONFLICT",
        6,
        4 * PAGE_SIZE + info5[10]["overflow_ptr"],
    )

    # Ancestor back-pointer: interior page 11 points back at the root page 2.
    b, meta = _base_builder()
    info11 = b.add_table_interior(11, [4], [2, 4])
    scenarios["ancestor_backpointer"] = (
        b.build(),
        ROOT_PAGE,
        "PAGE_OWNERSHIP_CONFLICT",
        2,
        10 * PAGE_SIZE + info11["ptrs"][0],
    )

    # Key bound violation: root divider key 3 < max rowid 8 of its left subtree.
    b, meta = _base_builder()
    root = b.add_table_interior(2, [3], [11, 5])
    scenarios["key_bound_conflict"] = (
        b.build(),
        ROOT_PAGE,
        "KEY_BOUND_CONFLICT",
        2,
        1 * PAGE_SIZE + root["ptrs"][0] + 4,
    )

    # Live page on the freelist: trunk page 8 lists b-tree leaf page 5.
    b, meta = _base_builder()
    b.add_freelist_trunk(8, 0, [9, 5])
    scenarios["live_page_on_freelist"] = (
        b.build(),
        ROOT_PAGE,
        "LIVE_PAGE_ON_FREELIST",
        5,
        7 * PAGE_SIZE + 8 + 4,
    )

    # Truncated cell: leaf 3 cell 0 points at a varint that runs off the page.
    b, meta = _base_builder()
    page3 = b.page(3)
    page3[8:10] = (PAGE_SIZE - 1).to_bytes(2, "big")
    page3[PAGE_SIZE - 1] = 0x80
    scenarios["truncated_cell"] = (
        b.build(),
        ROOT_PAGE,
        "TRUNCATED_CELL",
        3,
        2 * PAGE_SIZE + PAGE_SIZE - 1,
    )

    # Root page out of range.
    b, meta = _base_builder()
    scenarios["root_out_of_range"] = (
        b.build(),
        42,
        "ROOT_PAGE_OUT_OF_RANGE",
        42,
        41 * PAGE_SIZE,
    )

    # Overflow chain overrun: page 7 links on to page 12 after the payload ends.
    b, meta = _base_builder()
    b.page(7)[0:4] = (12).to_bytes(4, "big")
    scenarios["overflow_chain_overrun"] = (
        b.build(),
        ROOT_PAGE,
        "OVERFLOW_CHAIN_OVERRUN",
        7,
        6 * PAGE_SIZE,
    )

    # Overflow chain truncated: page 6 ends the chain one page too early.
    b, meta = _base_builder()
    b.page(6)[0:4] = (0).to_bytes(4, "big")
    scenarios["overflow_chain_truncated"] = (
        b.build(),
        ROOT_PAGE,
        "OVERFLOW_CHAIN_TRUNCATED",
        6,
        5 * PAGE_SIZE,
    )

    # Freelist count mismatch: header declares 5, chain yields 3.
    b, meta = _base_builder()
    b.freelist_count = 5
    scenarios["freelist_count_mismatch"] = (
        b.build(),
        ROOT_PAGE,
        "FREELIST_COUNT_MISMATCH",
        1,
        36,
    )

    # Auto-vacuum mode marker set.
    b, meta = _base_builder()
    b.patch_header(52, (5).to_bytes(4, "big"))
    scenarios["auto_vacuum"] = (
        b.build(),
        ROOT_PAGE,
        "AUTO_VACUUM_ENABLED",
        1,
        52,
    )

    # Reserved bytes per page.
    b, meta = _base_builder()
    b.patch_header(20, b"\x10")
    scenarios["reserved_bytes"] = (
        b.build(),
        ROOT_PAGE,
        "RESERVED_BYTES_PRESENT",
        1,
        20,
    )

    # Page size outside the reviewed 512..4096 window.
    b, meta = _base_builder()
    b.patch_header(16, (8192).to_bytes(2, "big"))
    scenarios["page_size_unsupported"] = (
        b.build(),
        ROOT_PAGE,
        "PAGE_SIZE_UNSUPPORTED",
        1,
        16,
    )

    # Not a SQLite 3 snapshot.
    b, meta = _base_builder()
    b.patch_header(0, b"SQLite format 4\x00")
    scenarios["bad_magic"] = (
        b.build(),
        ROOT_PAGE,
        "BAD_MAGIC",
        1,
        0,
    )

    return scenarios
