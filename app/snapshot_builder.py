"""Snapshot factory: builds valid SQLite images and surgical corruptions.

Valid images are produced by the real SQLite library so that the byte-level
verifier can be tested against ground truth.  Corruptions are applied with
raw byte edits at offsets derived from a verification report, so tests assert
both the rejection code *and* the exact page/offset/raw-byte evidence.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
from typing import Dict, List, Tuple

from .verifier import read_varint, verify_snapshot

# ---------------------------------------------------------------------------
# Valid snapshot construction
# ---------------------------------------------------------------------------

def build_valid_snapshot(page_size: int = 512,
                         n_rows: int = 1400,
                         big_blob_rows: Tuple[int, ...] = (1, 700, 1400),
                         blob_size: int = 9000) -> Tuple[bytes, int, str]:
    """Build a multi-level table b-tree with cross-page BLOB overflow.

    Returns (image, root_page, table_name).
    """
    fd, path = tempfile.mkstemp(suffix=".db", prefix="snap-")
    os.close(fd)
    try:
        con = sqlite3.connect(path)
        try:
            cur = con.cursor()
            cur.execute(f"PRAGMA page_size = {page_size}")
            cur.execute("PRAGMA auto_vacuum = NONE")
            cur.execute("CREATE TABLE telemetry "
                        "(id INTEGER PRIMARY KEY, reading INTEGER, raw BLOB)")
            big = {r: bytes((r * 7 + j) & 0xFF for j in range(blob_size))
                   for r in big_blob_rows}
            for i in range(1, n_rows + 1):
                if i in big:
                    cur.execute("INSERT INTO telemetry VALUES (?, ?, ?)",
                                (i, i * 3, big[i]))
                else:
                    # Mix of small rows and medium rows that spill onto
                    # overflow pages as well.
                    if i % 11 == 0:
                        payload = bytes((i + j) & 0xFF for j in range(600))
                        cur.execute("INSERT INTO telemetry VALUES (?, ?, ?)",
                                    (i, i, payload))
                    else:
                        cur.execute("INSERT INTO telemetry VALUES (?, ?, NULL)",
                                    (i, i * 2))
            con.commit()
            root = cur.execute(
                "SELECT rootpage FROM sqlite_master WHERE type='table' "
                "AND name='telemetry'").fetchone()[0]
            ps = cur.execute("PRAGMA page_size").fetchone()[0]
            av = cur.execute("PRAGMA auto_vacuum").fetchone()[0]
            assert ps == page_size and av == 0
        finally:
            con.close()
        with open(path, "rb") as fh:
            image = fh.read()
    finally:
        os.unlink(path)

    report = verify_snapshot(image, root)
    if not report.accepted:
        raise AssertionError(
            f"factory produced invalid snapshot: "
            f"{report.first_violation.code} @ "
            f"{report.first_violation.location}")
    roles = {o.owner_role for o in report.owners.values()}
    if "table-interior" not in roles:
        raise AssertionError("factory snapshot is not multi-level")
    if not report.overflow_chains:
        raise AssertionError("factory snapshot has no overflow pages")
    return image, root, "telemetry"


# ---------------------------------------------------------------------------
# Page-level helpers
# ---------------------------------------------------------------------------

def page_abs(image: bytes, page_size: int, page_no: int, off: int) -> int:
    return (page_no - 1) * page_size + off


def btree_page0(page_no: int) -> int:
    return 100 if page_no == 1 else 0


def parse_leaf_cells(image: bytes, page_size: int,
                     page_no: int) -> List[dict]:
    p0 = btree_page0(page_no)
    base = page_abs(image, page_size, page_no, p0)
    ncells = int.from_bytes(image[base + 3:base + 5], "big")
    cells = []
    for i in range(ncells):
        coff = int.from_bytes(
            image[base + 8 + i * 2: base + 10 + i * 2], "big")
        a = page_abs(image, page_size, page_no, coff)
        plen, l1 = read_varint(image, a)
        rowid, l2 = read_varint(image, a + l1)
        cells.append({
            "index": i,
            "offset": coff,
            "payload_length": plen,
            "payload_varint_len": l1,
            "rowid": rowid,
            "rowid_offset": coff + l1,
            "rowid_varint_len": l2,
            "record_offset": coff + l1 + l2,
        })
    return cells


def parse_interior_cells(image: bytes, page_size: int,
                         page_no: int) -> List[dict]:
    p0 = btree_page0(page_no)
    base = page_abs(image, page_size, page_no, p0)
    ncells = int.from_bytes(image[base + 3:base + 5], "big")
    right_ptr = int.from_bytes(image[base + 8:base + 12], "big")
    cells = []
    for i in range(ncells):
        coff = int.from_bytes(
            image[base + 12 + i * 2: base + 14 + i * 2], "big")
        a = page_abs(image, page_size, page_no, coff)
        child = int.from_bytes(image[a:a + 4], "big")
        key, klen = read_varint(image, a + 4)
        cells.append({
            "index": i,
            "offset": coff,
            "child": child,
            "key": key,
            "key_varint_len": klen,
            "key_offset": coff + 4,
        })
    return cells, right_ptr


def _set_u32(buf: bytearray, abs_off: int, value: int) -> None:
    buf[abs_off:abs_off + 4] = value.to_bytes(4, "big")


def encode_varint(value: int) -> bytes:
    """Encode a non-negative integer (up to 64 bits) as a SQLite varint."""
    if value <= 0x7F:
        return bytes([value])
    if value < (1 << 56):
        # Lowest 7-bit group is the terminator (high bit clear); all higher
        # groups carry the continuation bit; emit highest group first.
        parts = [value & 0x7F]
        v = value >> 7
        while v:
            parts.append(0x80 | (v & 0x7F))
            v >>= 7
        return bytes(reversed(parts))
    # 9-byte form: eight 7-bit groups followed by one raw 8-bit byte.
    high = value >> 8
    groups = bytearray()
    for _ in range(8):
        groups.append(0x80 | (high & 0x7F))
        high >>= 7
    return bytes(reversed(groups)) + bytes([value & 0xFF])


def varint_max(n_bytes: int) -> int:
    if n_bytes >= 9:
        return (1 << 64) - 1
    return (1 << (7 * n_bytes)) - 1


def tree_order_leaves(image: bytes, page_size: int,
                      root_page: int) -> List[int]:
    """Left-to-right list of table-leaf page numbers under root."""
    p0 = btree_page0(root_page)
    base = page_abs(image, page_size, root_page, p0)
    ptype = image[base]
    if ptype == 13:
        return [root_page]
    cells, right = parse_interior_cells(image, page_size, root_page)
    out: List[int] = []
    for c in cells:
        out.extend(tree_order_leaves(image, page_size, c["child"]))
    out.extend(tree_order_leaves(image, page_size, right))
    return out


# ---------------------------------------------------------------------------
# Corruption scenarios
# ---------------------------------------------------------------------------

def corrupt_shared_overflow(image: bytes, page_size: int,
                            report) -> Tuple[bytes, dict]:
    """Two live cells point at the same overflow page.

    Returns (mutated_image, evidence) where evidence describes the expected
    first violation (the second cell's pointer site).
    """
    # Collect overflow-bearing cells in tree traversal order.
    targets: List[Tuple[int, dict]] = []
    for pno in sorted(report.owners):
        own = report.owners[pno]
        if own.owner_role == "table-leaf":
            for cell in own.cells:
                if cell.first_overflow_page is not None:
                    targets.append((pno, cell))
    if len(targets) < 2:
        raise AssertionError("need >=2 overflow cells")
    (page_a, cell_a), (page_b, cell_b) = targets[0], targets[-1]

    buf = bytearray(image)
    ptr_abs = page_abs(buf, page_size, page_b,
                       cell_b.overflow_pointer_offset)
    _set_u32(buf, ptr_abs, cell_a.first_overflow_page)
    evidence = {
        "code": "OVERFLOW_SHARED",
        "page": page_b,
        "offset": cell_b.overflow_pointer_offset,
        "raw_byte": buf[ptr_abs],
        "shared_page": cell_a.first_overflow_page,
    }
    return bytes(buf), evidence


def corrupt_ancestor_backpointer(image: bytes, page_size: int,
                                 report) -> Tuple[bytes, dict]:
    """An interior page's right-most child pointer points at itself."""
    interior = sorted(p for p, o in report.owners.items()
                      if o.owner_role == "table-interior")
    if not interior:
        raise AssertionError("need an interior page")
    page_no = interior[0]
    p0 = btree_page0(page_no)
    buf = bytearray(image)
    ptr_abs = page_abs(buf, page_size, page_no, p0 + 8)
    _set_u32(buf, ptr_abs, page_no)
    evidence = {
        "code": "BTREE_ANCESTOR_BACKPOINTER",
        "page": page_no,
        "offset": p0 + 8,
        "raw_byte": buf[ptr_abs],
    }
    return bytes(buf), evidence


def corrupt_key_bounds(image: bytes, page_size: int,
                       report) -> Tuple[bytes, dict]:
    """Bump the last rowid in a bounded leaf beyond its divider key."""
    options = []
    for ino in sorted(report.owners):
        iown = report.owners[ino]
        if iown.owner_role != "table-interior":
            continue
        cells, _right = parse_interior_cells(image, page_size, ino)
        for cell0 in cells:
            child = report.owners.get(cell0["child"])
            if child is None or child.owner_role != "table-leaf":
                continue
            leaf_cells = parse_leaf_cells(image, page_size, cell0["child"])
            last = leaf_cells[-1]
            ceiling = varint_max(last["rowid_varint_len"])
            if ceiling > cell0["key"]:
                options.append((ino, cell0, last, ceiling))
    if not options:
        raise AssertionError("no bounded leaf admits an equal-length rowid bump")
    ino, cell0, last, ceiling = options[0]
    leaf_no = cell0["child"]
    divider = cell0["key"]
    buf = bytearray(image)
    candidate = min(ceiling, max(divider + 1, ceiling - 1))
    enc = encode_varint(candidate)
    assert len(enc) == last["rowid_varint_len"]
    val, _ = read_varint(enc, 0)
    assert val > divider
    a = page_abs(buf, page_size, leaf_no, last["rowid_offset"])
    buf[a:a + len(enc)] = enc
    evidence = {
        "code": "KEY_RANGE_CONFLICT",
        "page": leaf_no,
        "offset": last["rowid_offset"],
        "raw_byte": buf[a],
        "divider_key": divider,
        "injected_rowid": val,
    }
    return bytes(buf), evidence


def corrupt_live_page_on_freelist(image: bytes, page_size: int,
                                  report) -> Tuple[bytes, dict]:
    """Point the header free-list trunk pointer at a live leaf page."""
    leaf_no = sorted(p for p, o in report.owners.items()
                     if o.owner_role == "table-leaf")[0]
    buf = bytearray(image)
    _set_u32(buf, 32, leaf_no)      # free-list trunk page
    _set_u32(buf, 36, 1)            # free-list count
    evidence = {
        "code": "LIVE_PAGE_ON_FREELIST",
        "page": 1,
        "offset": 32,
        "raw_byte": buf[32],
        "live_page": leaf_no,
    }
    return bytes(buf), evidence


def corrupt_root_out_of_range(image: bytes, page_size: int,
                              report) -> Tuple[bytes, dict]:
    evidence = {
        "code": "ROOT_OUT_OF_RANGE",
        "page": 0,
        "offset": 0,
        "root_page": report.page_count + 1,
    }
    return image, evidence


# ---------------------------------------------------------------------------
# Convenience bundle used by tests and the demo script
# ---------------------------------------------------------------------------

def build_scenario_bundle() -> Dict[str, Tuple[bytes, int, dict]]:
    image, root, _name = build_valid_snapshot()
    page_size = verify_snapshot(image, root).page_size
    report = verify_snapshot(image, root)

    scenarios = {"valid": (image, root, {"code": None})}
    for name, fn in (
            ("shared_overflow", corrupt_shared_overflow),
            ("ancestor_backpointer", corrupt_ancestor_backpointer),
            ("key_bounds", corrupt_key_bounds),
            ("live_on_freelist", corrupt_live_page_on_freelist),
    ):
        mutated, evidence = fn(image, page_size, report)
        scenarios[name] = (mutated, root, evidence)
    mutated, evidence = corrupt_root_out_of_range(image, page_size, report)
    scenarios["root_oob"] = (mutated, evidence["root_page"], evidence)
    return scenarios
