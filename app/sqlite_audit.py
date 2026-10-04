"""Page-ownership auditor for SQLite 3 snapshot imports.

Before a maintenance snapshot is imported into the spaceborne archive, this
auditor proves that the table b-tree rooted at a requested page, the overflow
payload chain and the freelist trunk chain never share a page.  Only the
file-format subset needed for that proof is parsed:

* the 100-byte database header (magic, page size, reserved bytes,
  auto-vacuum markers, freelist head/count),
* table interior (0x05) and table leaf (0x0d) b-tree pages,
* varints, local payload splitting and overflow pages,
* the freelist trunk chain.

The first violation stops the audit and is reported with a stable page
number, absolute file offset and the raw bytes found there.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

sys.setrecursionlimit(max(sys.getrecursionlimit(), 10000))

MAX_SNAPSHOT_BYTES = 512 * 1024
MIN_PAGE_SIZE = 512
MAX_PAGE_SIZE = 4096
SQLITE_MAGIC = b"SQLite format 3\x00"

PAGE_TYPE_INTERIOR_TABLE = 0x05
PAGE_TYPE_LEAF_TABLE = 0x0D

KIND_ROOT = "btree_root"
KIND_INTERIOR = "btree_interior"
KIND_LEAF = "btree_leaf"
KIND_OVERFLOW = "overflow"
KIND_FREELIST_TRUNK = "freelist_trunk"
KIND_FREELIST_LEAF = "freelist_leaf"
LIVE_KINDS = frozenset({KIND_ROOT, KIND_INTERIOR, KIND_LEAF, KIND_OVERFLOW})

# Generous ceiling: with <=512KiB snapshots a b-tree can never get this deep;
# the guard only stops pathological inputs before Python's recursion limit.
MAX_BTREE_DEPTH = 4000


@dataclass
class AuditError:
    """The single first violation, located by page and absolute file offset."""

    code: str
    message: str
    page: int | None = None
    offset: int | None = None
    bytes_hex: str | None = None
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "page": self.page,
            "offset": self.offset,
            "bytes_hex": self.bytes_hex,
            "detail": self.detail,
        }


class Reject(Exception):
    """Raised with the first rule violation; auditing stops immediately."""

    def __init__(self, error: AuditError):
        super().__init__(error.message)
        self.error = error


@dataclass
class PageOwner:
    page: int
    kind: str
    referenced_by: str
    reference_offset: int | None
    role: str | None = None  # "interior" / "leaf" for b-tree pages
    rowid_min: int | None = None
    rowid_max: int | None = None

    def to_dict(self) -> dict:
        return {
            "page": self.page,
            "kind": self.kind,
            "referenced_by": self.referenced_by,
            "reference_offset": self.reference_offset,
            "rowid_range": (
                [self.rowid_min, self.rowid_max]
                if self.rowid_min is not None
                else None
            ),
        }


def to_signed64(value: int) -> int:
    return value - (1 << 64) if value >= (1 << 63) else value


def table_leaf_local(payload_len: int, usable: int) -> tuple[int, bool]:
    """Local payload bytes for a table leaf cell (SQLite file format rules).

    Returns (local_bytes, spills_to_overflow).
    """
    max_local = usable - 35
    min_local = ((usable - 12) * 32) // 255 - 23
    if payload_len <= max_local:
        return payload_len, False
    local = min_local + (payload_len - min_local) % (usable - 4)
    if local > max_local:
        local = min_local
    return local, True


class Auditor:
    def __init__(self, data: bytes, root_page: int):
        self.data = data
        self.root_page = root_page
        self.page_size = 0
        self.page_count = 0
        self.usable = 0
        self.freelist_head = 0
        self.freelist_count = 0
        self.owners: dict[int, PageOwner] = {}
        self.overflow_chains = 0
        # Overflow chains are walked after the whole b-tree is owned, so an
        # overflow page pointing at any b-tree page is a deterministic
        # ownership conflict regardless of traversal order.
        self.pending_overflow: list[tuple] = []

    # -- low-level helpers ------------------------------------------------

    def _hex(self, offset: int | None, length: int = 16) -> str | None:
        if offset is None or offset < 0 or offset >= len(self.data):
            return None
        return self.data[offset : offset + length].hex()

    def fail(self, code, message, page=None, offset=None, detail=None):
        raise Reject(
            AuditError(code, message, page, offset, self._hex(offset), detail or {})
        )

    def u16(self, off: int) -> int:
        return int.from_bytes(self.data[off : off + 2], "big")

    def u32(self, off: int) -> int:
        return int.from_bytes(self.data[off : off + 4], "big")

    def page_base(self, pgno: int) -> int:
        return (pgno - 1) * self.page_size

    def read_varint(self, off: int, limit: int, page: int, what: str):
        """Decode a SQLite varint in [off, limit); returns (value, next_off)."""
        value = 0
        for i in range(9):
            pos = off + i
            if pos >= limit:
                self.fail(
                    "TRUNCATED_CELL",
                    f"{what} on page {page} runs past the end of the page",
                    page=page,
                    offset=off,
                    detail={"what": what},
                )
            byte = self.data[pos]
            if i == 8:
                value = (value << 8) | byte
                return value, pos + 1
            value = (value << 7) | (byte & 0x7F)
            if not byte & 0x80:
                return value, pos + 1
        raise AssertionError("unreachable")

    # -- database header ----------------------------------------------------

    def parse_header(self):
        data = self.data
        if len(data) < 100:
            self.fail(
                "HEADER_TOO_SHORT",
                "snapshot is smaller than the 100-byte SQLite database header",
                page=1,
                offset=0,
                detail={"size": len(data)},
            )
        if data[0:16] != SQLITE_MAGIC:
            self.fail(
                "BAD_MAGIC",
                "missing 'SQLite format 3' magic; only SQLite 3 snapshots are reviewed",
                page=1,
                offset=0,
            )
        raw_size = self.u16(16)
        page_size = 65536 if raw_size == 1 else raw_size
        if (
            page_size < MIN_PAGE_SIZE
            or page_size > MAX_PAGE_SIZE
            or page_size & (page_size - 1)
        ):
            self.fail(
                "PAGE_SIZE_UNSUPPORTED",
                f"page size {page_size} is outside 512..4096 or not a power of two",
                page=1,
                offset=16,
                detail={"page_size": page_size},
            )
        self.page_size = page_size
        reserved = data[20]
        if reserved != 0:
            self.fail(
                "RESERVED_BYTES_PRESENT",
                f"page reserve field is {reserved}; review requires 0 reserved bytes",
                page=1,
                offset=20,
                detail={"reserved": reserved},
            )
        self.usable = page_size - reserved
        if self.u32(52) != 0:
            self.fail(
                "AUTO_VACUUM_ENABLED",
                "header marks auto-vacuum / incremental-vacuum mode; review requires a non-auto-vacuum snapshot",
                page=1,
                offset=52,
                detail={"largest_root_page": self.u32(52)},
            )
        if self.u32(64) != 0:
            self.fail(
                "AUTO_VACUUM_ENABLED",
                "incremental-vacuum flag is set; review requires a non-auto-vacuum snapshot",
                page=1,
                offset=64,
            )
        if len(data) % page_size != 0:
            self.fail(
                "TRUNCATED_PAGE",
                "file size is not a whole number of pages; the last page is truncated",
                page=len(data) // page_size + 1,
                offset=(len(data) // page_size) * page_size,
                detail={"size": len(data), "page_size": page_size},
            )
        self.page_count = len(data) // page_size
        self.freelist_head = self.u32(32)
        self.freelist_count = self.u32(36)
        if not 1 <= self.root_page <= self.page_count:
            self.fail(
                "ROOT_PAGE_OUT_OF_RANGE",
                f"table root page {self.root_page} is outside the snapshot's 1..{self.page_count} pages",
                page=self.root_page,
                offset=(self.root_page - 1) * page_size,
                detail={"page_count": self.page_count},
            )

    # -- ownership ------------------------------------------------------------

    def claim(self, pgno, kind, referenced_by, reference_offset) -> PageOwner:
        existing = self.owners.get(pgno)
        if existing is not None:
            self.fail(
                "PAGE_OWNERSHIP_CONFLICT",
                f"page {pgno} is already owned as {existing.kind} "
                f"(referenced by {existing.referenced_by}) and cannot also be "
                f"{kind} (referenced by {referenced_by})",
                page=pgno,
                offset=reference_offset,
                detail={
                    "first_kind": existing.kind,
                    "first_referenced_by": existing.referenced_by,
                    "first_reference_offset": existing.reference_offset,
                    "second_kind": kind,
                    "second_referenced_by": referenced_by,
                },
            )
        owner = PageOwner(pgno, kind, referenced_by, reference_offset)
        self.owners[pgno] = owner
        return owner

    def claim_free(self, pgno, kind, referenced_by, reference_offset) -> PageOwner:
        existing = self.owners.get(pgno)
        if existing is not None:
            if existing.kind in LIVE_KINDS:
                code = "LIVE_PAGE_ON_FREELIST"
                message = (
                    f"page {pgno} is live ({existing.kind}, referenced by "
                    f"{existing.referenced_by}) but also appears on the freelist "
                    f"({referenced_by})"
                )
            else:
                code = "FREELIST_DUPLICATE"
                message = (
                    f"page {pgno} appears twice on the freelist "
                    f"({existing.referenced_by} and {referenced_by})"
                )
            self.fail(
                code,
                message,
                page=pgno,
                offset=reference_offset,
                detail={
                    "first_kind": existing.kind,
                    "first_referenced_by": existing.referenced_by,
                    "first_reference_offset": existing.reference_offset,
                    "second_referenced_by": referenced_by,
                },
            )
        return self.claim(pgno, kind, referenced_by, reference_offset)

    # -- table b-tree -----------------------------------------------------------

    def _require_child_in_range(self, child, holder, offset):
        if not 1 <= child <= self.page_count:
            self.fail(
                "CHILD_PAGE_OUT_OF_RANGE",
                f"page {holder} points to child page {child}, outside the snapshot's 1..{self.page_count} pages",
                page=child,
                offset=offset,
                detail={
                    "holder_page": holder,
                    "child_page": child,
                    "page_count": self.page_count,
                },
            )

    def walk_btree(self, pgno, referenced_by, reference_offset, depth):
        """In-order walk; returns (rowid_min, rowid_max, row_count) of the subtree."""
        if depth > MAX_BTREE_DEPTH:
            self.fail(
                "BTREE_TOO_DEEP",
                f"b-tree nesting exceeds {MAX_BTREE_DEPTH} levels",
                page=pgno,
                offset=reference_offset,
            )
        base = self.page_base(pgno)
        hdr = base + (100 if pgno == 1 else 0)
        page_end = base + self.page_size
        ptype = self.data[hdr]
        if ptype not in (PAGE_TYPE_INTERIOR_TABLE, PAGE_TYPE_LEAF_TABLE):
            self.fail(
                "NOT_A_TABLE_BTREE_PAGE",
                f"page {pgno} has page type 0x{ptype:02x}; expected a table "
                f"interior (0x05) or table leaf (0x0d) page",
                page=pgno,
                offset=hdr,
                detail={"page_type": ptype, "referenced_by": referenced_by},
            )
        role = "interior" if ptype == PAGE_TYPE_INTERIOR_TABLE else "leaf"
        if depth == 0:
            kind = KIND_ROOT
        else:
            kind = KIND_INTERIOR if ptype == PAGE_TYPE_INTERIOR_TABLE else KIND_LEAF
        owner = self.claim(pgno, kind, referenced_by, reference_offset)
        owner.role = role

        ncells = self.u16(hdr + 3)
        content_start = self.u16(hdr + 5)
        hdr_size = 12 if ptype == PAGE_TYPE_INTERIOR_TABLE else 8
        rel_hdr = hdr - base
        ptr_end_rel = rel_hdr + hdr_size + 2 * ncells
        if ptr_end_rel > self.page_size:
            self.fail(
                "CELL_POINTER_ARRAY_OVERFLOW",
                f"page {pgno} declares {ncells} cells; the cell pointer array "
                f"overruns the page",
                page=pgno,
                offset=hdr + 3,
                detail={"cells": ncells},
            )
        if not ptr_end_rel <= content_start <= self.page_size:
            self.fail(
                "CONTENT_AREA_INVALID",
                f"page {pgno} cell content area starts at {content_start} but the "
                f"pointer array ends at {ptr_end_rel} (page size {self.page_size})",
                page=pgno,
                offset=hdr + 5,
                detail={
                    "content_start": content_start,
                    "pointer_array_end": ptr_end_rel,
                },
            )
        cells = []
        for i in range(ncells):
            ptr_off = hdr + hdr_size + 2 * i
            cptr = self.u16(ptr_off)
            if cptr < content_start or cptr >= self.page_size:
                self.fail(
                    "CELL_POINTER_OUT_OF_BOUNDS",
                    f"page {pgno} cell {i} points to byte {cptr}, outside the cell "
                    f"content area {content_start}..{self.page_size - 1}",
                    page=pgno,
                    offset=ptr_off,
                    detail={
                        "cell_index": i,
                        "pointer": cptr,
                        "content_start": content_start,
                    },
                )
            cells.append(base + cptr)

        if ptype == PAGE_TYPE_LEAF_TABLE:
            return self._parse_leaf(pgno, owner, cells, page_end)
        return self._parse_interior(pgno, owner, cells, hdr, page_end, depth)

    def _parse_leaf(self, pgno, owner, cells, page_end):
        prev = None
        lo = hi = None
        for i, coff in enumerate(cells):
            payload_len, o = self.read_varint(
                coff, page_end, pgno, f"cell {i} payload length"
            )
            rowid_raw, o = self.read_varint(o, page_end, pgno, f"cell {i} rowid")
            rowid = to_signed64(rowid_raw)
            local, spills = table_leaf_local(payload_len, self.usable)
            cell_end = o + local + (4 if spills else 0)
            if cell_end > page_end:
                self.fail(
                    "TRUNCATED_CELL",
                    f"page {pgno} cell {i} needs {cell_end - coff} bytes but only "
                    f"{page_end - coff} remain on the page",
                    page=pgno,
                    offset=coff,
                    detail={
                        "cell_index": i,
                        "payload_len": payload_len,
                        "local_bytes": local,
                    },
                )
            if spills:
                head = self.u32(o + local)
                self.pending_overflow.append(
                    (head, payload_len, local, pgno, o + local, i)
                )
            if prev is not None and rowid <= prev:
                self.fail(
                    "ROWID_NOT_INCREASING",
                    f"page {pgno} cell {i} rowid {rowid} does not exceed the "
                    f"previous rowid {prev}",
                    page=pgno,
                    offset=coff,
                    detail={
                        "cell_index": i,
                        "rowid": rowid,
                        "previous_rowid": prev,
                    },
                )
            prev = rowid
            if lo is None:
                lo = rowid
            hi = rowid
        owner.rowid_min = lo
        owner.rowid_max = hi
        return (lo, hi, len(cells))

    def _parse_interior(self, pgno, owner, cells, hdr, page_end, depth):
        right_ptr = self.u32(hdr + 8)
        entries = []
        for i, coff in enumerate(cells):
            if coff + 4 > page_end:
                self.fail(
                    "TRUNCATED_CELL",
                    f"page {pgno} cell {i} child pointer overruns the page",
                    page=pgno,
                    offset=coff,
                    detail={"cell_index": i},
                )
            child = self.u32(coff)
            key_raw, _ = self.read_varint(
                coff + 4, page_end, pgno, f"cell {i} divider key"
            )
            entries.append((child, to_signed64(key_raw), coff, coff + 4))
        children = [e[0] for e in entries] + [right_ptr]

        ranges = []
        for i, (child, key, child_off, key_off) in enumerate(entries):
            self._require_child_in_range(child, pgno, child_off)
            rng = self.walk_btree(
                child, f"page {pgno} cell {i} child pointer", child_off, depth + 1
            )
            if rng[2] and rng[1] > key:
                self.fail(
                    "KEY_BOUND_CONFLICT",
                    f"divider key {key} at page {pgno} cell {i} is below max rowid "
                    f"{rng[1]} of its left subtree rooted at page {child}",
                    page=pgno,
                    offset=key_off,
                    detail={
                        "divider_key": key,
                        "left_subtree_max": rng[1],
                        "left_child_page": child,
                        "cell_index": i,
                    },
                )
            ranges.append(rng)
        self._require_child_in_range(right_ptr, pgno, hdr + 8)
        ranges.append(
            self.walk_btree(
                right_ptr,
                f"page {pgno} right-most child pointer",
                hdr + 8,
                depth + 1,
            )
        )

        prev_key = None
        for i, (child, key, child_off, key_off) in enumerate(entries):
            if prev_key is not None and key <= prev_key:
                self.fail(
                    "KEY_BOUND_CONFLICT",
                    f"divider keys on page {pgno} are not strictly increasing "
                    f"({prev_key} then {key})",
                    page=pgno,
                    offset=key_off,
                    detail={
                        "previous_key": prev_key,
                        "divider_key": key,
                        "cell_index": i,
                    },
                )
            prev_key = key
            nxt = ranges[i + 1]
            if nxt[2] and key >= nxt[0]:
                self.fail(
                    "KEY_BOUND_CONFLICT",
                    f"divider key {key} at page {pgno} cell {i} is not below min "
                    f"rowid {nxt[0]} of its right subtree rooted at page "
                    f"{children[i + 1]}",
                    page=pgno,
                    offset=key_off,
                    detail={
                        "divider_key": key,
                        "right_subtree_min": nxt[0],
                        "right_child_page": children[i + 1],
                        "cell_index": i,
                    },
                )

        lo = hi = None
        total = 0
        for r_lo, r_hi, r_n in ranges:
            if r_n:
                total += r_n
                lo = r_lo if lo is None else min(lo, r_lo)
                hi = r_hi if hi is None else max(hi, r_hi)
        owner.rowid_min = lo
        owner.rowid_max = hi
        return (lo, hi, total)

    # -- overflow chain ---------------------------------------------------------

    def walk_pending_overflow(self):
        for head, payload_len, local, cell_page, ptr_off, cell_index in self.pending_overflow:
            self.walk_overflow(head, payload_len, local, cell_page, ptr_off, cell_index)

    def walk_overflow(self, first_pgno, payload_len, local_len, cell_page, ptr_off, cell_index):
        remaining = payload_len - local_len
        per_page = self.usable - 4
        needed = (remaining + per_page - 1) // per_page
        self.overflow_chains += 1
        pgno = first_pgno
        ref_by = f"page {cell_page} cell {cell_index} overflow pointer"
        ref_off = ptr_off
        seen = 0
        while True:
            if pgno == 0:
                self.fail(
                    "OVERFLOW_CHAIN_TRUNCATED",
                    f"overflow chain from page {cell_page} cell {cell_index} ends "
                    f"after {seen} page(s) but {needed} are required by the "
                    f"declared payload",
                    page=cell_page,
                    offset=ref_off,
                    detail={"needed_pages": needed, "found_pages": seen},
                )
            if not 1 <= pgno <= self.page_count:
                self.fail(
                    "OVERFLOW_PAGE_OUT_OF_RANGE",
                    f"overflow page {pgno} referenced by {ref_by} is outside the "
                    f"snapshot's 1..{self.page_count} pages",
                    page=pgno,
                    offset=ref_off,
                    detail={"page_count": self.page_count},
                )
            self.claim(pgno, KIND_OVERFLOW, ref_by, ref_off)
            seen += 1
            base = self.page_base(pgno)
            nxt = self.u32(base)
            if seen == needed:
                if nxt != 0:
                    self.fail(
                        "OVERFLOW_CHAIN_OVERRUN",
                        f"overflow chain continues at page {nxt} although the "
                        f"declared payload is fully covered by {needed} page(s)",
                        page=pgno,
                        offset=base,
                        detail={"next_page": nxt, "needed_pages": needed},
                    )
                break
            if nxt == 0:
                self.fail(
                    "OVERFLOW_CHAIN_TRUNCATED",
                    f"overflow chain ends at page {pgno} after {seen} of {needed} "
                    f"required page(s)",
                    page=pgno,
                    offset=base,
                    detail={"needed_pages": needed, "found_pages": seen},
                )
            ref_by = f"page {pgno} overflow next pointer"
            ref_off = base
            pgno = nxt

    # -- freelist trunk chain -----------------------------------------------------

    def walk_freelist(self):
        head = self.freelist_head
        expected = self.freelist_count
        if head == 0:
            if expected != 0:
                self.fail(
                    "FREELIST_COUNT_MISMATCH",
                    "freelist head is 0 but the header declares "
                    f"{expected} freelist page(s)",
                    page=1,
                    offset=36,
                    detail={"expected": expected, "found": 0},
                )
            return
        max_leaf = self.usable // 4 - 2
        found = 0
        pgno = head
        ref_by = "database header freelist head"
        ref_off = 32
        while pgno != 0:
            if not 1 <= pgno <= self.page_count:
                self.fail(
                    "FREELIST_PAGE_OUT_OF_RANGE",
                    f"freelist trunk page {pgno} referenced by {ref_by} is outside "
                    f"the snapshot's 1..{self.page_count} pages",
                    page=pgno,
                    offset=ref_off,
                    detail={"page_count": self.page_count},
                )
            self.claim_free(pgno, KIND_FREELIST_TRUNK, ref_by, ref_off)
            found += 1
            base = self.page_base(pgno)
            nxt = self.u32(base)
            nleaf = self.u32(base + 4)
            if nleaf > max_leaf:
                self.fail(
                    "FREELIST_TRUNK_LEAF_COUNT",
                    f"freelist trunk page {pgno} claims {nleaf} leaf pointers; "
                    f"at most {max_leaf} fit",
                    page=pgno,
                    offset=base + 4,
                    detail={"leaf_count": nleaf, "max_leaf": max_leaf},
                )
            for i in range(nleaf):
                slot_off = base + 8 + 4 * i
                leaf = self.u32(slot_off)
                if not 1 <= leaf <= self.page_count:
                    self.fail(
                        "FREELIST_PAGE_OUT_OF_RANGE",
                        f"freelist leaf page {leaf} on trunk page {pgno} slot {i} "
                        f"is outside the snapshot's 1..{self.page_count} pages",
                        page=leaf,
                        offset=slot_off,
                        detail={"trunk_page": pgno, "slot": i},
                    )
                self.claim_free(
                    leaf, KIND_FREELIST_LEAF, f"page {pgno} freelist leaf slot {i}", slot_off
                )
                found += 1
            ref_by = f"page {pgno} next-trunk pointer"
            ref_off = base
            pgno = nxt
        if found != expected:
            self.fail(
                "FREELIST_COUNT_MISMATCH",
                f"header declares {expected} freelist page(s) but the trunk chain "
                f"yields {found}",
                page=1,
                offset=36,
                detail={"expected": expected, "found": found},
            )

    # -- result -------------------------------------------------------------------

    def result(self, verdict, error):
        pages = [self.owners[p].to_dict() for p in sorted(self.owners)]
        counts: dict[str, int] = {}
        for owner in self.owners.values():
            counts[owner.kind] = counts.get(owner.kind, 0) + 1
        root_owner = self.owners.get(self.root_page)
        return {
            "verdict": verdict,
            "root_page": self.root_page,
            "page_size": self.page_size or None,
            "page_count": self.page_count or None,
            "error": error.to_dict() if error else None,
            "pages": pages,
            "summary": {
                "page_owners": counts,
                "btree_pages": counts.get(KIND_ROOT, 0)
                + counts.get(KIND_INTERIOR, 0)
                + counts.get(KIND_LEAF, 0),
                "overflow_pages": counts.get(KIND_OVERFLOW, 0),
                "overflow_chains": self.overflow_chains,
                "freelist_pages": counts.get(KIND_FREELIST_TRUNK, 0)
                + counts.get(KIND_FREELIST_LEAF, 0),
                "freelist_declared": self.freelist_count,
                "rowid_min": root_owner.rowid_min if root_owner else None,
                "rowid_max": root_owner.rowid_max if root_owner else None,
            },
        }


def audit_snapshot(data: bytes, root_page: int) -> dict:
    """Audit one snapshot; returns the verdict dict (accepted/rejected)."""
    auditor = Auditor(data, root_page)
    try:
        auditor.parse_header()
        auditor.walk_btree(root_page, "requested table root", None, 0)
        auditor.walk_pending_overflow()
        auditor.walk_freelist()
    except Reject as reject:
        return auditor.result("rejected", reject.error)
    return auditor.result("accepted", None)
