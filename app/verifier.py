"""SQLite B-tree page ownership / overflow / free-list verifier.

This module parses a raw SQLite database image *without* trusting the SQLite
library.  Given a table-root page number it walks the table B-tree (interior
and leaf table pages), validates cell boundaries and pointer arrays, checks
that row keys (rowids) are strictly increasing per subtree, follows overflow
chains and the free-page trunk list, and records a unique owner for every
page it touches.

Every rejection is reported as one :class:`Violation` carrying a stable
location (page number + byte offset, where known) and the value of the first
offending raw byte.  The first recorded violation is the one surfaced to
reviewers; stale success verdicts are never reused.

File format reference: https://www.sqlite.org/fileformat2.html
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MIN_PAGE_SIZE = 512
MAX_PAGE_SIZE = 4096
MAX_SNAPSHOT_BYTES = 512 * 1024

BTREE_HDR_INTERIOR = 12  # interior pages carry a 4-byte right-most pointer
BTREE_HDR_LEAF = 8


class PageType(Enum):
    INTERIOR_INDEX = 2
    INTERIOR_TABLE = 5
    LEAF_INDEX = 10
    LEAF_TABLE = 13


@dataclass(frozen=True)
class Location:
    """Stable location of a finding.

    ``page`` is the 1-based SQLite page number (0 means file/header level);
    ``offset`` is the 0-based byte offset within that page (-1 if unknown).
    """

    page: int
    offset: int = -1

    def __str__(self) -> str:
        if self.page <= 0:
            return "file header"
        if self.offset < 0:
            return f"page {self.page}"
        return f"page {self.page} offset {self.offset}"


class Violation(Exception):
    """A single, stable rejection reason."""

    def __init__(self, code: str, message: str, location: Location,
                 raw_byte: Optional[int] = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.location = location
        self.raw_byte = raw_byte

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "page": self.location.page,
            "offset": self.location.offset,
            "location": str(self.location),
            "raw_byte": self.raw_byte,
        }


@dataclass(frozen=True)
class OverflowHop:
    page: int
    next_page: int
    bytes_on_page: int


@dataclass(frozen=True)
class CellRef:
    """Where a cell (and its overflow pointer, if any) lives."""

    rowid: int
    payload_length: int
    local_bytes: int
    overflow_bytes: int
    cell_offset: int
    overflow_pointer_offset: Optional[int] = None
    first_overflow_page: Optional[int] = None


@dataclass
class PageOwnership:
    page: int
    owner_role: str  # table-interior | table-leaf | overflow | free-trunk | free-leaf
    detail: str = ""
    referenced_by: List[int] = field(default_factory=list)
    location: Optional[Location] = None
    raw_byte: Optional[int] = None
    row_keys: List[int] = field(default_factory=list)
    cells: List[CellRef] = field(default_factory=list)


@dataclass
class SubtreeRange:
    page: int
    rowid_min: int
    rowid_max: int


@dataclass
class SnapshotReport:
    accepted: bool
    page_size: int
    page_count: int
    root_page: int
    owners: Dict[int, PageOwnership]
    first_violation: Optional[Violation]
    row_key_range: Optional[Tuple[int, int]]
    subtree_ranges: List[SubtreeRange]
    overflow_chains: List[List[OverflowHop]]
    free_trunk_chain: List[int]
    free_leaf_pages: List[int]
    checked_constraints: List[str]

    def page_listing(self) -> List[dict]:
        out = []
        for pno in sorted(self.owners):
            own = self.owners[pno]
            out.append({
                "page": pno,
                "owner_role": own.owner_role,
                "detail": own.detail,
                "referenced_by": own.referenced_by,
                "reference_location": str(own.location) if own.location else "",
                "raw_byte": own.raw_byte,
                "row_keys": own.row_keys,
                "cells": [{
                    "rowid": c.rowid,
                    "payload_length": c.payload_length,
                    "local_bytes": c.local_bytes,
                    "overflow_bytes": c.overflow_bytes,
                    "cell_offset": c.cell_offset,
                    "overflow_pointer_offset": c.overflow_pointer_offset,
                    "first_overflow_page": c.first_overflow_page,
                } for c in own.cells],
            })
        return out

    def to_dict(self) -> dict:
        return {
            "accepted": self.accepted,
            "verdict": "ACCEPTED" if self.accepted else "REJECTED",
            "page_size": self.page_size,
            "page_count": self.page_count,
            "root_page": self.root_page,
            "first_violation": (self.first_violation.to_dict()
                                if self.first_violation else None),
            "row_key_range": (list(self.row_key_range)
                              if self.row_key_range is not None else None),
            "subtree_ranges": [
                {"page": r.page, "rowid_min": r.rowid_min,
                 "rowid_max": r.rowid_max}
                for r in sorted(self.subtree_ranges, key=lambda r: r.page)],
            "pages": self.page_listing(),
            "overflow_chains": [[hop.page for hop in chain]
                                for chain in self.overflow_chains],
            "free_trunk_chain": self.free_trunk_chain,
            "free_leaf_pages": self.free_leaf_pages,
            "checked_constraints": self.checked_constraints,
        }


def _u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 2], "big")


def _u32(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "big")


def read_varint(data: bytes, off: int) -> Tuple[int, int]:
    """Decode a SQLite varint.  Returns (value, bytes_consumed, 1..9)."""
    result = 0
    for i in range(8):
        byte = data[off + i]
        if byte & 0x80:
            result = (result << 7) | (byte & 0x7F)
        else:
            result = (result << 7) | byte
            return result, i + 1
    result = (result << 8) | data[off + 8]
    return result, 9


class SnapshotVerifier:
    def __init__(self, image: bytes, root_page: int) -> None:
        self.image = image
        self.root_page = root_page
        self.page_size = 0
        self.page_count = 0
        self.owners: Dict[int, PageOwnership] = {}
        self.overflow_chains: List[List[OverflowHop]] = []
        self.subtree_ranges: List[SubtreeRange] = []
        self.free_trunk_chain: List[int] = []
        self.free_leaf_pages: List[int] = []
        self.checked: List[str] = []

    # ------------------------------------------------------------------ utils

    def fail(self, code: str, message: str, page: int = 0,
             offset: int = -1, raw: Optional[int] = None) -> "Violation":
        raise Violation(code, message, Location(page, offset), raw)

    def _pabs(self, page_no: int, page_offset: int) -> int:
        """Absolute image offset of a page-relative offset."""
        return (page_no - 1) * self.page_size + page_offset

    def _raw(self, page_no: int, page_offset: int) -> Optional[int]:
        if page_no <= 0 or page_offset < 0:
            return None
        off = self._pabs(page_no, page_offset)
        return self.image[off] if 0 <= off < len(self.image) else None

    def _varint(self, page_no: int, page_offset: int) -> Tuple[int, int]:
        """read_varint with page-aware truncation errors."""
        abs_off = self._pabs(page_no, page_offset)
        if abs_off >= len(self.image):
            self.fail("TRUNCATED_VARINT", "varint starts past end of image",
                      page_no, page_offset)
        for i in range(9):
            pos = abs_off + i
            if pos >= len(self.image):
                self.fail("TRUNCATED_VARINT",
                          "varint runs past end of page/image",
                          page_no, page_offset + i)
            if i < 8 and not (self.image[pos] & 0x80):
                break  # terminator reached; no further byte is required
        return read_varint(self.image, abs_off)

    def _payload_split(self, payload: int) -> Tuple[int, int]:
        """Official table b-tree leaf payload locality algorithm."""
        u = self.page_size  # reserved bytes == 0
        x = u - 35
        if payload <= x:
            return payload, 0
        m = ((u - 12) * 32 // 255) - 23
        k = m + ((payload - m) % (u - 4))
        local = k if k <= x else m
        return local, payload - local

    # --------------------------------------------------------------- ownership

    def _claim(self, page_no: int, role: str, detail: str,
               referenced_by: int, location: Optional[Location] = None,
               raw: Optional[int] = None) -> PageOwnership:
        own = PageOwnership(
            page=page_no, owner_role=role, detail=detail,
            referenced_by=[referenced_by] if referenced_by else [],
            location=location, raw_byte=raw)
        self.owners[page_no] = own
        return own

    # ---------------------------------------------------------------- header

    def verify_header(self) -> None:
        if len(self.image) < 100:
            self.fail("TRUNCATED_HEADER",
                      f"snapshot is {len(self.image)} bytes, shorter than the "
                      "100-byte SQLite header", 0, len(self.image))
        if self.image[:16] != b"SQLite format 3\x00":
            self.fail("NOT_SQLITE3",
                      "magic string 'SQLite format 3\\0' not found",
                      0, 0, self.image[0])

        page_size = _u16(self.image, 16)
        if page_size == 1:
            page_size = 65536
        if not (MIN_PAGE_SIZE <= page_size <= MAX_PAGE_SIZE):
            self.fail("BAD_PAGE_SIZE",
                      f"page size {page_size} not in 512..4096",
                      0, 16, self.image[16])
        if page_size & (page_size - 1):
            self.fail("BAD_PAGE_SIZE",
                      f"page size {page_size} is not a power of two",
                      0, 16, self.image[16])
        self.page_size = page_size

        reserved = self.image[20]
        if reserved != 0:
            self.fail("RESERVED_BYTES",
                      f"{reserved} reserved bytes per page; review policy "
                      "requires 0", 0, 20, reserved)

        wv, rv = self.image[18], self.image[19]
        if wv not in (1, 2):
            self.fail("BAD_FILE_FORMAT",
                      f"file format write version {wv} is invalid",
                      0, 18, wv)
        if rv not in (1, 2):
            self.fail("BAD_FILE_FORMAT",
                      f"file format read version {rv} is invalid",
                      0, 19, rv)

        # Offset 52..55: page number of the largest root b-tree page.
        # Non-zero iff auto-vacuum or incremental-vacuum is enabled.
        # Offset 64..67: incremental-vacuum mode flag (1 = incremental).
        largest_root = _u32(self.image, 52)
        incr_mode = _u32(self.image, 64)
        if largest_root != 0:
            self.fail("AUTOVACUUM_ENABLED",
                      "auto-vacuum / incremental-vacuum must be disabled "
                      f"(largest-root page number = {largest_root}"
                      f"{', incremental flag = 1' if incr_mode else ''})",
                      0, 52, self.image[52])
        if incr_mode not in (0, 1):
            self.fail("BAD_AUTOVACUUM",
                      f"incremental-vacuum mode flag {incr_mode} is invalid",
                      0, 64, self.image[64])

        db_size_pages = _u32(self.image, 28)
        freelist_trunk = _u32(self.image, 32)
        freelist_count = _u32(self.image, 36)
        self._freelist_trunk = freelist_trunk
        self._freelist_count = freelist_count

        if len(self.image) % page_size:
            boundary = (len(self.image) // page_size) * page_size
            self.fail("TRUNCATED_IMAGE",
                      f"image length {len(self.image)} is not a whole number "
                      f"of {page_size}-byte pages", 0, boundary)
        self.page_count = len(self.image) // page_size

        if db_size_pages not in (0, self.page_count):
            self.fail("DB_SIZE_MISMATCH",
                      f"in-header page count {db_size_pages} disagrees with "
                      f"image page count {self.page_count}",
                      0, 28, self.image[28])

        if not (1 <= self.root_page <= self.page_count):
            self.fail("ROOT_OUT_OF_RANGE",
                      f"table root page {self.root_page} is outside 1.."
                      f"{self.page_count}", self.root_page if self.root_page > 0 else 0)

        self.checked.append("sqlite3 magic, page size 512..4096, zero reserved "
                            "bytes, auto-vacuum disabled")

    # ----------------------------------------------------------------- tree

    def _read_btree_header(self, page_no: int):
        page0 = 100 if page_no == 1 else 0
        b = self._pabs(page_no, page0)
        ptype = self.image[b]
        if ptype not in (pt.value for pt in PageType):
            self.fail("BAD_BTREE_TYPE",
                      f"page {page_no} has invalid b-tree page type "
                      f"0x{ptype:02x}", page_no, page0, ptype)
        if ptype in (PageType.INTERIOR_INDEX.value, PageType.LEAF_INDEX.value):
            self.fail("INDEX_PAGE_IN_TABLE_TREE",
                      f"page {page_no} is an index b-tree page (type "
                      f"{ptype}); table root requires a table b-tree",
                      page_no, page0, ptype)
        first_free = _u16(self.image, b + 1)
        ncells = _u16(self.image, b + 3)
        cell_start = _u16(self.image, b + 5)
        frag = self.image[b + 7]
        right_ptr = (_u32(self.image, b + 8)
                     if ptype == PageType.INTERIOR_TABLE.value else 0)
        return page0, ptype, first_free, ncells, cell_start, frag, right_ptr

    def walk_tree(self) -> None:
        self._walk_page(self.root_page, 0, None, None, set(), -1)
        self.checked.append("table interior/leaf pages, varints, local "
                            "payload framing")
        self.checked.append("cell boundaries & cell pointer arrays")
        self.checked.append("subtree row keys strictly increasing")

    def _check_child_pointer(self, child: int, ref_page: int,
                             ref_off: int, ancestors: Set[int]) -> None:
        """Validate a child pointer at its exact reference site."""
        if not (1 <= child <= self.page_count):
            self.fail("CHILD_POINTER_OOB",
                      f"child page number {child} outside 1.."
                      f"{self.page_count}",
                      ref_page, ref_off, self._raw(ref_page, ref_off))
        if child in ancestors:
            self.fail("BTREE_ANCESTOR_BACKPOINTER",
                      f"child pointer at {Location(ref_page, ref_off)} loops "
                      f"back to ancestor page {child}",
                      ref_page, ref_off, self._raw(ref_page, ref_off))
        if child in self.owners:
            existing = self.owners[child]
            self.fail("PAGE_SHARED",
                      f"page {child} reached through the table tree but it "
                      f"is already owned as {existing.owner_role} "
                      f"({existing.detail})",
                      ref_page, ref_off, self._raw(ref_page, ref_off))

    def _walk_page(self, page_no: int, parent: int,
                   low: Optional[int], high: Optional[int],
                   ancestors: Set[int], ref_off: int) -> Tuple[int, int]:
        if parent != 0:
            # Parent already validated the pointer via _check_child_pointer;
            # the assertions here are defence in depth for the root path.
            if page_no in self.owners and page_no not in ancestors:
                existing = self.owners[page_no]
                self.fail("PAGE_SHARED",
                          f"page {page_no} reached through the table tree but "
                          f"it is already owned as {existing.owner_role}",
                          parent, ref_off)

        page0, ptype, first_free, ncells, cell_start, frag, right_ptr = \
            self._read_btree_header(page_no)
        hdr_len = (BTREE_HDR_INTERIOR
                   if ptype == PageType.INTERIOR_TABLE.value
                   else BTREE_HDR_LEAF)

        if cell_start == 0:
            cell_start = self.page_size  # 0 encodes 65536
        min_start = page0 + hdr_len
        if cell_start < min_start:
            self.fail("CELL_CONTENT_BAD_START",
                      f"cell content area starts at {cell_start}, before "
                      f"b-tree header end {min_start}",
                      page_no, page0 + 5, self._raw(page_no, page0 + 5))
        if cell_start > self.page_size and not (cell_start == self.page_size and ncells == 0):
            self.fail("CELL_CONTENT_BAD_START",
                      f"cell content area start {cell_start} beyond page size",
                      page_no, page0 + 5, self._raw(page_no, page0 + 5))

        role = ("table-interior"
                if ptype == PageType.INTERIOR_TABLE.value else "table-leaf")
        own = self._claim(page_no, role, f"{ncells} cell(s)", parent,
                          Location(page_no, page0), self._raw(page_no, page0))

        array_off = page0 + hdr_len
        if self._pabs(page_no, array_off + ncells * 2) > self._pabs(page_no, self.page_size):
            self.fail("CELLPOINTER_ARRAY_OVERRUN",
                      "cell pointer array extends past end of page",
                      page_no, array_off)
        # The pointer array grows upward while cell content grows downward;
        # they must never cross.
        if ncells > 0 and array_off + ncells * 2 > cell_start:
            self.fail("CELLPOINTER_ARRAY_OVERRUN",
                      f"cell pointer array ({ncells} entries) extends into "
                      f"the cell content area starting at {cell_start}",
                      page_no, array_off + ncells * 2 - 2,
                      self._raw(page_no, array_off + ncells * 2 - 2))

        pointers: List[int] = []
        for i in range(ncells):
            poff_off = array_off + i * 2
            poff = _u16(self.image, self._pabs(page_no, poff_off))
            if poff < min_start:
                self.fail("CELLPOINTER_INTO_HEADER",
                          f"cell pointer {i} = {poff} points into the page "
                          "header/reserved area",
                          page_no, poff_off, self._raw(page_no, poff_off))
            if poff >= self.page_size:
                self.fail("CELLPOINTER_OOB",
                          f"cell pointer {i} = {poff} outside the page",
                          page_no, poff_off, self._raw(page_no, poff_off))
            if poff < cell_start:
                self.fail("CELLPOINTER_OUTSIDE_CONTENT",
                          f"cell pointer {i} = {poff} lies below the cell "
                          f"content area start {cell_start}",
                          page_no, poff_off, self._raw(page_no, poff_off))
            if poff in pointers:
                self.fail("CELLPOINTER_DUPLICATE",
                          f"cell pointer {i} = {poff} duplicates another cell",
                          page_no, poff_off, self._raw(page_no, poff_off))
            pointers.append(poff)

        subtree_lo: Optional[int] = None
        subtree_hi: Optional[int] = None

        def widen(k: int) -> None:
            nonlocal subtree_lo, subtree_hi
            subtree_lo = k if subtree_lo is None else min(subtree_lo, k)
            subtree_hi = k if subtree_hi is None else max(subtree_hi, k)

        # Parse every cell first (offsets, keys, extents) so cell boundaries
        # can be cross-checked before descending.
        parsed = []
        for i, coff in enumerate(pointers):
            if ptype == PageType.INTERIOR_TABLE.value:
                child = _u32(self.image, self._pabs(page_no, coff))
                key, klen = self._varint(page_no, coff + 4)
                end = coff + 4 + klen
                if end > self.page_size:
                    self.fail("TRUNCATED_CELL",
                              f"interior cell {i} overruns page {page_no}",
                              page_no, coff, self._raw(page_no, coff))
                parsed.append(("interior", coff, end, child, key, coff))
            else:
                payload_len, l1 = self._varint(page_no, coff)
                rowid, l2 = self._varint(page_no, coff + l1)
                local, overflow = self._payload_split(payload_len)
                rec_off = coff + l1 + l2
                end = rec_off + local + (4 if overflow else 0)
                if end > self.page_size:
                    self.fail("TRUNCATED_CELL",
                              f"leaf cell {i} (rowid {rowid}) overruns page "
                              f"{page_no}",
                              page_no, coff, self._raw(page_no, coff))
                parsed.append(("leaf", coff, end, payload_len, rowid,
                               rec_off, local, overflow, coff + l1))

        # Cell extents must not overlap (sorted by on-page offset).
        order = sorted(parsed, key=lambda c: c[1])
        for a, nxt in zip(order, order[1:]):
            if a[2] > nxt[1]:
                self.fail("CELLS_OVERLAP",
                          f"cell at offset {a[1]} (end {a[2]}) overlaps cell "
                          f"at offset {nxt[1]} on page {page_no}",
                          page_no, nxt[1], self._raw(page_no, nxt[1]))

        if ptype == PageType.INTERIOR_TABLE.value:
            prev_key: Optional[int] = None
            keys: List[int] = []
            children: List[int] = []
            for kind, coff, end, child, key, _ in parsed:
                if child == 0:
                    self.fail("INTERIOR_NULL_CHILD",
                              f"interior cell at offset {coff} has a zero "
                              "left-child pointer",
                              page_no, coff, 0)
                if prev_key is not None and not key > prev_key:
                    self.fail("ROWID_NOT_STRICT",
                              f"interior divider keys {prev_key} -> {key} not "
                              "strictly increasing",
                              page_no, coff + 4,
                              self._raw(page_no, coff + 4))
                prev_key = key
                keys.append(key)
                children.append(child)
                widen(key)
                own.row_keys.append(key)
            if right_ptr == 0:
                self.fail("INTERIOR_NULL_RIGHTMOST",
                          "interior page right-most pointer is zero",
                          page_no, page0 + 8, 0)

            # Ordered children: cell i's left child then the right-most page.
            # Divider key k equals the maximum rowid of its left subtree.
            child_ancestors = ancestors | {page_no}
            for i, child in enumerate(children):
                self._check_child_pointer(
                    child, page_no, parsed[i][5], child_ancestors)
                child_lo = (keys[i - 1] + 1) if i > 0 else None
                child_hi = keys[i]
                clo, chi = self._walk_page(
                    child, page_no,
                    self._merge_lo(low, child_lo),
                    self._merge_hi(high, child_hi),
                    child_ancestors, parsed[i][5])
                if low is not None and clo < low:
                    self.fail("KEY_RANGE_CONFLICT",
                              f"subtree rooted at page {child} contains rowid "
                              f"{clo} below ancestor bound {low}",
                              child, -1, self._raw(child, 0))
                if high is not None and chi > high:
                    self.fail("KEY_RANGE_CONFLICT",
                              f"subtree rooted at page {child} contains rowid "
                              f"{chi} above ancestor bound {high}",
                              child, -1, self._raw(child, 0))
                if chi > child_hi:
                    self.fail("KEY_RANGE_CONFLICT",
                              f"left child page {child} max rowid {chi} "
                              f"exceeds divider key {child_hi} on page "
                              f"{page_no}",
                              child, -1, self._raw(child, 0))
                # The lower sibling bound (keys[i-1]+1) and ancestor bounds
                # are already enforced inside the subtree at the exact rowid
                # offset via propagated low/high parameters.
                widen(clo)
                widen(chi)

            rm_lo = (keys[-1] + 1) if keys else None
            self._check_child_pointer(
                right_ptr, page_no, page0 + 8, child_ancestors)
            clo, chi = self._walk_page(
                right_ptr, page_no, self._merge_lo(low, rm_lo), high,
                child_ancestors, page0 + 8)
            if keys and chi <= keys[-1]:
                self.fail("KEY_RANGE_CONFLICT",
                          f"right-most child page {right_ptr} max rowid {chi} "
                          f"does not exceed last divider {keys[-1]}",
                          right_ptr, -1, self._raw(right_ptr, 0))
            if low is not None and clo < low:
                self.fail("KEY_RANGE_CONFLICT",
                          f"subtree rooted at page {right_ptr} contains "
                          f"rowid {clo} below ancestor bound {low}",
                          right_ptr, -1, self._raw(right_ptr, 0))
            if high is not None and chi > high:
                self.fail("KEY_RANGE_CONFLICT",
                          f"subtree rooted at page {right_ptr} contains "
                          f"rowid {chi} above ancestor bound {high}",
                          right_ptr, -1, self._raw(right_ptr, 0))
            widen(clo)
            widen(chi)
        else:
            prev_rowid: Optional[int] = None
            for rec in parsed:
                (_, coff, end, payload_len, rowid,
                 rec_off, local, overflow, rowid_off) = rec
                if prev_rowid is not None and rowid <= prev_rowid:
                    self.fail("ROWID_NOT_STRICT",
                              f"leaf rowids {prev_rowid} -> {rowid} not "
                              "strictly increasing",
                              page_no, rowid_off,
                              self._raw(page_no, rowid_off))
                prev_rowid = rowid
                if low is not None and rowid < low:
                    self.fail("KEY_RANGE_CONFLICT",
                              f"rowid {rowid} on page {page_no} below "
                              f"subtree lower bound {low}",
                              page_no, rowid_off,
                              self._raw(page_no, rowid_off))
                if high is not None and rowid > high:
                    self.fail("KEY_RANGE_CONFLICT",
                              f"rowid {rowid} on page {page_no} exceeds "
                              f"subtree upper bound {high}",
                              page_no, rowid_off,
                              self._raw(page_no, rowid_off))

                # Local payload framing: a table record starts with a varint
                # header length; make sure it fits inside the local payload.
                hlen, hlen_n = read_varint(self.image,
                                           self._pabs(page_no, rec_off))
                if hlen < hlen_n or rec_off + hlen > rec_off + local:
                    self.fail("RECORD_HEADER_OVERRUN",
                              f"record header length {hlen} for rowid {rowid} "
                              f"exceeds {local} local payload byte(s)",
                              page_no, rec_off,
                              self._raw(page_no, rec_off))

                own.row_keys.append(rowid)
                widen(rowid)

                first_ovf = None
                ovf_ptr_off = None
                if overflow:
                    ovf_ptr_off = end - 4
                    first_ovf = _u32(self.image,
                                     self._pabs(page_no, ovf_ptr_off))
                    chain = self._walk_overflow(
                        first_ovf, overflow, page_no, ovf_ptr_off)
                    self.overflow_chains.append(chain)
                own.cells.append(CellRef(
                    rowid=rowid, payload_length=payload_len,
                    local_bytes=local, overflow_bytes=overflow,
                    cell_offset=coff,
                    overflow_pointer_offset=ovf_ptr_off,
                    first_overflow_page=first_ovf))

        lo_out = subtree_lo if subtree_lo is not None else 0
        hi_out = subtree_hi if subtree_hi is not None else 0
        self.subtree_ranges.append(
            SubtreeRange(page_no, lo_out, hi_out))
        return lo_out, hi_out

    @staticmethod
    def _merge_lo(a: Optional[int], b: Optional[int]) -> Optional[int]:
        if a is None:
            return b
        if b is None:
            return a
        return max(a, b)

    @staticmethod
    def _merge_hi(a: Optional[int], b: Optional[int]) -> Optional[int]:
        if a is None:
            return b
        if b is None:
            return a
        return min(a, b)

    # -------------------------------------------------------------- overflow

    def _walk_overflow(self, first: int, remaining: int,
                       referrer: int, ptr_page_off: int) -> List[OverflowHop]:
        capacity = self.page_size - 4  # no reserved bytes
        chain: List[OverflowHop] = []
        seen: Set[int] = set()
        cur = first
        prev_page = referrer
        prev_off = ptr_page_off
        left = remaining
        while True:
            if cur == 0:
                self.fail("OVERFLOW_PREMATURE_END",
                          f"overflow chain from page {referrer} terminates "
                          f"with {left} declared payload byte(s) outstanding",
                          prev_page, prev_off,
                          self._raw(prev_page, prev_off))
            if not (1 <= cur <= self.page_count):
                self.fail("OVERFLOW_POINTER_OOB",
                          f"overflow page number {cur} outside 1.."
                          f"{self.page_count}",
                          prev_page, prev_off,
                          self._raw(prev_page, prev_off))
            if cur in seen:
                self.fail("OVERFLOW_CYCLE",
                          f"overflow page {cur} repeats within one chain",
                          prev_page, prev_off,
                          self._raw(prev_page, prev_off))
            if cur in self.owners:
                existing = self.owners[cur]
                self.fail("OVERFLOW_SHARED",
                          f"overflow page {cur} is already owned as "
                          f"{existing.owner_role} ({existing.detail})",
                          prev_page, prev_off,
                          self._raw(prev_page, prev_off))
            seen.add(cur)

            nxt = _u32(self.image, self._pabs(cur, 0))
            take = min(capacity, left)
            if self._pabs(cur, 4 + take) > len(self.image):
                self.fail("OVERFLOW_TRUNCATED",
                          f"payload on overflow page {cur} runs past image end",
                          cur, 4, self._raw(cur, 4))
            self._claim(cur, "overflow",
                        f"{take} payload byte(s), next={nxt}",
                        prev_page, Location(prev_page, prev_off),
                        self._raw(prev_page, prev_off))
            chain.append(OverflowHop(cur, nxt, take))
            left -= take

            if left == 0:
                if nxt != 0:
                    self.fail("OVERFLOW_TOO_LONG",
                              f"overflow chain covered its {remaining} "
                              f"declared byte(s) but page {cur} still points "
                              f"to page {nxt}",
                              cur, 0, self._raw(cur, 0))
                return chain
            if nxt == 0:
                self.fail("OVERFLOW_PREMATURE_END",
                          f"overflow chain ends on page {cur} with {left} "
                          "payload byte(s) outstanding",
                          cur, 0, self._raw(cur, 0))
            if take < capacity:
                # A short (final-sized) page appeared before the payload was
                # fully covered -> chain geometry is broken.
                self.fail("OVERFLOW_SHORT_PAGE",
                          f"overflow page {cur} holds only {take} byte(s) but "
                          f"{left} byte(s) remain",
                          cur, 0, self._raw(cur, 0))
            prev_page, prev_off = cur, 0
            cur = nxt

    # --------------------------------------------------------------- free list

    def walk_free_list(self) -> None:
        trunk = self._freelist_trunk
        expected_total = self._freelist_count
        # The header free-list pointers physically live inside page 1.
        prev_page, prev_off = 1, 32
        seen: Set[int] = set()
        hops = 0
        while trunk != 0:
            if not (1 <= trunk <= self.page_count):
                self.fail("FREELIST_TRUNK_OOB",
                          f"free-list trunk page {trunk} outside 1.."
                          f"{self.page_count}",
                          prev_page, prev_off,
                          self._raw(prev_page, prev_off))
            if trunk in seen:
                self.fail("FREELIST_CYCLE",
                          f"free-list trunk chain cycles at page {trunk}",
                          prev_page, prev_off,
                          self._raw(prev_page, prev_off))
            if trunk in self.owners:
                existing = self.owners[trunk]
                self.fail("LIVE_PAGE_ON_FREELIST",
                          f"live page {trunk} ({existing.owner_role}, "
                          f"{existing.detail}) is linked into the free-page "
                          "trunk chain",
                          prev_page, prev_off,
                          self._raw(prev_page, prev_off))
            seen.add(trunk)

            hdr = 100 if trunk == 1 else 0
            nxt = _u32(self.image, self._pabs(trunk, hdr))
            n_leaves = _u32(self.image, self._pabs(trunk, hdr + 4))
            array_end_off = hdr + 8 + n_leaves * 4
            if array_end_off > self.page_size:
                self.fail("FREELIST_LEAF_ARRAY_OVERRUN",
                          f"trunk page {trunk} declares {n_leaves} leaf "
                          "pointers that overrun the page",
                          trunk, hdr + 4, self._raw(trunk, hdr + 4))
            self._claim(trunk, "free-trunk",
                        f"{n_leaves} free-leaf pointer(s), next={nxt}",
                        prev_page, Location(prev_page, prev_off),
                        self._raw(prev_page, prev_off))
            self.free_trunk_chain.append(trunk)

            for i in range(n_leaves):
                p_off = hdr + 8 + i * 4
                leaf = _u32(self.image, self._pabs(trunk, p_off))
                if leaf == 0:
                    self.fail("FREELIST_NULL_LEAF",
                              f"zero free-leaf pointer in trunk {trunk} "
                              f"slot {i}",
                              trunk, p_off, 0)
                if not (1 <= leaf <= self.page_count):
                    self.fail("FREELIST_LEAF_OOB",
                              f"free-leaf page {leaf} outside 1.."
                              f"{self.page_count}",
                              trunk, p_off, self._raw(trunk, p_off))
                if leaf in seen:
                    self.fail("FREELIST_DUPLICATE_PAGE",
                              f"free page {leaf} appears more than once in "
                              "the free list",
                              trunk, p_off, self._raw(trunk, p_off))
                if leaf in self.owners:
                    existing = self.owners[leaf]
                    self.fail("LIVE_PAGE_ON_FREELIST",
                                  f"live page {leaf} ({existing.owner_role}) "
                                  "is hung off a free-list trunk",
                                  trunk, p_off, self._raw(trunk, p_off))
                seen.add(leaf)
                self.free_leaf_pages.append(leaf)
                self._claim(leaf, "free-leaf",
                            f"free leaf reached from trunk {trunk}",
                            trunk, Location(trunk, p_off),
                            self._raw(trunk, p_off))

            prev_page, prev_off = trunk, hdr
            trunk = nxt
            hops += 1
            if hops > self.page_count:
                self.fail("FREELIST_CYCLE",
                          "free-list trunk chain does not terminate",
                          prev_page, prev_off,
                          self._raw(prev_page, prev_off))

        actual_total = len(self.free_trunk_chain) + len(self.free_leaf_pages)
        if expected_total != actual_total:
            self.fail("FREELIST_COUNT_MISMATCH",
                      f"header declares {expected_total} free pages but chain "
                      f"contains {actual_total}",
                      0, 36, self.image[36])
        self.checked.append("free-page trunk chain parsed, acyclic and "
                            "disjoint from live/overflow pages")

    # ------------------------------------------------------------------ run

    def run(self) -> SnapshotReport:
        try:
            self.verify_header()
            # Tree first: a live page that also shows up on the free list is
            # then reported at the free-list reference site.
            self.walk_tree()
            self.walk_free_list()
            self.checked.append("unique page ownership: btree / overflow / "
                                "free chain are pairwise disjoint")
        except Violation as exc:
            return self._report(False, exc)
        return self._report(True, None)

    def _report(self, accepted: bool,
                violation: Optional[Violation]) -> SnapshotReport:
        keys = [k for o in self.owners.values()
                if o.owner_role == "table-leaf" for k in o.row_keys]
        rng = (min(keys), max(keys)) if keys else None
        return SnapshotReport(
            accepted=accepted,
            page_size=self.page_size,
            page_count=self.page_count,
            root_page=self.root_page,
            owners=self.owners,
            first_violation=violation,
            row_key_range=rng,
            subtree_ranges=sorted(self.subtree_ranges, key=lambda r: r.page),
            overflow_chains=self.overflow_chains,
            free_trunk_chain=self.free_trunk_chain,
            free_leaf_pages=self.free_leaf_pages,
            checked_constraints=self.checked)


def verify_snapshot(image: bytes, root_page: int) -> SnapshotReport:
    return SnapshotVerifier(image, root_page).run()
