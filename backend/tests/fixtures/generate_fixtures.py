"""Generate small, *real* forensic test fixtures for Svetovid's integration tests.

Outputs (into this directory unless ``--out`` is given):
    security.evtx  — a structurally valid Windows EVTX with a handful of
                     recognizable security events (Event ID 4624 login and
                     4688 process creation). Detectable by the scanner via the
                     ``ElfFile\\x00`` magic AND parseable by EvtxECmd / Chainsaw
                     (real ELFChnk + BinXml records, not just a magic stub).
    capture.pcap   — a minimal valid libpcap file (global header + one TCP
                     packet record) for G07 / network-signature testing.

Why a hand-rolled writer instead of a library?
    ``python-evtx`` (the only widely-used Python EVTX package) is a *reader*
    only — there is no maintained pure-Python EVTX writer, and shelling out to
    PowerShell-on-Wine is far too heavy for a fixture. So we hand-encode the
    ELFChnk + BinXml structures per the MS-EVEN6 / libevtx format spec. The
    result is a genuine EVTX that real parsers (Chainsaw, EvtxECmd,
    python-evtx, libevtx) accept.

Format references (Joachim Metz's libevtx docs):
  * EVTX file header:  4096 bytes, magic ``ElfFile\\x00``.
  * Chunk ("ELFChnk"): 65536 bytes, magic ``ElfChnk\\x00``.
  * Each chunk has its own header, a name/string table, a template table,
    and an array of record tokens; records themselves carry their own
    24-byte header (magic ``\\x2a\\x2a\\x00\\x00``) + BinXml payload.

Run::
    /opt/anaconda3/bin/python3 backend/tests/fixtures/generate_fixtures.py
"""
from __future__ import annotations

import argparse
import io
import struct
import sys
from pathlib import Path
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# BinXml system tokens (subset of the Windows BinXml vocabulary).
# Values taken straight from python-evtx Nodes.SYSTEM_TOKENS — they are the
# exact byte values real EVTX writers and readers agree on.
# ---------------------------------------------------------------------------
TOK_END_OF_STREAM = 0x00      # sentinel terminating a BinXml stream
TOK_OPEN_START_ELEMENT = 0x01 # <element>      (low nibble=1; high nibble=flags)
TOK_CLOSE_START_ELEMENT = 0x02
TOK_CLOSE_EMPTY_ELEMENT = 0x03
TOK_CLOSE_ELEMENT = 0x04      # </element>
TOK_ATTRIBUTE = 0x06          # attribute (name via string_offset, then value)
TOK_TEMPLATE_INSTANCE = 0x0C  # references a template definition (resident or not)
TOK_NORMAL_SUBSTITUTION = 0x0D # a value-substitution placeholder: index + type
TOK_START_OF_STREAM = 0x0F    # start of a BinXml fragment

# Value types (the "type" byte of a NormalSubstitution token + the record
# value-list descriptors — they must agree). These match python-evtx
# Nodes.NODE_TYPES exactly (WSTRING=0x01, UNSIGNED_WORD=0x06, FILETIME=0x11).
VT_STRING = 0x01      # WSTRING — null-terminated UTF-16LE, length from descriptor
VT_UINT16 = 0x06      # UNSIGNED_WORD (2 bytes)
VT_UINT32 = 0x08      # UNSIGNED_DWORD (4 bytes)
VT_UINT64 = 0x0A      # UNSIGNED_QWORD (8 bytes)
VT_FILETIME = 0x11    # FILETIME (8 bytes, 100-ns ticks since 1601)
VT_BLOB = 0x0E        # BINARY

EVTX_FILE_MAGIC = b"ElfFile\x00"
EVTX_CHUNK_MAGIC = b"ElfChnk\x00"
EVTX_RECORD_MAGIC = b"\x2a\x2a\x00\x00"

# ---------------------------------------------------------------------------
# Low-level BinXml / EVTX encoders
# ---------------------------------------------------------------------------

def _u8(v: int) -> bytes:
    return struct.pack("<B", v & 0xFF)

def _u16(v: int) -> bytes:
    return struct.pack("<H", v & 0xFFFF)

def _u32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)

def _u48(v: int) -> bytes:
    return struct.pack("<HI", v & 0xFFFFFFFFFFFF, 0)[:6]

def _u64(v: int) -> bytes:
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)

def _utf16(s: str) -> bytes:
    return s.encode("utf-16-le")

def _hash(name: str) -> int:
    """The ELFChnk name-table hash (libevtx: ELFCHNK_HASH).

    A 31-bit multiplicative hash over the UTF-16LE bytes of the name. Used to
    place a name in the chunk's name/hash table so template-instance records
    can reference element/attribute names by index.
    """
    h = 0
    for b in _utf16(name):
        h = (h * 0x1003F + b) & 0x7FFFFFFF
    return h


class BinXmlTemplate:
    """A BinXml template definition (the resident template inside token 0x0C).

    A template is a self-contained BinXml token stream that uses *value
    substitution*: element/attribute names are written INLINE (as
    NameStringNode bytes embedded in the element/attribute header), and the
    data values are filled in per record via NormalSubstitution (0x0D) tokens.
    This lets many 4624 events share one compiled template and differ only in
    their value list.

    Builder model: the public ``add_*``/``close_*`` methods append typed
    instruction records to ``self.ops`` (an AST). ``finalize`` then serializes
    the AST to bytes in a single pass, computing the per-element flag bits and
    the attribute-data-size field that the on-disk format requires. This avoids
    any fragile post-hoc byte patching.

    On-disk format (verified byte-for-byte against a real Windows Security EVTX
    using both python-evtx and Eric Zimmerman's EvtxECmd):

      OpenStartElement, no attributes  (token 0x01):
        [0x01] unknown0(2) size(4) string_offset(4) <inline NameStringNode>
      OpenStartElement, has attributes (token 0x41, flag bit 0x4):
        [0x41] unknown0(2) size(4) string_offset(4) <inline NameStringNode>
              attr_data_size(4)   # bytes from here through the element's close
        ... attributes + content + close ...
      Attribute, value is a substitution (token 0x46, flag bit 0x4):
        [0x46] string_offset(4) <inline NameStringNode>   # value = next node
      Attribute, value is literal (token 0x06):
        [0x06] string_offset(4) <inline NameStringNode>   # value = next node
      NormalSubstitution (0x0D): index(2) type(1)
      CloseStartElement (0x02) / CloseEmptyElement (0x03) / CloseElement (0x04)
      EndOfStream (0x00)
    """

    # Instruction opcodes for the in-memory AST.
    _OP_STREAM_START = "stream_start"  # StartOfStream token (0x0F) — body preamble
    _OP_ELEM_OPEN = "elem_open"     # (name) — must be matched by close_*
    _OP_ATTR = "attr"               # (name) — value is the immediately-following op
    _OP_SUB = "sub"                 # (value_type)
    _OP_CLOSE_START = "close_start"
    _OP_CLOSE_EMPTY = "close_empty"
    _OP_CLOSE = "close"
    _OP_END = "end"

    def __init__(self) -> None:
        self.names: list[str] = []
        self._name_idx: dict[str, int] = {}
        self.ops: list[tuple] = []
        # ordered value types, one per add_value_slot() call
        self.value_types: list[int] = []

    def _name_ref(self, name: str) -> None:
        if name not in self._name_idx:
            self._name_idx[name] = len(self.names)
            self.names.append(name)

    @staticmethod
    def _inline_name_node(name: str) -> bytes:
        """A NameStringNode written inline: next_offset(4) + hash(2) +
        string_length(2) + UTF-16LE name + 2-byte null terminator.

        python-evtx's ``NameStringNode.length()`` returns
        ``string_length*2 + 10`` (the trailing +2 is a null terminator that is
        physically present in the stream but not counted by ``string_length``),
        so the on-disk node is 8 header bytes + ``2*string_length`` string
        bytes + 2 null bytes. We must write exactly that many bytes or every
        token after this name will be misaligned (the element's tag_length is
        extended by the name's full ``length()``).
        """
        h = _hash(name)
        enc = _utf16(name)
        return _u32(0) + _u16(h & 0xFFFF) + _u16(len(enc) // 2) + enc + b"\x00\x00"

    def add_element(self, name: str) -> None:
        self._name_ref(name)
        self.ops.append((self._OP_ELEM_OPEN, name))

    def add_attr(self, name: str) -> None:
        self._name_ref(name)
        self.ops.append((self._OP_ATTR, name))

    def add_value_slot(self, value_type: int) -> None:
        """A NormalSubstitution (0x0D): index(2) + type(1). Filled per record."""
        idx = len(self.value_types)
        self.value_types.append(value_type)
        self.ops.append((self._OP_SUB, idx, value_type))

    def close_start_element(self) -> None:
        self.ops.append((self._OP_CLOSE_START,))

    def close_empty_element(self) -> None:
        self.ops.append((self._OP_CLOSE_EMPTY,))

    def close_element(self) -> None:
        self.ops.append((self._OP_CLOSE,))

    def stream_start(self) -> None:
        """Emit a StartOfStream token (0x0F 0x01 0x00 0x01) — the 4-byte
        preamble that begins every BinXml template body (and every record's
        BinXml fragment). Real EVTX writers always include it."""
        self.ops.append((self._OP_STREAM_START,))

    def end(self) -> None:
        self.ops.append((self._OP_END,))

    # -- serialization -------------------------------------------------------

    def _serialize(self, ops: list[tuple], base_off: int,
                   name_slots: list[tuple[int, int, str]],
                   body_base: int) -> bytes:
        """Serialize an op-list to BinXml bytes.

        ``base_off`` is the chunk-relative offset where the first byte of this
        serialized run will live (so inline name string_offsets can be patched
        to chunk-relative offsets). ``body_base`` is the chunk-relative offset
        of the OUTER body's first byte (used so name-slot positions, which are
        recorded relative to this run's local buffer, can be converted to
        body-relative positions for the final patch pass).

        Element flag bits and the attr_data_size field are computed here from
        the op structure. ``name_slots`` accumulates ``(body_rel_offset, name)``.
        """
        out = bytearray()
        # Body-relative offset of this run's first byte. base_off is the
        # chunk-relative offset of this run; body_base is the chunk-relative
        # offset of the outermost body. Their difference is this run's position
        # within the body, which is what name-slot patching needs.
        run_body_off = base_off - body_base

        def emit_name(name: str) -> None:
            # Record the slot as a BODY-relative offset so the final patch pass
            # in finalize() can locate it. Use extend() (not +=) so `out` stays
            # a free (closure) variable rather than a local one.
            name_slots.append((run_body_off + len(out), name))
            out.extend(b"\x00\x00\x00\x00")       # string_offset placeholder
            out.extend(self._inline_name_node(name))

        i = 0
        while i < len(ops):
            op = ops[i]
            if op[0] == self._OP_ELEM_OPEN:
                # Collect this element's attributes (any _OP_ATTR before the
                # matching close) to decide the flag bit.
                has_attrs = False
                for j in range(i + 1, len(ops)):
                    if ops[j][0] in (self._OP_CLOSE_START, self._OP_CLOSE_EMPTY):
                        break
                    if ops[j][0] == self._OP_ATTR:
                        has_attrs = True
                        break
                token = TOK_OPEN_START_ELEMENT | (0x40 if has_attrs else 0x00)
                out += _u8(token)
                out += _u16(0xFFFF)               # SubstitutionSlot = -1 (none)
                size_slot = len(out)
                out += _u32(0)                    # Size (patched below)
                emit_name(op[1])
                # Locate the matching close so we know the element's full extent.
                # Both _OP_CLOSE and _OP_CLOSE_EMPTY terminate an element, so
                # both decrement the open-element depth (and either one at depth
                # 0 is this element's own close).
                depth = 0
                end = 0
                for k, kop in enumerate(ops[i + 1:], start=0):
                    if kop[0] == self._OP_ELEM_OPEN:
                        depth += 1
                    elif kop[0] in (self._OP_CLOSE, self._OP_CLOSE_EMPTY):
                        if depth == 0:
                            end = k + 1
                            break
                        depth -= 1
                rest_span = ops[i + 1: i + 1 + end]
                if has_attrs:
                    # Split rest_span into the attribute ops (each _OP_ATTR plus
                    # its value op) vs. the trailing close/content. EvtxECmd
                    # reads attributes in an attrSize-bounded loop, THEN reads
                    # one CloseStartElement/CloseEmptyElement tag, THEN reads
                    # remaining nodes in a Size-bounded loop. So attrSize must
                    # cover ONLY the attributes, not the close tag.
                    attr_count = 0
                    for kop in rest_span:
                        if kop[0] == self._OP_ATTR:
                            attr_count += 1
                        else:
                            break
                    # attr ops + their value ops (the value follows each attr)
                    attr_ops = []
                    k = 0
                    while k < len(rest_span) and rest_span[k][0] == self._OP_ATTR:
                        attr_ops.append(rest_span[k])      # the _OP_ATTR
                        k += 1
                        # the attribute's value is the immediately-following op
                        if k < len(rest_span):
                            attr_ops.append(rest_span[k])
                            k += 1
                    after_attr = rest_span[k:]
                    attr_bytes = self._serialize(
                        attr_ops, base_off + len(out) + 4, name_slots, body_base)
                    out += _u32(len(attr_bytes))           # attr_data_size
                    out += attr_bytes
                    rest_bytes = self._serialize(
                        after_attr, base_off + len(out), name_slots, body_base)
                    out += rest_bytes
                else:
                    elem_inner = self._serialize(
                        rest_span, base_off + len(out), name_slots, body_base)
                    out += elem_inner
                # Size = bytes from startPos (just after the Size field) through
                # the end of the element (its close tag).
                out[size_slot:size_slot + 4] = _u32(len(out) - (size_slot + 4))
                i += 1 + end
                continue
            if op[0] == self._OP_STREAM_START:
                out += _u8(TOK_START_OF_STREAM)
                out += _u8(0x01)
                out += _u16(0x0001)
                i += 1
                continue
            if op[0] == self._OP_ATTR:
                # Attribute value is the next op (always a substitution here),
                # so use flag 0x4 (token 0x46) per the real format.
                out += _u8(TOK_ATTRIBUTE | 0x40)
                emit_name(op[1])
                i += 1
                continue
            if op[0] == self._OP_SUB:
                out += _u8(TOK_NORMAL_SUBSTITUTION)
                out += _u16(op[1])
                out += _u8(op[2])
                i += 1
                continue
            if op[0] == self._OP_CLOSE_START:
                out += _u8(TOK_CLOSE_START_ELEMENT)
                i += 1
                continue
            if op[0] == self._OP_CLOSE_EMPTY:
                out += _u8(TOK_CLOSE_EMPTY_ELEMENT)
                i += 1
                continue
            if op[0] == self._OP_CLOSE:
                out += _u8(TOK_CLOSE_ELEMENT)
                i += 1
                continue
            if op[0] == self._OP_END:
                out += _u8(TOK_END_OF_STREAM)
                i += 1
                continue
            raise ValueError(f"unknown op: {op!r}")
        return bytes(out)

    def finalize(self, body_chunk_off: int) -> bytes:
        """Serialize the op-list to bytes with all name string_offsets patched
        to their inline NameStringNode's chunk-relative offset.

        ``body_chunk_off`` is the chunk-relative offset where this body begins.
        Each inline name node lives right after its element/attribute header's
        string_offset dword, so its chunk-relative offset is
        ``body_chunk_off + slot_position + 4``. ``slot_position`` is
        body-relative (recorded during serialization).
        """
        name_slots: list[tuple[int, str]] = []
        body = self._serialize(self.ops, body_chunk_off, name_slots,
                               body_chunk_off)
        out = bytearray(body)
        for slot_off, _name in name_slots:
            name_abs = body_chunk_off + slot_off + 4
            out[slot_off:slot_off + 4] = _u32(name_abs)
        return bytes(out)


def _filetime(dt: datetime) -> int:
    """Python datetime → Windows FILETIME (100-ns ticks since 1601-01-01)."""
    unix = int(dt.replace(tzinfo=timezone.utc).timestamp())
    return (unix + 11644473600) * 10_000_000


def _encode_value(value_type: int, value: object) -> tuple[bytes, int]:
    """Encode one value for a record's value-list data region.

    Returns ``(data, type_byte)``. The descriptor ``size`` is ``len(data)``;
    there is NO inline length prefix — the value-list descriptor carries it
    (see ``RootNode.substitutions`` in python-evtx).
    """
    if value_type == VT_STRING:
        # WSTRING: UTF-16LE, null-terminated. The trailing \x00\x00 is part of
        # the stored value (WstringTypeNode.string() rstrips it on read).
        return _utf16(str(value)) + b"\x00\x00", value_type
    if value_type == VT_UINT16:
        return _u16(int(value)), value_type
    if value_type == VT_UINT32:
        return _u32(int(value)), value_type
    if value_type == VT_UINT64:
        return _u64(int(value)), value_type
    if value_type == VT_FILETIME:
        return _u64(int(value)), value_type
    if value_type == VT_BLOB:
        data = bytes(value) if isinstance(value, (bytes, bytearray)) else str(value).encode()
        return data, value_type
    raise ValueError(f"unsupported value type: {value_type:#x}")


# ---------------------------------------------------------------------------
# EVTX file assembler
# ---------------------------------------------------------------------------

def _pad_to(buf: bytearray, size: int, fill: int = 0) -> None:
    if len(buf) < size:
        buf.extend(bytes(size - len(buf)) * (b"\x00" if fill == 0 else bytes([fill])))


def build_template_for_event() -> BinXmlTemplate:
    """One template covering all our sample events.

    The events share the same XML skeleton::

        <Event>
          <Provider Name='$p'/>          <!-- empty element: attr only -->
          <EventID>$id</EventID>          <!-- element with a text value -->
          <TimeCreated SystemTime='$t'/>
          <Channel>$c</Channel>
          <Computer>$m</Computer>
          <EventData>
            <Data Name='$u'>$v</Data>     <!-- element with attr + text value -->
          </EventData>
        </Event>

    BinXml element encoding (per python-evtx node parsing):
      * non-empty element:  OpenStart(0x01) [attrs] CloseStart(0x02) [body] Close(0x04)
      * empty element:      OpenStart(0x01) [attrs] CloseEmpty(0x03)
      * each attribute:     Attr(0x06)+name_offset, then its value node (a 0x0D sub)
    """
    t = BinXmlTemplate()
    # Every BinXml body starts with a StartOfStream token.
    t.stream_start()
    # <Event> ... </Event>
    t.add_element("Event")
    t.close_start_element()
    # <Provider Name='$p'/>  (empty: attr only)
    t.add_element("Provider")
    t.add_attr("Name"); t.add_value_slot(VT_STRING)
    t.close_empty_element()
    # <EventID>$id</EventID>
    t.add_element("EventID")
    t.close_start_element()
    t.add_value_slot(VT_UINT16)
    t.close_element()
    # <TimeCreated SystemTime='$t'/>
    t.add_element("TimeCreated")
    t.add_attr("SystemTime"); t.add_value_slot(VT_FILETIME)
    t.close_empty_element()
    # <Channel>$c</Channel>
    t.add_element("Channel")
    t.close_start_element()
    t.add_value_slot(VT_STRING)
    t.close_element()
    # <Computer>$m</Computer>
    t.add_element("Computer")
    t.close_start_element()
    t.add_value_slot(VT_STRING)
    t.close_element()
    # <EventData><Data Name='$u'>$v</Data></EventData>
    t.add_element("EventData")
    t.close_start_element()
    t.add_element("Data")
    t.add_attr("Name"); t.add_value_slot(VT_STRING)
    t.close_start_element()
    t.add_value_slot(VT_STRING)
    t.close_element()                    # </Data>
    t.close_element()                    # </EventData>
    t.close_element()                    # </Event>
    t.end()
    return t


def _render_record_binxml(template: BinXmlTemplate,
                          values: list[tuple[int, object]],
                          record_chunk_off: int) -> bytes:
    """Render one record's BinXml stream.

    Layout (matching python-evtx RootNode parsing):
      1. StreamStart token (0x0F): [0x0F][0x01][0x00 0x01]                 (4 B)
      2. TemplateInstance (0x0C):  [0x0C][flags=0x01][template_id][tmpl_off] (10 B)
      3. Resident TemplateNode:    [next_off][template_id][guid][data_len]  (24 B)
                                   + data_len bytes of finalized BinXml body
      4. Value-list descriptor table: sub_count(4) + [size(2)+type(1)+pad(1)] * N
      5. Value data: each value's bytes, concatenated

    ``template_offset`` is the chunk-relative offset of the resident TemplateNode
    (its ``next_offset`` field), which sits 10 bytes after the 0x0C opcode
    (opcode + version + template_id + template_offset = 10). Both python-evtx and
    Eric Zimmerman's EvtxECmd resolve the template via this offset — EvtxECmd via
    a fallback that re-reads the 0x0C at ``offset - 10``. Element/attribute names
    are written INLINE in the body and their ``string_offset`` values are patched
    by ``BinXmlTemplate.finalize(body_chunk_off)`` to point at those inline nodes.

    The resident-template layout (verified against a real Windows EVTX
    byte-for-byte), from the 0x0C opcode::

        opcode(1) version(1) template_id(4) template_offset(4)   <- 10 bytes
        next_offset(4) template_id(4) guid(16) data_length(4)    <- TemplateNode (0x18)
        <body>

    The TemplateInstance's ``template_offset`` field (byte 6) points forward to
    the TemplateNode's ``next_offset`` field (byte 10). The TemplateNode's
    ``template_id`` (byte 14) repeats the instance id; ``guid`` is 16 bytes
    (python-evtx declares it overlapping the id at +0x04, EvtxECmd reads it at
    +0x0E — both agree on the byte positions). Total header = 0x22 bytes.
    """
    out = bytearray()
    header_size = 0x18                      # record header (magic/size/record_num/filetime)

    # 1. StreamStart
    out += _u8(TOK_START_OF_STREAM)
    out += _u8(0x01)
    out += _u16(0x0001)

    # 2. TemplateInstance (0x0C) + resident TemplateNode header.
    TEMPLATE_ID = 0x6F8C0B24                  # arbitrary, stable per template
    opcode_abs = record_chunk_off + header_size + len(out)   # 0x0C opcode chunk offset
    out += _u8(TOK_TEMPLATE_INSTANCE)
    out += _u8(0x01)                          # version
    out += _u32(TEMPLATE_ID)                  # template_id (instance)
    # template_offset -> the TemplateNode's next_offset field (opcode + 10).
    template_node_abs = opcode_abs + 10
    out += _u32(template_node_abs)            # template_offset
    # TemplateNode (0x18 bytes from next_offset): next_offset(4) + guid(16) +
    # data_length(4). NB the guid's first 4 bytes overlap the template_id
    # (python-evtx declares guid at +0x04 overlapping id; EvtxECmd reads a
    # 16-byte guid at +0x0E and length at +0x1E). So we write the id as the
    # first 4 bytes of the 16-byte guid, then data_length. The body begins at
    # template_node_abs + 0x18.
    out += _u32(0)                            # next_offset (no other templates)
    out += _u32(TEMPLATE_ID)                  # guid bytes 0..3 (== template_id)
    out += b"\x00" * 12                       # guid bytes 4..15
    body_chunk_off = template_node_abs + 0x18
    body = template.finalize(body_chunk_off)
    out += _u32(len(body))                    # data_length
    out += body

    # 4 + 5. Value-list descriptor table + value data.
    encoded = [_encode_value(vt, vv) for vt, vv in values]
    out += _u32(len(encoded))
    for data, vtype in encoded:
        out += _u16(len(data))                # size
        out += _u8(vtype)                     # type
        out += _u8(0x00)                      # padding (descriptor is 4 bytes)
    for data, _vtype in encoded:
        out += data

    return bytes(out)


def _record_header(record_id: int, timestamp_ft: int, payload: bytes) -> bytes:
    """A 24-byte EVTX record header wrapping a BinXml payload."""
    size = 24 + len(payload) + 4          # +4 for the trailing copy of size
    h = bytearray()
    h += EVTX_RECORD_MAGIC                 # magic 0x2a2a0000
    h += _u32(size)                        # record size
    h += _u64(record_id)                   # event record id
    h += _u64(timestamp_ft)                # creation time (FILETIME)
    h += payload
    h += _u32(size)                        # trailing size copy (libevtx expects it)
    return bytes(h)


def build_evtx(events: list[dict]) -> bytes:
    """Assemble a complete EVTX byte blob from a list of event dicts.

    Each event dict has: provider, event_id, time (datetime), channel,
    computer, user, value (the EventData value, e.g. a process path).

    The layout follows the libevtx / python-evtx spec exactly:
      * FileHeader (0x1000 bytes): magic, oldest/current chunk, next record,
        header_size=128, minor=1/major=3 versions, header_chunk_size=0x1000,
        chunk_count, flags=0, checksum=CRC32([0..0x78]).
      * One ELFChnk (0x10000 bytes): ChunkHeader (first 0x200 bytes) with the
        64-bucket name table at 0x80 and the 32-bucket template table at 0x180
        (both empty here), then records from 0x200 onward. Each record carries
        its template definition inline (resident template, token 0x0C), and
        element/attribute names are written INLINE in the BinXml body — so the
        chunk-level name/template tables are empty. python-evtx discovers the
        names as it parses each record's tokens via ``chunk.add_string``.
    """
    import zlib
    template = build_template_for_event()

    records_off = 0x200                     # records always start at chunk offset 512

    # ---- render records (names are inline, so no separate name table needed) ----
    records_blob = bytearray()
    for i, ev in enumerate(events, start=1):
        ordered = [
            (VT_STRING, ev["provider"]),
            (VT_UINT16, ev["event_id"]),
            (VT_FILETIME, _filetime(ev["time"])),
            (VT_STRING, ev["channel"]),
            (VT_STRING, ev["computer"]),
            (VT_STRING, ev["user"]),
            (VT_STRING, ev["value"]),
        ]
        # This record's header sits at this absolute chunk offset (records are
        # appended sequentially from records_off).
        record_chunk_off = records_off + len(records_blob)
        payload = _render_record_binxml(template, ordered, record_chunk_off)
        records_blob += _record_header(i, _filetime(ev["time"]), payload)

    # ---- assemble the chunk ----
    chunk = bytearray(0x10000)
    # ChunkHeader fields
    chunk[0x0:0x8] = EVTX_CHUNK_MAGIC       # "ElfChnk\x00"
    chunk[0x8:0x10] = _u64(1)               # file_first_record_number
    chunk[0x10:0x18] = _u64(len(events))    # file_last_record_number
    chunk[0x18:0x20] = _u64(1)              # log_first_record_number
    chunk[0x20:0x28] = _u64(len(events))    # log_last_record_number
    chunk[0x28:0x2C] = _u32(0x80)           # header_size (size of the header region)
    chunk[0x30:0x34] = _u32(records_off + len(records_blob))  # next_record_offset
    # (last_record_offset at 0x2C unused for iteration; leave 0)
    # Name table (0x80) and template table (0x180) stay zeroed — names are
    # inline in the records and templates are resident.

    # Records region (0x200 onward).
    chunk[records_off:records_off + len(records_blob)] = records_blob

    # Checksums (computed last, over the exact byte ranges python-evtx uses).
    # header_checksum = CRC32([0x0..0x78] + [0x80..0x180]), stored at 0x7C.
    hdr_cs = zlib.crc32(bytes(chunk[0x0:0x78]) + bytes(chunk[0x80:0x180])) & 0xFFFFFFFF
    chunk[0x7C:0x80] = _u32(hdr_cs)
    # data_checksum = CRC32([0x200..next_record_offset]), stored at 0x3C.
    data_cs = zlib.crc32(bytes(chunk[0x200:records_off + len(records_blob)])) & 0xFFFFFFFF
    chunk[0x3C:0x40] = _u32(data_cs)

    # ---- file header (0x1000 bytes) ----
    header = bytearray(0x1000)
    header[0x0:0x8] = EVTX_FILE_MAGIC       # "ElfFile\x00"
    header[0x8:0x10] = _u64(0)              # oldest_chunk
    header[0x10:0x18] = _u64(0)             # current_chunk_number (0 = first chunk)
    header[0x18:0x20] = _u64(len(events) + 1)  # next_record_number
    header[0x20:0x24] = _u32(128)           # header_size
    header[0x24:0x26] = _u16(1)             # minor_version = 1
    header[0x26:0x28] = _u16(3)             # major_version = 3
    header[0x28:0x2A] = _u16(0x1000)        # header_chunk_size
    header[0x2A:0x2C] = _u16(1)             # chunk_count = 1
    # flags at 0x78, checksum at 0x7C = CRC32([0x0..0x78])
    hcs = zlib.crc32(bytes(header[0x0:0x78])) & 0xFFFFFFFF
    header[0x7C:0x80] = _u32(hcs)

    return bytes(header) + bytes(chunk)


# ---------------------------------------------------------------------------
# PCAP (libpcap) writer
# ---------------------------------------------------------------------------

def build_pcap() -> bytes:
    """A minimal valid libpcap file: global header + one TCP-over-IP packet.

    Packet = Ethernet → IPv4 → TCP, SYN from 10.0.0.5:54321 to 93.184.216.34:80.
    Enough for tshark/zeek to decode protocol layers in the network test.
    """
    out = bytearray()
    # Global header: magic (LE, μs), ver 2.4, thiszone=0, sigfigs=0, snaplen,
    # network=1 (LINKTYPE_ETHERNET).
    out += struct.pack(
        "<IHHiIII",
        0xA1B2C3D4,  # magic
        2, 4,        # version major/minor
        0, 0,        # thiszone, sigfigs
        65535,       # snaplen
        1,           # LINKTYPE_ETHERNET
    )
    # Build the packet layers (bottom-up).
    src_ip = bytes([10, 0, 0, 5])
    dst_ip = bytes([93, 184, 216, 34])
    tcp = struct.pack(
        "!HHIIBBHHH",
        54321, 80,      # src/dst port
        100, 1,         # seq, ack
        0x50, 0x02,     # data offset (5), flags (SYN)
        65535,          # window
        0,              # checksum (0 — fine for fixture)
        0,              # urgent pointer
    )
    # IPv4 total length = 20 (ip) + 20 (tcp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0,        # ver+ihl, dscp/ecn
        20 + len(tcp),  # total length
        0x1234, 0x4000, # id, flags+frag (DF)
        64, 6,          # ttl, protocol (TCP)
        0,              # checksum (0 — fine for fixture)
        src_ip, dst_ip,
    )
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    pkt = eth + ip + tcp
    # Packet record header: ts_sec, ts_usec, incl_len, orig_len.
    out += struct.pack("<IIII", 0x67A70000, 0, len(pkt), len(pkt))
    out += pkt
    return bytes(out)


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

def _now(year: int = 2024, month: int = 6, day: int = 1, hour: int = 9, minute: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, 0, tzinfo=timezone.utc)


def sample_events() -> list[dict]:
    """A handful of recognizable Windows security events.

    Event ID 4624 = successful logon; 4688 = process creation. Both are the
    bread-and-butter of an attack-timeline investigation and what Sigma rules
    key on for the G01 goal.
    """
    return [
        {
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4624,
            "time": _now(day=1, hour=9, minute=5),
            "channel": "Security",
            "computer": "WIN-FORENSIC",
            "user": "Administrator",
            "value": "interactive",
        },
        {
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4688,
            "time": _now(day=1, hour=9, minute=6),
            "channel": "Security",
            "computer": "WIN-FORENSIC",
            "user": "Administrator",
            "value": r"C:\Windows\System32\powershell.exe",
        },
        {
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4688,
            "time": _now(day=1, hour=9, minute=7),
            "channel": "Security",
            "computer": "WIN-FORENSIC",
            "user": "Administrator",
            "value": r"C:\Users\Public\payload.exe",
        },
        {
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4624,
            "time": _now(day=1, hour=10, minute=15),
            "channel": "Security",
            "computer": "WIN-FORENSIC",
            "user": "svc_backup",
            "value": "network",
        },
    ]


def write_fixtures(out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    evtx_path = out_dir / "security.evtx"
    evtx_path.write_bytes(build_evtx(sample_events()))
    pcap_path = out_dir / "capture.pcap"
    pcap_path.write_bytes(build_pcap())
    return {"evtx": evtx_path, "pcap": pcap_path}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path,
                   default=Path(__file__).resolve().parent,
                   help="output directory (default: this script's dir)")
    args = p.parse_args(argv)
    paths = write_fixtures(args.out)
    for kind, path in paths.items():
        print(f"wrote {kind}: {path} ({path.stat().st_size} bytes)")
    # Quick self-check: re-parse the EVTX with python-evtx if importable.
    # The PyPI `evtx` package internally does `import Evtx.Views` (capital E),
    # so the lowercase package must be aliased under the `Evtx` name first.
    # Ordering matters: the top-level alias MUST be registered BEFORE any
    # submodule is imported, because importing e.g. evtx.Views triggers the
    # `import Evtx.Nodes` line inside Views.py. We also alias the submodules
    # themselves so class identity is preserved (isinstance checks in
    # Views.render_root_node_with_subs use `Evtx.Nodes.Foo`, which must be the
    # SAME class object as `evtx.Nodes.Foo`, or every record renders as "").
    parsed: int | None = None
    event_ids: list[str] = []
    last_err: object = None
    try:
        import evtx as _evtx_pkg                # __init__ only; no submodule imports
        sys.modules.setdefault("Evtx", _evtx_pkg)
        import evtx.Views as _v
        import evtx.Nodes as _n
        import evtx.BinaryParser as _bp
        import evtx.Evtx as _e
        sys.modules.setdefault("Evtx.Views", _v)
        sys.modules.setdefault("Evtx.Nodes", _n)
        sys.modules.setdefault("Evtx.BinaryParser", _bp)
        sys.modules.setdefault("Evtx.Evtx", _e)
        from evtx.Evtx import Evtx
        import re
        with Evtx(str(paths["evtx"])) as log:
            for rec in log.records():
                parsed = (parsed or 0) + 1
                m = re.search(r"<EventID[^>]*>\s*(\d+)", rec.xml())
                if m:
                    event_ids.append(m.group(1))
    except Exception as e:  # noqa: BLE001 - env-dependent, best-effort
        last_err = e
    if parsed is not None:
        print(f"self-check: python-evtx parsed {parsed} record(s); "
              f"event_ids={event_ids}")
    else:
        print(f"self-check: python-evtx unavailable or parse failed ({last_err})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
