"""CRIU checkpoint parser tool wrapper.

Wraps a pure-Python CRIU ``.img`` parser that runs inside ``svetovid/base``
using only the standard library (``struct`` + manual protobuf wire-format
walking). NO protobuf library, NO ``crit``, NO ``protoc`` — the parser walks
the raw wire format from field-number tables baked into the source, so it stays
lightweight and portable across every base image.

A CRIU (Checkpoint/Restore In Userspace) dump is a directory of ``.img`` files:
length-prefixed Protocol Buffer messages preceded by a u32 magic number and
(in img_version 1) a legacy u64 addr. When investigating a compromised
container, a CRIU checkpoint captures the container's frozen state — process
tree, memory mappings, open files, network connections, and credentials.

This tool takes a ``evidence_subpath`` (the dump directory) and an
``analysis_type`` selector and returns structured rows tailored to that view:
process_tree, network, files, memory, credentials, or full.

CLI shape (inside the container / host fallback)::

    python3 -c '<PARSER>' <analysis_type> <dump_dir>

The parser emits one JSON object per row to stdout; the wrapper collects them,
persists a provenance copy at ``/work/criu_<analysis>.jsonl``, and emits
``report.timeline_entry`` / ``report.ioc`` events for notable findings
(suspicious network connections, processes).

The protobuf-wire helpers below (``_parse_pb_fields``, ``_read_img_file``,
``_interpret_*``) are defined at module level so the unit tests can exercise
them directly. The embedded ``_PARSER`` string carries the same logic so it can
run standalone in a subprocess (the sandbox process cannot import this module).
"""

from __future__ import annotations

import hashlib
import json
import socket
import struct
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult


# ===========================================================================
# Magic numbers — verified against the CRIU source (images/images.h).
# ===========================================================================

MAGIC = {
    "INVENTORY": 0x58311116,
    "PSTREE": 0x50273030,
    "CORE": 0x55053847,
    "MM": 0x57492820,
    "CREDS": 0x54023547,
    "FDINFO": 0x56213732,
    "FILES": 0x56303138,
    "REG_FILES": 0x50363636,
    "INETSK": 0x56443851,
    "UNIXSK": 0x54373943,
}

ANALYSIS_TYPES: dict[str, str] = {
    "process_tree": (
        "Process tree from pstree.img + core-*.img: PID / PPID / PGID / SID "
        "with the process name (comm), task state, and exit code."
    ),
    "network": (
        "Network connections from inetsk.img: 5-tuples (src_ip:port → "
        "dst_ip:port), protocol, TCP state. Flags suspicious external egress."
    ),
    "files": (
        "Open files from fdinfo-*.img + files.img + reg-files.img: fd, type, "
        "flags, and resolved file path / size / mode."
    ),
    "memory": (
        "Memory mappings from mm-*.img: each VMA's start/end/prot/flags with "
        "anonymous RWX regions flagged (code-injection indicator)."
    ),
    "credentials": (
        "Process credentials from creds-*.img: uid/euid/gid/egid, effective "
        "capabilities, and dangerous-capability flags (CAP_SYS_ADMIN, "
        "CAP_SYS_PTRACE, CAP_NET_ADMIN, CAP_DAC_OVERRIDE) + setuid-root."
    ),
    "full": (
        "Everything: process tree, network, files, memory, and credentials in "
        "one pass. Recommended first call — surfaces code-injection (anon RWX "
        "VMAs) and privilege-escalation (dangerous capabilities) findings."
    ),
}


# ===========================================================================
# Protobuf wire-format constants.
# ===========================================================================

_WIRE_VARINT = 0
_WIRE_64BIT = 1
_WIRE_LEN = 2
_WIRE_32BIT = 5

# VMA prot bitmask
PROT_READ, PROT_WRITE, PROT_EXEC = 1, 2, 4
# VMA status bitmask
VMA_AREA_REGULAR, VMA_AREA_ANON, VMA_AREA_FILE = 1, 2, 4
# fd types
FD_TYPES = {1: "REG", 2: "PIPE", 4: "INETSK", 5: "UNIXSK"}
# TCP states (subset)
TCP_STATES = {
    1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
    5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
    9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING",
}
# capability bits we flag as dangerous
CAP_BITS = {21: "CAP_SYS_ADMIN", 19: "CAP_SYS_PTRACE",
            12: "CAP_NET_ADMIN", 1: "CAP_DAC_OVERRIDE"}


# ===========================================================================
# Protobuf wire-format primitives (pure-Python, stdlib only).
# ===========================================================================

def _decode_varint(buf: bytes, pos: int) -> tuple[int, int]:
    """Decode a base-128 varint at ``pos``. Returns (value, new_pos)."""
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    return result, pos


def _parse_pb_fields(payload: bytes) -> dict[int, Any]:
    """Walk a protobuf payload, returning {field_number: value}.

    - Varint (wire 0) → int
    - 64-bit (wire 1) → int (little-endian u64)
    - Length-delimited (wire 2) → raw bytes (caller interprets)
    - 32-bit (wire 5) → int (little-endian u32)

    Repeated fields accumulate into a list. Non-repeated fields keep their last
    value; callers that expect repetition access the list form via
    :func:`_as_list`.
    """
    fields: dict[int, Any] = {}
    pos = 0
    n = len(payload)
    while pos < n:
        tag, pos = _decode_varint(payload, pos)
        field_number = tag >> 3
        wire_type = tag & 0x7
        if field_number == 0:
            raise ValueError(f"invalid field number 0 (tag={tag})")
        if wire_type == _WIRE_VARINT:
            value, pos = _decode_varint(payload, pos)
        elif wire_type == _WIRE_64BIT:
            if pos + 8 > n:
                raise ValueError("truncated 64-bit field")
            value = struct.unpack_from("<Q", payload, pos)[0]
            pos += 8
        elif wire_type == _WIRE_LEN:
            length, pos = _decode_varint(payload, pos)
            if pos + length > n:
                raise ValueError("truncated length-delimited field")
            value = payload[pos:pos + length]
            pos += length
        elif wire_type == _WIRE_32BIT:
            if pos + 4 > n:
                raise ValueError("truncated 32-bit field")
            value = struct.unpack_from("<I", payload, pos)[0]
            pos += 4
        else:
            raise ValueError(f"unsupported wire_type {wire_type} (field {field_number})")
        if field_number in fields:
            existing = fields[field_number]
            if isinstance(existing, list):
                existing.append(value)
            else:
                fields[field_number] = [existing, value]
        else:
            fields[field_number] = value
    return fields


def _as_list(v: Any) -> list:
    """Normalize a parsed field value into a list (repeated-field helper)."""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _decode_packed_varints(blob: bytes) -> list[int]:
    """Decode a packed-repeated varint array (used for cap_eff / threads)."""
    out: list[int] = []
    pos = 0
    while pos < len(blob):
        val, pos = _decode_varint(blob, pos)
        out.append(val)
    return out


def _decode_packed_u32(blob: bytes) -> list[int]:
    """Decode a packed-repeated fixed32 array (threads as packed u32).

    CRIU emits some packed arrays as fixed32 and some as varints; we try fixed
    decode first and fall back to varint if the length isn't a multiple of 4.
    """
    if len(blob) % 4 == 0 and blob:
        return [struct.unpack_from("<I", blob, i)[0] for i in range(0, len(blob), 4)]
    return _decode_packed_varints(blob)


# ===========================================================================
# .img framing.
# ===========================================================================

def _read_img_file(path: str, img_version: int = 2) -> dict[str, Any]:
    """Read one ``.img`` file and return its framing + parsed entries.

    Returns ``{"magic": int, "raw": bool, "entries": [fields, ...]}``.

    - Reads the first 4 bytes as the magic (u32 LE).
    - Magic 0 → raw image (pages/pipes); ``raw`` is True and ``entries`` empty.
    - img_version 1 → read & discard the 8-byte legacy addr after the magic.
    - Otherwise loop: u32 length, then ``length`` bytes payload, parsed with
      :func:`_parse_pb_fields`. EOF after a clean entry boundary ends the loop.
    """
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 4:
        return {"magic": 0, "raw": True, "entries": []}
    magic = struct.unpack_from("<I", data, 0)[0]
    pos = 4
    if magic == 0:
        return {"magic": 0, "raw": True, "entries": []}
    if img_version == 1:
        # legacy 8-byte addr immediately after the magic
        pos += 8
    entries: list[dict[int, Any]] = []
    n = len(data)
    while pos + 4 <= n:
        (entry_length,) = struct.unpack_from("<I", data, pos)
        pos += 4
        if entry_length == 0:
            continue
        if pos + entry_length > n:
            break  # truncated tail — stop cleanly
        payload = data[pos:pos + entry_length]
        pos += entry_length
        entries.append(_parse_pb_fields(payload))
    return {"magic": magic, "raw": False, "entries": entries}


# ===========================================================================
# Per-message interpreters (field_number → semantic value).
# ===========================================================================

def _u32(v: Any) -> int:
    return int(v) if v is not None else 0


def _u64(v: Any) -> int:
    return int(v) if v is not None else 0


def _str_field(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (bytes, bytearray)):
        try:
            return v.split(b"\x00", 1)[0].decode("utf-8", "replace")
        except Exception:
            return v.decode("latin-1", "replace")
    return str(v)


def _interpret_pstree(fields: dict[int, Any]) -> dict[str, Any]:
    """pstree_entry: 1=pid, 2=ppid, 3=pgid, 4=sid, 5=threads (packed u32)."""
    threads_blob = fields.get(5)
    threads: list[int] = []
    if isinstance(threads_blob, (bytes, bytearray)) and threads_blob:
        threads = _decode_packed_u32(threads_blob)
    return {
        "pid": _u32(fields.get(1)),
        "ppid": _u32(fields.get(2)),
        "pgid": _u32(fields.get(3)),
        "sid": _u32(fields.get(4)),
        "threads": threads,
    }


def _interpret_core(fields: dict[int, Any]) -> dict[str, Any]:
    """core_entry → task names + ids.

    core_entry layout (relevant fields):
      thread_core_entry (repeated) — field 1
      task_core_entry            — field 2: {1=task_state, 2=exit_code, 6=comm}
      tc_state                   — field 4
      task_kobj_ids_entry        — field 7: {1=vm_id, 2=files_id, 3=fs_id}
      thread_info_entry          — field 9

    Different CRIU versions shuffle the embedded message field numbers; we walk
    every length-delimited field looking for a task_core_entry that yields a
    comm string, and the task_kobj_ids_entry that yields vm_id/files_id.
    """
    comm = ""
    task_state = 0
    exit_code = 0
    vm_id = 0
    files_id = 0
    fs_id = 0

    # Try the documented field numbers first.
    task_core = fields.get(2)
    if isinstance(task_core, (bytes, bytearray)):
        tc = _parse_pb_fields(task_core)
        task_state = _u32(tc.get(1))
        exit_code = _u32(tc.get(2))
        comm = _str_field(tc.get(6))
    kobj = fields.get(7)
    if isinstance(kobj, (bytes, bytearray)):
        ki = _parse_pb_fields(kobj)
        vm_id = _u64(ki.get(1))
        files_id = _u64(ki.get(2))
        fs_id = _u64(ki.get(3))

    # If we did not find a comm, scan embedded messages for a task_core-like
    # blob carrying field 6 (comm). Robust across CRIU schema drift.
    if not comm:
        for fn, val in fields.items():
            if isinstance(val, (bytes, bytearray)) and len(val) >= 2:
                try:
                    sub = _parse_pb_fields(val)
                except Exception:
                    continue
                candidate = _str_field(sub.get(6))
                if candidate and candidate.isprintable():
                    comm = candidate
                    if not task_state:
                        task_state = _u32(sub.get(1))
                    if not exit_code:
                        exit_code = _u32(sub.get(2))
                    break

    return {
        "comm": comm,
        "task_state": task_state,
        "exit_code": exit_code,
        "vm_id": vm_id,
        "files_id": files_id,
        "fs_id": fs_id,
    }


def _interpret_vma(fields: dict[int, Any]) -> dict[str, Any]:
    """vma_entry: 1=start, 2=end, 3=pgoff, 4=shmid, 5=prot, 6=flags, 7=status, 8=fd."""
    prot = _u32(fields.get(5))
    status = _u32(fields.get(7))
    start = _u64(fields.get(1))
    end = _u64(fields.get(2))
    is_anon = bool(status & VMA_AREA_ANON)
    is_rwx = bool((prot & PROT_READ) and (prot & PROT_WRITE) and (prot & PROT_EXEC))
    return {
        "start": start,
        "end": end,
        "pgoff": _u64(fields.get(3)),
        "shmid": _u64(fields.get(4)),
        "prot": prot,
        "flags": _u32(fields.get(6)),
        "status": status,
        "fd": _u32(fields.get(8)),
        "size": end - start if end >= start else 0,
        "prot_str": _prot_str(prot),
        "is_anon": is_anon,
        "is_rwx": is_rwx,
        "is_anon_rwx": is_anon and is_rwx,
    }


def _prot_str(prot: int) -> str:
    return ("r" if prot & PROT_READ else "-") + \
           ("w" if prot & PROT_WRITE else "-") + \
           ("x" if prot & PROT_EXEC else "-")


def _interpret_creds(fields: dict[int, Any]) -> dict[str, Any]:
    """creds_entry: 1=uid, 2=gid, 3=euid, 4=egid, 11=cap_eff(packed u32), 18=no_new_privs."""
    uid = _u32(fields.get(1))
    euid = _u32(fields.get(3))
    gid = _u32(fields.get(2))
    egid = _u32(fields.get(4))
    no_new_privs = _u32(fields.get(18))
    cap_eff_blob = fields.get(11)
    cap_words: list[int] = []
    if isinstance(cap_eff_blob, (bytes, bytearray)) and cap_eff_blob:
        # cap_eff is a packed array of u32 capability words (one per 32 caps).
        if len(cap_eff_blob) % 4 == 0:
            cap_words = [struct.unpack_from("<I", cap_eff_blob, i)[0]
                         for i in range(0, len(cap_eff_blob), 4)]
        else:
            cap_words = _decode_packed_varints(cap_eff_blob)
    # Map capability bit positions → names across the packed words.
    present_caps: list[str] = []
    for bit, name in CAP_BITS.items():
        word_index = bit // 32
        bit_mask = 1 << (bit % 32)
        if word_index < len(cap_words) and (cap_words[word_index] & bit_mask):
            present_caps.append(name)
    return {
        "uid": uid,
        "gid": gid,
        "euid": euid,
        "egid": egid,
        "cap_eff": cap_words,
        "capabilities": present_caps,
        "has_sys_admin": "CAP_SYS_ADMIN" in present_caps,
        "has_sys_ptrace": "CAP_SYS_PTRACE" in present_caps,
        "has_net_admin": "CAP_NET_ADMIN" in present_caps,
        "has_dac_override": "CAP_DAC_OVERRIDE" in present_caps,
        "setuid_root": (euid == 0) and (uid != 0),
        "running_as_root": (euid == 0),
        "no_new_privs": bool(no_new_privs),
    }


def _addr_str(blob: Any, family: int) -> str:
    """Render an address blob (4 bytes IPv4 / 16 bytes IPv6) as a string."""
    if not isinstance(blob, (bytes, bytearray)) or not blob:
        return ""
    try:
        if len(blob) == 4:
            return socket.inet_ntop(socket.AF_INET, bytes(blob))
        if len(blob) == 16:
            return socket.inet_ntop(socket.AF_INET6, bytes(blob))
    except (OSError, ValueError):
        pass
    # Unknown length — render as hex.
    return "0x" + bytes(blob).hex()


def _interpret_inetsk(fields: dict[int, Any]) -> dict[str, Any]:
    """inet_sk_entry: 1=id, 3=family, 4=type, 5=proto, 6=state, 7=src_port,
    8=dst_port, 11=src_addr, 12=dst_addr."""
    family = _u32(fields.get(3))
    proto = _u32(fields.get(5))
    state = _u32(fields.get(6))
    src_addr = _addr_str(fields.get(11), family)
    dst_addr = _addr_str(fields.get(12), family)
    return {
        "id": _u64(fields.get(1)),
        "family": family,
        "type": _u32(fields.get(4)),
        "proto": proto,
        "proto_str": _proto_str_sk(proto),
        "state": state,
        "state_str": TCP_STATES.get(state, f"UNKNOWN({state})"),
        "src_addr": src_addr,
        "src_port": _u32(fields.get(7)),
        "dst_addr": dst_addr,
        "dst_port": _u32(fields.get(8)),
        "5tuple": f"{src_addr}:{_u32(fields.get(7))} -> {dst_addr}:{_u32(fields.get(8))} "
                  f"({_proto_str_sk(proto)})",
    }


def _proto_str_sk(proto: int) -> str:
    return {6: "tcp", 17: "udp", 132: "sctp", 1: "icmp"}.get(proto, str(proto))


def _interpret_regfile(fields: dict[int, Any]) -> dict[str, Any]:
    """reg_file_entry: 1=id, 6=name, 7=mnt_id, 8=size, 10=mode."""
    mode = _u32(fields.get(10))
    return {
        "id": _u64(fields.get(1)),
        "name": _str_field(fields.get(6)),
        "mnt_id": _u32(fields.get(7)),
        "size": _u64(fields.get(8)),
        "mode": mode,
        "mode_str": _mode_str(mode),
    }


def _mode_str(mode: int) -> str:
    """Render a POSIX st_mode as ``drwxr-xr-x`` style."""
    import stat as _stat
    try:
        return _stat.filemode(mode)
    except Exception:
        return oct(mode)


# ===========================================================================
# Embedded subprocess parser. This string is a self-contained python3 program
# that re-implements the helpers above (a sandbox process cannot import this
# module). It walks the dump dir and emits one JSON row per finding to stdout.
# Keep the logic in sync with the module-level helpers above.
# ===========================================================================

_PARSER = r'''
import json, os, socket, stat as _stat, struct, sys

# ---- constants -----------------------------------------------------------
MAGIC = {
    "INVENTORY": 0x58311116, "PSTREE": 0x50273030, "CORE": 0x55053847,
    "MM": 0x57492820, "CREDS": 0x54023547, "FDINFO": 0x56213732,
    "FILES": 0x56303138, "REG_FILES": 0x50363636, "INETSK": 0x56443851,
    "UNIXSK": 0x54373943,
}
PROT_READ, PROT_WRITE, PROT_EXEC = 1, 2, 4
VMA_AREA_REGULAR, VMA_AREA_ANON, VMA_AREA_FILE = 1, 2, 4
FD_TYPES = {1: "REG", 2: "PIPE", 4: "INETSK", 5: "UNIXSK"}
TCP_STATES = {1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
              5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
              9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING"}
CAP_BITS = {21: "CAP_SYS_ADMIN", 19: "CAP_SYS_PTRACE",
            12: "CAP_NET_ADMIN", 1: "CAP_DAC_OVERRIDE"}
PRIVATE_RANGES = (
    ("10.0.0.0", "10.255.255.255"), ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"), ("127.0.0.0", "127.255.255.255"),
    ("169.254.0.0", "169.254.255.255"),
)

analysis = sys.argv[1] if len(sys.argv) > 1 else "full"
dump_dir = sys.argv[2] if len(sys.argv) > 2 else ""
out = sys.stdout


def emit(row):
    out.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    out.flush()


def _decode_varint(buf, pos):
    result = 0; shift = 0
    while True:
        b = buf[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def _parse_pb_fields(payload):
    fields = {}
    pos = 0; n = len(payload)
    while pos < n:
        tag, pos = _decode_varint(payload, pos)
        fn = tag >> 3; wt = tag & 0x7
        if wt == 0:
            value, pos = _decode_varint(payload, pos)
        elif wt == 1:
            value = struct.unpack_from("<Q", payload, pos)[0]; pos += 8
        elif wt == 2:
            length, pos = _decode_varint(payload, pos)
            value = payload[pos:pos + length]; pos += length
        elif wt == 5:
            value = struct.unpack_from("<I", payload, pos)[0]; pos += 4
        else:
            break
        if fn in fields:
            ex = fields[fn]
            if isinstance(ex, list):
                ex.append(value)
            else:
                fields[fn] = [ex, value]
        else:
            fields[fn] = value
    return fields


def _decode_packed_u32(blob):
    if len(blob) % 4 == 0 and blob:
        return [struct.unpack_from("<I", blob, i)[0] for i in range(0, len(blob), 4)]
    out = []; pos = 0
    while pos < len(blob):
        v, pos = _decode_varint(blob, pos); out.append(v)
    return out


def _u32(v): return int(v) if v is not None else 0
def _u64(v): return int(v) if v is not None else 0


def _str_field(v):
    if v is None:
        return ""
    if isinstance(v, (bytes, bytearray)):
        return v.split(b"\x00", 1)[0].decode("utf-8", "replace")
    return str(v)


def _addr_str(blob, family):
    if not isinstance(blob, (bytes, bytearray)) or not blob:
        return ""
    try:
        if len(blob) == 4:
            return socket.inet_ntop(socket.AF_INET, bytes(blob))
        if len(blob) == 16:
            return socket.inet_ntop(socket.AF_INET6, bytes(blob))
    except (OSError, ValueError):
        pass
    return "0x" + bytes(blob).hex()


def _proto_str_sk(p):
    return {6: "tcp", 17: "udp", 132: "sctp", 1: "icmp"}.get(p, str(p))


def _prot_str(p):
    return ("r" if p & 1 else "-") + ("w" if p & 2 else "-") + ("x" if p & 4 else "-")


def read_img(path, img_version):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        emit({"error": "read failed for %s: %s" % (path, e)})
        return {"magic": 0, "raw": True, "entries": []}
    if len(data) < 4:
        return {"magic": 0, "raw": True, "entries": []}
    magic = struct.unpack_from("<I", data, 0)[0]
    pos = 4
    if magic == 0:
        return {"magic": 0, "raw": True, "entries": []}
    if img_version == 1:
        pos += 8
    entries = []
    n = len(data)
    while pos + 4 <= n:
        (el,) = struct.unpack_from("<I", data, pos); pos += 4
        if el == 0:
            continue
        if pos + el > n:
            break
        payload = data[pos:pos + el]; pos += el
        try:
            entries.append(_parse_pb_fields(payload))
        except Exception as e:
            emit({"error": "pb parse failed in %s: %s" % (path, e)})
    return {"magic": magic, "raw": False, "entries": entries}


def interpret_pstree(f):
    t = f.get(5)
    threads = _decode_packed_u32(t) if isinstance(t, (bytes, bytearray)) and t else []
    return {"pid": _u32(f.get(1)), "ppid": _u32(f.get(2)),
            "pgid": _u32(f.get(3)), "sid": _u32(f.get(4)), "threads": threads}


def interpret_core(f):
    comm = ""; task_state = 0; exit_code = 0
    vm_id = 0; files_id = 0; fs_id = 0
    tc = f.get(2)
    if isinstance(tc, (bytes, bytearray)):
        sub = _parse_pb_fields(tc)
        task_state = _u32(sub.get(1)); exit_code = _u32(sub.get(2))
        comm = _str_field(sub.get(6))
    ko = f.get(7)
    if isinstance(ko, (bytes, bytearray)):
        sub = _parse_pb_fields(ko)
        vm_id = _u64(sub.get(1)); files_id = _u64(sub.get(2)); fs_id = _u64(sub.get(3))
    if not comm:
        for fn, val in f.items():
            if isinstance(val, (bytes, bytearray)) and len(val) >= 2:
                try:
                    sub = _parse_pb_fields(val)
                except Exception:
                    continue
                cand = _str_field(sub.get(6))
                if cand and cand.isprintable():
                    comm = cand
                    if not task_state:
                        task_state = _u32(sub.get(1))
                    if not exit_code:
                        exit_code = _u32(sub.get(2))
                    break
    return {"comm": comm, "task_state": task_state, "exit_code": exit_code,
            "vm_id": vm_id, "files_id": files_id, "fs_id": fs_id}


def interpret_vma(f):
    prot = _u32(f.get(5)); status = _u32(f.get(7))
    start = _u64(f.get(1)); end = _u64(f.get(2))
    is_anon = bool(status & VMA_AREA_ANON)
    is_rwx = bool((prot & 1) and (prot & 2) and (prot & 4))
    return {"start": start, "end": end, "pgoff": _u64(f.get(3)),
            "shmid": _u64(f.get(4)), "prot": prot, "flags": _u32(f.get(6)),
            "status": status, "fd": _u32(f.get(8)),
            "size": end - start if end >= start else 0,
            "prot_str": _prot_str(prot), "is_anon": is_anon, "is_rwx": is_rwx,
            "is_anon_rwx": is_anon and is_rwx}


def interpret_creds(f):
    uid = _u32(f.get(1)); euid = _u32(f.get(3))
    no_new_privs = _u32(f.get(18))
    blob = f.get(11); cap_words = []
    if isinstance(blob, (bytes, bytearray)) and blob:
        if len(blob) % 4 == 0:
            cap_words = [struct.unpack_from("<I", blob, i)[0] for i in range(0, len(blob), 4)]
        else:
            pos = 0
            while pos < len(blob):
                v, pos = _decode_varint(blob, pos); cap_words.append(v)
    present = []
    for bit, name in CAP_BITS.items():
        wi = bit // 32; mask = 1 << (bit % 32)
        if wi < len(cap_words) and (cap_words[wi] & mask):
            present.append(name)
    return {"uid": uid, "gid": _u32(f.get(2)), "euid": euid, "egid": _u32(f.get(4)),
            "cap_eff": cap_words, "capabilities": present,
            "has_sys_admin": "CAP_SYS_ADMIN" in present,
            "setuid_root": (euid == 0) and (uid != 0),
            "running_as_root": (euid == 0),
            "no_new_privs": bool(no_new_privs)}


def interpret_inetsk(f):
    family = _u32(f.get(3)); proto = _u32(f.get(5)); state = _u32(f.get(6))
    sp = _u32(f.get(7)); dp = _u32(f.get(8))
    sa = _addr_str(f.get(11), family); da = _addr_str(f.get(12), family)
    return {"id": _u64(f.get(1)), "family": family, "type": _u32(f.get(4)),
            "proto": proto, "proto_str": _proto_str_sk(proto), "state": state,
            "state_str": TCP_STATES.get(state, "UNKNOWN(%d)" % state),
            "src_addr": sa, "src_port": sp, "dst_addr": da, "dst_port": dp,
            "5tuple": "%s:%d -> %s:%d (%s)" % (sa, sp, da, dp, _proto_str_sk(proto))}


def interpret_regfile(f):
    mode = _u32(f.get(10))
    try:
        ms = _stat.filemode(mode)
    except Exception:
        ms = oct(mode)
    return {"id": _u64(f.get(1)), "name": _str_field(f.get(6)),
            "mnt_id": _u32(f.get(7)), "size": _u64(f.get(8)),
            "mode": mode, "mode_str": ms}


def is_private_ip(ip):
    if not ip or ":" in ip:
        return True  # treat IPv6 / empty conservatively
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return True
    except Exception:
        return True
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 127:
        return True
    if parts[0] == 169 and parts[1] == 254:
        return True
    return False


def find_files(dump_dir):
    """Return a dict mapping lowercase basename -> path for .img files."""
    out = {}
    if not dump_dir or not os.path.isdir(dump_dir):
        return out
    for dp, dns, fns in os.walk(dump_dir):
        for fn in fns:
            if fn.lower().endswith(".img"):
                out.setdefault(fn.lower(), os.path.join(dp, fn))
                out[fn.lower()] = os.path.join(dp, fn)
    return out


def main():
    files = find_files(dump_dir)
    if not files:
        emit({"error": "no .img files found under %s" % dump_dir})
        return

    # 1. inventory → img_version
    img_version = 2
    inv_path = files.get("inventory.img")
    if inv_path:
        inv = read_img(inv_path, img_version=2)
        for e in inv["entries"]:
            if 1 in e:
                img_version = _u32(e.get(1))
                break

    do_pt = analysis in ("process_tree", "full")
    do_net = analysis in ("network", "full")
    do_files = analysis in ("files", "full")
    do_mem = analysis in ("memory", "full")
    do_cred = analysis in ("credentials", "full")

    pids = {}        # pid -> process row
    cores = {}       # pid -> core row (keyed by core-<pid>.img)
    vms = {}         # mm_id -> list of vma rows
    creds_rows = {}  # pid -> creds row
    file_id_to_name = {}

    # ---- pstree ----
    if do_pt or do_files or do_mem or do_cred:
        pt_path = files.get("pstree.img")
        if pt_path:
            pt = read_img(pt_path, img_version)
            for e in pt["entries"]:
                row = interpret_pstree(e)
                pids[row["pid"]] = row
                emit({"artifact_type": "process_tree", "source": "pstree.img", **row})

    # ---- core-*.img ----
    if do_pt or do_mem or do_cred or do_files:
        for name, path in files.items():
            if not name.startswith("core-") or not name.endswith(".img"):
                continue
            try:
                pid = int(name[len("core-"):-len(".img")])
            except ValueError:
                pid = 0
            c = read_img(path, img_version)
            for e in c["entries"]:
                crow = interpret_core(e)
                cores[pid] = crow
                if do_pt:
                    emit({"artifact_type": "process_tree", "source": name,
                          "pid": pid, **crow})

    # ---- mm-*.img (memory / VMAs) ----
    if do_mem:
        for name, path in files.items():
            if not name.startswith("mm-") or not name.endswith(".img"):
                continue
            try:
                mm_id = int(name[len("mm-"):-len(".img")])
            except ValueError:
                mm_id = 0
            m = read_img(path, img_version)
            anon_rwx = 0
            exe_file_id = 0
            vma_count = 0
            for e in m["entries"]:
                if 1 in e and isinstance(e.get(1), int):
                    exe_file_id = _u64(e.get(1))
                # VMAs are repeated embedded vma_entry messages in field 14
                for blob in (e.get(14) if isinstance(e.get(14), list) else
                             ([e.get(14)] if 14 in e else [])):
                    if not isinstance(blob, (bytes, bytearray)):
                        continue
                    try:
                        vma = interpret_vma(_parse_pb_fields(blob))
                    except Exception:
                        continue
                    vma_count += 1
                    if vma["is_anon_rwx"]:
                        anon_rwx += 1
                    emit({"artifact_type": "memory", "source": name,
                          "mm_id": mm_id, **vma})
            emit({"artifact_type": "memory", "source": name, "summary": True,
                  "mm_id": mm_id, "exe_file_id": exe_file_id,
                  "vma_count": vma_count, "anon_rwx_count": anon_rwx,
                  "code_injection": anon_rwx > 0})

    # ---- creds-*.img ----
    if do_cred:
        for name, path in files.items():
            if not name.startswith("creds-") or not name.endswith(".img"):
                continue
            try:
                pid = int(name[len("creds-"):-len(".img")])
            except ValueError:
                pid = 0
            cr = read_img(path, img_version)
            for e in cr["entries"]:
                row = interpret_creds(e)
                creds_rows[pid] = row
                emit({"artifact_type": "credentials", "source": name,
                      "pid": pid, **row})

    # ---- reg-files.img + files.img ----
    if do_files:
        rf_path = files.get("reg-files.img")
        if rf_path:
            rf = read_img(rf_path, img_version)
            for e in rf["entries"]:
                row = interpret_regfile(e)
                file_id_to_name[row["id"]] = row["name"]
                emit({"artifact_type": "files", "source": "reg-files.img",
                      "kind": "reg_file", **row})

    # ---- fdinfo-*.img (join fd → file id → name) ----
    if do_files:
        for name, path in files.items():
            if not name.startswith("fdinfo-") or not name.endswith(".img"):
                continue
            try:
                pid = int(name[len("fdinfo-"):-len(".img")])
            except ValueError:
                pid = 0
            fi = read_img(path, img_version)
            for e in fi["entries"]:
                fd = _u32(e.get(1)); fid = _u64(e.get(2))
                flags = _u32(e.get(3)); ftype = _u32(e.get(4))
                emit({"artifact_type": "files", "source": name,
                      "pid": pid, "fd": fd, "file_id": fid, "flags": flags,
                      "type": ftype, "type_str": FD_TYPES.get(ftype, str(ftype)),
                      "name": file_id_to_name.get(fid, "")})

    # ---- inetsk.img ----
    if do_net:
        isk_path = files.get("inetsk.img")
        if isk_path:
            isk = read_img(isk_path, img_version)
            suspicious = 0
            for e in isk["entries"]:
                row = interpret_inetsk(e)
                ext = row["dst_addr"] and not is_private_ip(row["dst_addr"])
                row["external_dst"] = ext
                if ext and row["state"] == 1:  # ESTABLISHED to non-private
                    suspicious += 1
                emit({"artifact_type": "network", "source": "inetsk.img", **row})
            emit({"artifact_type": "network", "source": "inetsk.img",
                  "summary": True, "suspicious_egress": suspicious})

    emit({"artifact_type": "_meta", "img_version": img_version,
          "analysis": analysis, "file_count": len(files),
          "process_count": len(pids), "core_count": len(cores)})


main()
'''


def _build_command(analysis_type: str, sub: str) -> list[str]:
    """Build the container argv: python3 -c '<parser>' <analysis> <dump_dir>."""
    target = f"/evidence/{sub}".rstrip("/") if sub else ""
    return ["python3", "-c", _PARSER, analysis_type, target]


# ===========================================================================
# Output hash helper (mirrors k8s_parse / chainsaw).
# ===========================================================================

def _hash_file(p: Path) -> str | None:
    if not p.exists():
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


class CriuParseTool(Tool):
    """Wrap the pure-Python CRIU ``.img`` parser inside ``svetovid/base``.

    Mirrors k8s_parse / linux_logs: an embedded python3 program walks the dump
    directory, emits JSONL rows to stdout, and the wrapper persists a provenance
    copy + emits timeline / IOC events for notable findings. Zero non-stdlib
    dependencies so it runs anywhere the base image runs (and via host fallback
    in tests).
    """

    name = "criu_parse"
    image = "svetovid/base"
    description = (
        "Parse a CRIU (Checkpoint/Restore In Userspace) container checkpoint "
        "directory (.img files) into structured rows. analysis_type selects the "
        "view: process_tree (pstree + core → PID/PPID/comm/state), network "
        "(inetsk → 5-tuples, flags external egress), files (fdinfo + files + "
        "reg-files → open file paths), memory (mm → VMAs, flags anonymous RWX "
        "code-injection regions), credentials (creds → uid/euid/cap_eff, flags "
        "CAP_SYS_ADMIN / setuid-root), or full (all of the above). Runs "
        "read-only over /evidence using pure-Python protobuf wire parsing."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "evidence_subpath": {
                    "type": "string",
                    "description": (
                        "Subpath under /evidence to the CRIU dump directory "
                        "(the folder holding inventory.img / pstree.img)."
                    ),
                },
                "analysis_type": {
                    "type": "string",
                    "enum": list(ANALYSIS_TYPES.keys()),
                    "description": (
                        "Which view to extract. 'full' is the recommended first "
                        "call — it surfaces code-injection and privilege-"
                        "escalation findings in one pass."
                    ),
                },
            },
            "required": ["evidence_subpath", "analysis_type"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox
        from ._reporting import emit_hit_events, record_tool_call_db

        call_id = ctx.make_call_id()
        atype = args.get("analysis_type", "")
        sub = args.get("evidence_subpath", "") or ""

        if atype not in ANALYSIS_TYPES:
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=2, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=(f"unknown analysis_type {atype!r}; pick from "
                         f"{list(ANALYSIS_TYPES)}"),
            )
        if not sub:
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=2, duration_s=0.0,
                output_hash=None, output_path=None,
                summary="evidence_subpath is required (the CRIU dump directory)",
            )

        cmd = _build_command(atype, sub)

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=True, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(ctx.investigation_id, tool=self.name, args=args))

        stdout_lines: list[str] = []

        def on_stdout(line: str) -> None:
            stdout_lines.append(line)
            ctx.bus.publish(E.tool_stdout(ctx.investigation_id, call_id, line))

        def on_stderr(line: str) -> None:
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, line))

        try:
            res = await run_in_sandbox(
                image=self.image or "",
                command=cmd,
                evidence_path=ctx.evidence_path,
                output_dir=ctx.output_dir,
                investigation_id=ctx.investigation_id,
                on_stdout=on_stdout,
                on_stderr=on_stderr,
                host_fallback=True,
            )
        except Exception as e:
            ctx.bus.publish(E.error_event(
                ctx.investigation_id, f"criu_parse ({atype}) failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"criu_parse ({atype}) failed: {e}",
            )

        # Persist a provenance copy and parse the JSONL rows.
        local_out = Path(ctx.output_dir) / f"criu_{atype}.jsonl"
        if stdout_lines:
            try:
                local_out.write_text("\n".join(stdout_lines) + "\n", encoding="utf-8")
            except Exception:
                pass

        rows: list[dict[str, Any]] = []
        for line in stdout_lines:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"raw": line})
        rows = rows[:5000]

        output_hash = _hash_file(local_out)
        if rows:
            summary = f"criu_parse ({atype}): {len(rows)} row(s)"
        else:
            summary = (f"criu_parse ({atype}) exited {res.exit_code} "
                       "but produced no JSONL output")

        ctx.bus.publish(E.tool_end(
            ctx.investigation_id, call_id, res.exit_code, res.duration_s, output_hash,
        ))
        ctx.bus.publish(E.agent_observation(
            ctx.investigation_id, tool=self.name, summary=summary,
        ))
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name,
            "image": self.image,
            "args": args,
            "exit_code": res.exit_code,
            "duration_s": res.duration_s,
            "output_hash": output_hash,
            "ts": E._now_iso(),
        }))

        # Emit timeline / IOC events for notable findings.
        timeline_hits: list[dict[str, Any]] = []
        ioc_hits: list[dict[str, Any]] = []
        for r in rows:
            at = r.get("artifact_type")
            if at == "process_tree" and r.get("comm") and r.get("pid") and not r.get("summary"):
                timeline_hits.append({
                    "timestamp": "",  # CRIU snapshots have no wall-clock ts
                    "event": f"process pid={r.get('pid')} comm={r.get('comm')}",
                    "actor": str(r.get("comm") or ""),
                    "pid": r.get("pid"),
                    "mitre_tags": [],
                })
            elif at == "network" and r.get("external_dst") and r.get("dst_addr"):
                ioc_hits.append({
                    "rule_name": f"external egress to {r.get('dst_addr')}:{r.get('dst_port')}",
                    "details": r.get("5tuple", ""),
                    "mitre_tags": ["T1071"],
                })
            elif at == "memory" and r.get("is_anon_rwx"):
                timeline_hits.append({
                    "timestamp": "",
                    "event": (f"anonymous RWX VMA "
                              f"{r.get('start'):x}-{r.get('end'):x} (code injection)"),
                    "actor": "",
                    "mitre_tags": ["T1055"],
                })
            elif at == "credentials" and (r.get("has_sys_admin") or r.get("setuid_root")):
                timeline_hits.append({
                    "timestamp": "",
                    "event": (f"elevated creds pid={r.get('pid')} "
                              f"caps={r.get('capabilities')}"),
                    "actor": str(r.get("pid")),
                    "mitre_tags": ["T1548"],
                })

        await record_tool_call_db(
            call_id=call_id, investigation_id=ctx.investigation_id,
            tool=self.name, args=args, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash,
        )
        # Timeline events for processes / suspicious VMAs / creds.
        for h in timeline_hits[:200]:
            ctx.bus.publish(E.report_timeline_entry(
                investigation_id=ctx.investigation_id,
                ts=h.get("timestamp") or "checkpoint",
                source="criu_parse",
                event=str(h.get("event")),
                actor=h.get("actor") or None,
                mitre_tags=h.get("mitre_tags"),
            ))
        # IOC extraction from suspicious network connections.
        emit_hit_events(
            ctx.bus,
            investigation_id=ctx.investigation_id,
            source="criu_parse",
            hits=ioc_hits[:200],
            timeline_fields={"timestamp": "timestamp", "event": "rule_name"},
            ioc_text_getter=lambda h: str(h.get("rule_name") or "") + " " + str(h.get("details") or ""),
        )

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash,
            output_path=str(local_out) if local_out.exists() else None,
            summary=summary, data={"analysis_type": atype, "rows": rows},
        )


# Module-level instance for tool enumeration parity with the other wrappers.
tool = CriuParseTool()
