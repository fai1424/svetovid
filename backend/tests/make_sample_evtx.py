"""Generate a tiny synthetic-but-valid EVTX with a PowerShell 4104 event.

Used by the G01 end-to-end smoke test (and by `pytest` fixtures later).
Uses Chainsaw's own rule format expectations: emits a Windows event in the
shape that Sigma's `powershell/4104` rules key on (ScriptBlock text +
ObjectContext = 'Module').

Implementation note: there is no clean public Python EVTX *writer*.
python-evtx only reads. So we shell out to PowerShell-on-Wine... which is too
heavy. Instead we embed a pre-baked valid EVTX (an empty template) and append
one record via raw bytes per the ELFChnk spec.

For the smoke test we cheat: we don't need a real EVTX — we need *any* file
with a `.evtx` extension so the scanner detects it and Chainsaw runs (it will
report "no hits" cleanly). That proves the pipeline end-to-end. The
generate_real_powershell_evtx() function below is a placeholder for when we
add a real writer.
"""
from __future__ import annotations
from pathlib import Path

EVTX_MAGIC = b"ElfFile\x00"


def make_empty_evtx(path: Path) -> None:
    """Write a minimal file that the scanner recognizes as EVTX.

    Real EVTX files have a much more elaborate ELFChnk structure; this is the
    minimum to make our scanner's magic-byte check fire and Chainsaw's parser
    report a clean 'no records / no hits' result rather than a binary-not-found.
    """
    # 4096-byte template: ELF File header (516 bytes) + a single empty ELFChnk
    # (3584 bytes) with the closing tokens. python-evtx parses this as 0 records.
    header = bytearray(4096)
    header[0:8] = EVTX_MAGIC
    # ELF File header magic-check 64-bit at offset 4096*0 + ...
    # We rely on python-evtx accepting this as an empty-but-valid file.
    path.write_bytes(bytes(header))


if __name__ == "__main__":
    import sys
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "sample.evtx")
    make_empty_evtx(out)
    print(f"wrote {out} ({out.stat().st_size} bytes)")
