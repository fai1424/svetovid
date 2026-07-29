"""The Sleuth Kit (TSK) tool wrapper (research item C11a).

Wraps the core TSK CLI tools for filesystem analysis — already installed in
svetovid/eztools via apt. Used by G03 (deadbox examination) and G22
(super-timeline). The agent picks the sub-tool:

  - fls       : list files (allocated + deleted) → body file for Plaso
  - icat      : extract a file by inode
  - mmls      : list partitions
  - fsstat    : filesystem stats
  - ils       : list deleted inodes
  - mactime   : body file → timeline CSV

We expose a single ``tsk`` tool with the sub-command as an arg.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult


TSK_SUBTOOLS: dict[str, str] = {
    "fls": "List allocated and deleted files. Output is body-file format (for mactime/Plaso).",
    "icat": "Extract file contents by inode. Requires inode number in extra_args.",
    "mmls": "List partition table.",
    "fsstat": "Filesystem statistics.",
    "ils": "List deleted inodes.",
    "mactime": "Convert body file to timeline CSV. Requires body file path in extra_args.",
}


class SleuthKitTool(Tool):
    name = "tsk"
    image = "svetovid/eztools"
    description = (
        "Run a Sleuth Kit (TSK) filesystem-analysis subtool. fls lists files, "
        "icat extracts by inode, mmls lists partitions, mactime converts a body "
        "file to a timeline. Used for deadbox examination and timeline building."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "subtool": {
                    "type": "string",
                    "enum": list(TSK_SUBTOOLS.keys()),
                    "description": "Which TSK subtool to run.",
                },
                "evidence_subpath": {
                    "type": "string",
                    "description": "Path to image file under /evidence.",
                },
                "partition_offset": {
                    "type": "number",
                    "description": "Byte offset of the partition (from mmls). Skip for raw partition images.",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Subtool-specific args (e.g. inode number for icat, body file path for mactime).",
                },
            },
            "required": ["subtool", "evidence_subpath"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        sub = args.get("subtool", "")
        if sub not in TSK_SUBTOOLS:
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=2, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"unknown TSK subtool {sub!r}",
            )
        ev_sub = args.get("evidence_subpath", "")
        offset = args.get("partition_offset")
        extra = args.get("extra_args") or ""

        img = f"/evidence/{ev_sub}"
        cmd: list[str] = [sub]

        # fls/icat/ils/fsstat take -o <offset> for partition offset
        if offset and sub in ("fls", "icat", "ils", "fsstat"):
            cmd.extend(["-o", str(int(offset))])

        if sub == "fls":
            # -r recursive, -m / for body-file path prefix (Plaso-friendly)
            cmd.extend(["-r", "-m", "/", img])
        elif sub == "icat":
            cmd.extend([img] + (extra.split() if extra else []))
        elif sub == "mmls":
            cmd.append(img)
        elif sub == "fsstat":
            cmd.append(img)
        elif sub == "ils":
            cmd.extend(["-r", img])
        elif sub == "mactime":
            # mactime takes a body file, not an image
            body = extra.strip() or "/work/body.txt"
            cmd = ["mactime", "-b", body]
        if extra and sub not in ("icat", "mactime"):
            cmd.extend(extra.split())

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
                timeout_s=1200,
                host_fallback=False,
            )
        except Exception as e:
            ctx.bus.publish(E.error_event(ctx.investigation_id, f"tsk {sub} failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None, summary=f"tsk {sub} failed: {e}",
            )

        # Capture stdout as the structured data
        # For fls/ils: write body file for Plaso consumption
        if sub in ("fls", "ils"):
            body_path = Path(ctx.output_dir) / "body.txt"
            body_path.write_text("\n".join(stdout_lines), encoding="utf-8")
        rows = stdout_lines[:2000]
        summary = f"tsk {sub}: {len(stdout_lines)} line(s)"

        ctx.bus.publish(E.tool_end(
            ctx.investigation_id, call_id, res.exit_code, res.duration_s, None,
        ))
        ctx.bus.publish(E.agent_observation(ctx.investigation_id, tool=self.name, summary=summary))
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name, "image": self.image, "args": args,
            "exit_code": res.exit_code, "duration_s": res.duration_s,
            "output_hash": None, "ts": E._now_iso(),
        }))

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=None, output_path=None,
            summary=summary, data={"subtool": sub, "output": rows},
        )


tool = SleuthKitTool()
