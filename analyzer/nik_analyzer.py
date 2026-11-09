"""Nik analyzer worker: static disassembly of malware samples with rizin.

The worker runs in its own container (see Dockerfile), next to the Nik
backend, with the sample store mounted read-only. For each request it opens
the stored file in rizin, runs the automatic analysis and returns functions,
calls and per-function control-flow graphs as JSON. The sample is only read
and disassembled: nothing is loaded into memory as a program or executed.

Python 3.9 (the rizin image ships Debian bullseye), standard library only:
rizin is driven through its pipe mode (``rizin -q0``), where every command's
output ends with a NUL byte.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from typing import Any, Dict, List, Optional

MAX_FUNCTIONS = 3000
MAX_BLOCKS_PER_FUNCTION = 400
MAX_OPS_PER_FUNCTION = 4000
CALL_TYPES = {"call", "ucall", "rcall", "icall", "ircall", "ccall", "uccall"}


def rizin_version(binary: str = "rizin") -> str:
    """``0.9.1`` from ``rizin -v`` (pipe mode does not report it)."""
    try:
        out = subprocess.run([binary, "-v"], capture_output=True, text=True, timeout=10).stdout
        match = re.search(r"rizin\s+([0-9][\w.\-]*)", out)
        return match.group(1) if match else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unavailable"


class AnalysisError(Exception):
    """The file could not be analysed (bad input, rizin failure)."""


class AnalysisTimeout(AnalysisError):
    """rizin did not finish within the time limit and was stopped."""


class RizinPipe:
    """A rizin process in pipe mode; ``cmd`` returns a command's output as text."""

    def __init__(self, path: str, binary: str = "rizin") -> None:
        self.proc = subprocess.Popen(
            [binary, "-2", "-q0", path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self._read()  # the initial NUL after loading the file

    def _read(self) -> str:
        chunks = bytearray()
        while True:
            byte = self.proc.stdout.read(1)
            if not byte:
                raise AnalysisError("rizin stopped unexpectedly")
            if byte == b"\x00":
                return chunks.decode("utf-8", errors="replace")
            chunks += byte

    def cmd(self, command: str) -> str:
        self.proc.stdin.write(command.encode("utf-8") + b"\n")
        self.proc.stdin.flush()
        return self._read()

    def cmdj(self, command: str) -> Any:
        text = self.cmd(command).strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()

    def close(self) -> None:
        try:
            self.proc.stdin.write(b"q!\n")
            self.proc.stdin.flush()
            self.proc.wait(timeout=5)
        except Exception:
            self.kill()


# ---------------------------------------------------------------------------
# Pure transforms (rizin JSON → Nik JSON); unit-tested with recorded output
# ---------------------------------------------------------------------------
_OPERAND_CLEAN = re.compile(r"^(?:dword|qword|word|byte)\s*(?:ptr\s*)?\[|\]$")


def callee_name(op: Dict[str, Any]) -> str:
    """The call target as written in the disassembly (``sym.imp.puts``, ``fcn.00401000``…)."""
    disasm = op.get("disasm") or op.get("opcode") or ""
    operand = disasm.split(None, 1)[1] if " " in disasm else ""
    return _OPERAND_CLEAN.sub("", operand.strip()).strip()


def is_import(name: str) -> bool:
    """rizin names imported functions ``sym.imp.<name>`` (ELF/Mach-O stubs, PE thunks)."""
    return name.startswith(("sym.imp.", "imp."))


def summarize_info(info: Dict[str, Any]) -> Dict[str, Any]:
    bin_info = (info or {}).get("bin", {})
    keys = ("arch", "bits", "os", "class", "machine", "compiler", "lang", "stripped", "canary", "nx", "pie", "static")
    return {key: bin_info.get(key) for key in keys if key in bin_info}


def build_function(
    fn: Dict[str, Any], blocks: Optional[List[dict]], pdf: Optional[dict], names: Dict[int, str]
) -> Dict[str, Any]:
    """One function: summary fields, its calls and its CFG (blocks with instructions)."""
    name = fn.get("name", "")
    entry = {
        "addr": fn["offset"],
        "name": name,
        "kind": "import" if is_import(name) else "function",
        "size": fn.get("realsz", fn.get("size", 0)),
        "blocks": fn.get("nbbs", 0),
        "edges": fn.get("edges", 0),
        "cc": fn.get("cc", 0),
        "indegree": fn.get("indegree", 0),
        "calls": [],
    }
    if entry["kind"] == "import":
        return entry

    ops = (pdf or {}).get("ops") or []
    truncated = len(ops) > MAX_OPS_PER_FUNCTION or len(blocks or []) > MAX_BLOCKS_PER_FUNCTION
    ops = ops[:MAX_OPS_PER_FUNCTION]
    seen = set()
    for op in ops:
        if op.get("type") not in CALL_TYPES:
            continue
        target = op.get("jump")
        callee = names.get(target) if target is not None else None
        label = callee or callee_name(op)
        key = (target, label)
        if label and key not in seen:
            seen.add(key)
            entry["calls"].append({"addr": target if callee else None, "name": label, "at": op.get("offset")})

    cfg_blocks = []
    for block in (blocks or [])[:MAX_BLOCKS_PER_FUNCTION]:
        start, size = block["addr"], block.get("size", 0)
        block_ops = [
            {
                "addr": op.get("offset"),
                "text": op.get("disasm") or op.get("opcode") or "invalid",
                "type": op.get("type", ""),
            }
            for op in ops
            if start <= (op.get("offset") or -1) < start + size
        ]
        cfg_blocks.append(
            {"addr": start, "size": size, "jump": block.get("jump"), "fail": block.get("fail"), "ops": block_ops}
        )
    entry["cfg"] = {"blocks": cfg_blocks, "truncated": truncated}
    return entry


# ---------------------------------------------------------------------------
# Full analysis
# ---------------------------------------------------------------------------
def analyze(path: str, timeout: float = 600, binary: str = "rizin") -> Dict[str, Any]:
    """Disassemble the file at ``path``; raises AnalysisTimeout after ``timeout`` seconds."""
    if not os.path.isfile(path):
        raise AnalysisError("Sample not found in the store.")
    pipe = RizinPipe(path, binary)
    timed_out = threading.Event()

    def stop() -> None:
        timed_out.set()
        pipe.kill()

    timer = threading.Timer(timeout, stop)
    timer.start()
    try:
        for setting in ("e scr.color=0", "e scr.utf8=false", "e asm.bytes=false", "e scr.interactive=false"):
            pipe.cmd(setting)
        info = pipe.cmdj("ij") or {}
        pipe.cmd("aaa")
        functions = pipe.cmdj("aflj") or []
        functions.sort(key=lambda f: f.get("offset", 0))
        truncated = len(functions) > MAX_FUNCTIONS
        functions = functions[:MAX_FUNCTIONS]
        names = {f["offset"]: f.get("name", "") for f in functions}
        results = []
        for fn in functions:
            if is_import(fn.get("name", "")):
                results.append(build_function(fn, None, None, names))
                continue
            at = fn["offset"]
            results.append(build_function(fn, pipe.cmdj(f"afbj @ {at}"), pipe.cmdj(f"pdfj @ {at}"), names))
        entries = pipe.cmdj("iej") or []
        return {
            "engine": {"name": "rizin", "version": rizin_version(binary)},
            "info": summarize_info(info),
            "entry": entries[0].get("vaddr") if entries else None,
            "functions": results,
            "truncated": truncated,
        }
    except AnalysisError:
        if timed_out.is_set():
            raise AnalysisTimeout(f"rizin did not finish within {int(timeout)} seconds") from None
        raise
    finally:
        timer.cancel()
        pipe.close()
