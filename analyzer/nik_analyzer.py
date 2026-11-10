"""Nik analyzer worker: static disassembly and decompilation with rizin.

The worker runs in its own container (see Dockerfile), next to the Nik
backend, with the sample store mounted read-only. For each request it opens
the stored file in rizin, runs the automatic analysis and returns functions,
calls, per-function control-flow graphs, the strings each function uses and
the Rust crate it comes from (from panic locations), and within a time budget
the pseudo-C of each function from rz-ghidra (Ghidra's decompiler, shipped as
a rizin plugin in the official image). The sample is only read, disassembled
and decompiled: nothing is loaded into memory as a program or executed.

Python 3.9 (the rizin image ships Debian bullseye), standard library only:
rizin is driven through its pipe mode (``rizin -q0``), where every command's
output ends with a NUL byte.
"""

from __future__ import annotations

import bisect
import json
import os
import re
import struct
import subprocess
import threading
import time
from collections import Counter
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

# A safety cap, not a working limit: a ~5,000-function Rust binary is
# disassembled in about 75 s; past the cap the list is marked truncated.
MAX_FUNCTIONS = int(os.environ.get("ANALYZER_MAX_FUNCTIONS", "20000"))
MAX_BLOCKS_PER_FUNCTION = 400
MAX_OPS_PER_FUNCTION = 4000
CALL_TYPES = {"call", "ucall", "rcall", "icall", "ircall", "ccall", "uccall"}

# Decompilation limits: one function may not take longer than this (rz-ghidra
# has no timeout of its own, so a stuck function costs the session), its code
# is cut at MAX_DECOMPILED_CHARS, and the up-front pass stops once its output
# reaches MAX_DECOMPILED_TOTAL; the rest is decompiled on demand.
DECOMPILE_FUNCTION_SECONDS = 30
MAX_DECOMPILED_CHARS = 64_000
MAX_DECOMPILED_TOTAL = 12_000_000
DECOMPILER = "rz-ghidra"

# Strings a function references, kept per function (file offsets, for linking
# indicators of compromise to code).
MAX_STRING_REFS_PER_FUNCTION = 64

# Rust embeds the source path of every panic site in a `Location` struct
# (`&str` file, line, column). A path under `.cargo/registry/src` names the
# crate (`hyper-0.14.32` → hyper); one under `library/<std|core|alloc>` is the
# standard library. Rust strings are not NUL-terminated, so rizin merges them
# and a path often sits in the middle of a longer string: the tell-tale part
# is found first, then the path's real start (where the `&str` points) is
# searched backwards: a drive (`C:\`), `/rustc/<hash>/`, or the start of an
# absolute Unix path.
_PATH_CHAR = "[^\x00-\x1f\"'<>|]"
RUST_CRATE_PATH = re.compile(
    r"registry[\\/]src[\\/][^\\/]+[\\/]([A-Za-z0-9_\-]+?)-\d+\.\d+[^\\/]*[\\/]src[\\/]" + _PATH_CHAR + r"*?\.rs"
)
RUST_STD_PATH = re.compile(r"library[\\/](std|core|alloc|proc_macro|panic_\w+)[\\/]src[\\/]" + _PATH_CHAR + r"*?\.rs")
_DRIVE = re.compile(r"[A-Za-z]:[\\/]")
_RUSTC = re.compile(r"/rustc/[0-9a-f]{40}/$")
_BAD_IN_PATH = re.compile("[\x00-\x1f\"'<>|]")
DATA_SECTIONS = (".rdata", ".data", ".rodata", ".data.rel.ro", "__const", "__data")

# rz-ghidra syntax-highlight classes → the one-letter span kinds Nik stores.
_SPAN_KINDS = {
    "keyword": "k",
    "comment": "c",
    "datatype": "t",
    "function_name": "f",
    "function_parameter": "p",
    "local_variable": "v",
    "constant_variable": "n",
    "global_variable": "g",
}


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


class DataIndex:
    """What a data address means: a string (by file offset) and/or a Rust crate.

    Built once per sample from rizin's strings (``izj``), sections (``iSj``)
    and the file's bytes. ``resolve`` answers for any address an instruction
    points at: the string it lands in, and the crate when the address is a
    Rust panic path or a pointer to one (the `Location` struct).
    """

    def __init__(self, strings: Iterable[dict], sections: Iterable[dict], data: bytes) -> None:
        self.starts: List[int] = []
        self.ranges: List[Tuple[int, int, int]] = []  # (vaddr, end, paddr)
        self.paths: Dict[int, str] = {}
        self.crates: Counter = Counter()
        for s in sorted(strings, key=lambda s: s.get("vaddr", 0)):
            vaddr, paddr, text = s.get("vaddr"), s.get("paddr"), s.get("string", "")
            if vaddr is None or paddr is None:
                continue
            size = s.get("size") or len(text.encode("utf-8"))
            self.starts.append(vaddr)
            self.ranges.append((vaddr, vaddr + size, paddr))
            for match, label in rust_paths(text):
                self.paths[vaddr + len(text[:match].encode("utf-8"))] = label
                self.crates[label] += 1
        self.holders = pointer_holders(data, sections, self.paths)

    def string_at(self, addr: int) -> Optional[int]:
        """File offset of ``addr`` when it lands inside a known string."""
        i = bisect.bisect_right(self.starts, addr) - 1
        if i >= 0:
            vaddr, end, paddr = self.ranges[i]
            if vaddr <= addr < end:
                return paddr + (addr - vaddr)
        return None

    def resolve(self, addr: Any) -> Tuple[Optional[int], Optional[str]]:
        """``(string file offset, crate)`` for an address an instruction refers to."""
        if not isinstance(addr, int) or addr <= 0:
            return None, None
        target = self.holders.get(addr, addr)
        return self.string_at(target), self.paths.get(target)


def rust_paths(text: str) -> List[Tuple[int, str]]:
    """``(character offset, crate)`` of each Rust source path in ``text`` (``std`` for the standard library)."""
    found = [(_path_start(text, m.start()), m.group(1)) for m in RUST_CRATE_PATH.finditer(text)]
    found += [(_path_start(text, m.start()), "std") for m in RUST_STD_PATH.finditer(text)]
    return found


def _path_start(text: str, pivot: int) -> int:
    """Where the path containing ``text[pivot]`` begins."""
    head = text[:pivot]
    rustc = _RUSTC.search(head)
    if rustc:
        return rustc.start()
    drives = [m.start() for m in _DRIVE.finditer(head)]
    if drives and not _BAD_IN_PATH.search(head[drives[-1] :]):
        return drives[-1]
    # Unix: the run of non-blank path characters ending at the pivot, from its first "/".
    run = pivot
    while run > 0 and not head[run - 1].isspace() and not _BAD_IN_PATH.match(head[run - 1]):
        run -= 1
    slash = head.find("/", run)
    return slash if slash != -1 else pivot


def pointer_holders(data: bytes, sections: Iterable[dict], targets: Dict[int, Any]) -> Dict[int, int]:
    """Addresses in data sections that hold a 64- or 32-bit pointer to one of ``targets``.

    That is how code reaches a Rust panic path: it loads the address of a
    `Location` struct whose first field points at the path.
    """
    holders: Dict[int, int] = {}
    if not targets:
        return holders
    for section in sections:
        name, size, paddr, vaddr = (
            section.get("name", ""),
            section.get("size") or 0,
            section.get("paddr"),
            section.get("vaddr"),
        )
        if name not in DATA_SECTIONS or not size or paddr is None or vaddr is None:
            continue
        raw = data[paddr : paddr + size]
        for width, fmt in ((8, "<Q"), (4, "<I")):
            for offset in range(0, len(raw) - width + 1, width):
                (value,) = struct.unpack_from(fmt, raw, offset)
                if value in targets:
                    holders.setdefault(vaddr + offset, value)
    return holders


def _op_addresses(op: Dict[str, Any]) -> List[Any]:
    """Data addresses an instruction may refer to: rip-relative and absolute operands
    (``ptr``), immediates (``val``, e.g. ``push offset str`` in 32-bit code) and data refs.
    Values that land in no string are ignored by the caller."""
    found = [op.get("ptr"), op.get("val")]
    found += [ref.get("addr") for ref in op.get("refs") or [] if ref.get("type", "DATA") != "CALL"]
    return found


def build_function(
    fn: Dict[str, Any],
    blocks: Optional[List[dict]],
    pdf: Optional[dict],
    names: Dict[int, str],
    index: Optional[DataIndex] = None,
) -> Dict[str, Any]:
    """One function: summary fields, its calls, its CFG and, given an index, strings and crates."""
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

    if index is not None:
        strings: List[int] = []
        crates: Counter = Counter()
        for op in ops:
            for addr in _op_addresses(op):
                string, crate = index.resolve(addr)
                if crate:
                    crates[crate] += 1
                if string is not None and string not in strings and len(strings) < MAX_STRING_REFS_PER_FUNCTION:
                    strings.append(string)
        if strings:
            entry["strings"] = strings
        if crates:
            entry["crates"] = dict(crates)
    return entry


def build_decompiled(pdgj: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """rz-ghidra's ``pdgj`` → ``{code, spans, truncated}``, or None when there is no code.

    ``spans`` are ``[start, end, kind]`` (``[start, end, "f", address]`` for a
    function name rizin resolved), sorted and non-overlapping, with offsets
    into ``code``. rizin's verbose annotations (about 10x the code's size) are
    reduced to the highlight classes and the call targets.
    """
    code = (pdgj or {}).get("code") or ""
    if not code.strip():
        return None
    lead = len(code) - len(code.lstrip("\n"))
    code = code[lead:].rstrip()
    truncated = len(code) > MAX_DECOMPILED_CHARS
    code = code[:MAX_DECOMPILED_CHARS]

    targets: Dict[Tuple[int, int], int] = {}
    kinds: Dict[Tuple[int, int], str] = {}
    for note in (pdgj or {}).get("annotations") or []:
        start, end = note.get("start", 0) - lead, note.get("end", 0) - lead
        if start < 0 or end <= start or end > len(code):
            continue
        if note.get("type") == "function_name" and isinstance(note.get("offset"), int):
            targets[(start, end)] = note["offset"]
        elif note.get("type") == "syntax_highlight" and note.get("syntax_highlight") in _SPAN_KINDS:
            kinds[(start, end)] = _SPAN_KINDS[note["syntax_highlight"]]

    spans: List[list] = []
    last_end = 0
    for start, end in sorted(set(kinds) | set(targets)):
        if start < last_end:
            continue
        if (start, end) in targets:
            spans.append([start, end, "f", targets[(start, end)]])
        elif (
            spans and len(spans[-1]) == 3 and spans[-1][2] == kinds[(start, end)] and _blank(code, spans[-1][1], start)
        ):
            spans[-1][1] = end  # same class across plain spaces (rizin splits comments per word)
        else:
            spans.append([start, end, kinds[(start, end)]])
        last_end = end
    return {"code": code, "spans": spans, "truncated": truncated}


def _blank(code: str, start: int, end: int) -> bool:
    gap = code[start:end]
    return gap.strip(" \t") == ""


LIBRARY_PREFIXES = ("flirt.", "sub.", "case.")


def looks_like_library(fn: Dict[str, Any]) -> bool:
    """Library or glue code by the worker's own evidence: a FLIRT match, a Rust crate, a thunk."""
    return bool(fn.get("crates")) or fn.get("name", "").startswith(LIBRARY_PREFIXES)


def decompile_functions(
    session: Any,
    functions: List[Dict[str, Any]],
    deadline: float,
    first: Tuple[Optional[int], ...] = (),
    clock: Callable[[], float] = time.monotonic,
    per_function: float = DECOMPILE_FUNCTION_SECONDS,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """Decompile the non-import ``functions`` until ``deadline`` (a ``clock`` value).

    Order: the addresses in ``first`` (entry point, ``main``), then the
    functions not recognised as library code (no FLIRT match, no Rust crate,
    not a thunk) before the others, the smallest first within each group,
    which gives the most coverage of the code worth reading per second. A function
    that crashes rizin or runs over ``per_function`` seconds (the watchdog
    stops rizin) is skipped and the session restarted, while restarts last.
    Returns the pseudo-C keyed by address (as a string) and
    ``{engine, done, failed, total, stopped}`` where ``stopped`` is None,
    ``"time"``, ``"size"`` or ``"error"`` (no restarts left).
    """
    own = [fn for fn in functions if fn.get("kind") != "import"]
    order = sorted(
        own,
        key=lambda fn: (
            fn["addr"] not in first,
            first.index(fn["addr"]) if fn["addr"] in first else 0,
            looks_like_library(fn),
            fn.get("size", 0),
        ),
    )
    decompiled: Dict[str, Dict[str, Any]] = {}
    stats: Dict[str, Any] = {"engine": DECOMPILER, "done": 0, "failed": 0, "total": len(own), "stopped": None}
    total_size = 0
    for fn in order:
        if clock() >= deadline:
            stats["stopped"] = "time"
            break
        if total_size >= MAX_DECOMPILED_TOTAL:
            stats["stopped"] = "size"
            break
        watchdog = threading.Timer(min(per_function, max(0.0, deadline - clock())), session.kill)
        watchdog.start()
        try:
            result = build_decompiled(session.cmdj(f"pdgj @ {fn['addr']}"))
        except AnalysisError:
            stats["failed"] += 1
            if clock() >= deadline:
                stats["stopped"] = "time"
                break
            try:
                session.restart()
            except AnalysisError:
                stats["stopped"] = "error"
                break
            continue
        finally:
            watchdog.cancel()
        if result is not None:
            decompiled[str(fn["addr"])] = result
            total_size += len(result["code"]) + 12 * len(result["spans"])
        stats["done"] += 1
    return decompiled, stats


class Session:
    """A rizin session on one file, analysed with ``aaa``, that can be reopened.

    rizin 0.9 can crash after thousands of commands in one session (a
    segfault that does not happen on the same command in a fresh session):
    ``restart`` reopens the file and reruns the analysis, at most
    ``MAX_RESTARTS`` times per request. ``stop`` (the request timeout) kills
    the current process and makes every later ``restart`` fail.
    """

    MAX_RESTARTS = 3

    def __init__(self, path: str, binary: str = "rizin", signatures: Iterable[str] = ()) -> None:
        self.path, self.binary = path, binary
        self.signatures = list(signatures)
        self.restarts = 0
        self.stopped = False
        self.pipe: Optional[RizinPipe] = None
        self._open()

    def _open(self) -> None:
        if self.stopped:
            raise AnalysisError("The analysis was stopped.")
        self.pipe = RizinPipe(self.path, self.binary)
        _configure(self.pipe)
        self.pipe.cmd("aaa")  # also applies rizin's bundled FLIRT signatures (sigdb)
        for signature in self.signatures:  # admin-provided .sig / .pat files
            self.pipe.cmd(f"Fs {signature}")

    def cmd(self, command: str) -> str:
        return self.pipe.cmd(command)

    def cmdj(self, command: str) -> Any:
        return self.pipe.cmdj(command)

    def restart(self) -> None:
        if self.restarts >= self.MAX_RESTARTS:
            raise AnalysisError(f"rizin crashed {self.restarts + 1} times on this sample")
        self.restarts += 1
        self.pipe.close()
        self._open()

    def kill(self) -> None:
        if self.pipe is not None:
            self.pipe.kill()

    def stop(self) -> None:
        self.stopped = True
        self.kill()

    def close(self) -> None:
        if self.pipe is not None:
            self.pipe.close()


class WarmSessions:
    """Analysed rizin sessions kept open after a request, so the next one skips ``aaa``.

    Opening a large binary costs a full analysis (a minute or more); a
    decompilation on demand right after costs a few seconds in a warm session.
    A session is used by one request at a time: ``take`` removes it, ``give``
    puts it back. At most ``size`` sessions are kept (the oldest is closed),
    each for at most ``idle`` seconds without use. Keys identify the file and
    the FLIRT signatures applied to it.
    """

    def __init__(self, size: int = 1, idle: float = 600, clock: Callable[[], float] = time.monotonic) -> None:
        self.size, self.idle, self.clock = size, idle, clock
        self._items: Dict[Tuple[Any, ...], Tuple[Any, float]] = {}
        self._lock = threading.Lock()

    def take(self, key: Tuple[Any, ...]) -> Optional[Any]:
        with self._lock:
            item = self._items.pop(key, None)
        if item is None:
            return None
        session, since = item
        if self.clock() - since > self.idle:
            session.close()
            return None
        session.restarts = 0  # the crash allowance is per request
        return session

    def give(self, key: Tuple[Any, ...], session: Any) -> None:
        if self.size <= 0:
            session.close()
            return
        with self._lock:
            replaced = self._items.pop(key, None)
            self._items[key] = (session, self.clock())
            evicted = [replaced[0]] if replaced else []
            while len(self._items) > self.size:
                oldest = min(self._items, key=lambda k: self._items[k][1])
                evicted.append(self._items.pop(oldest)[0])
        for old in evicted:
            old.close()

    def expire(self) -> None:
        """Close the sessions idle for longer than ``idle`` (called periodically)."""
        now = self.clock()
        with self._lock:
            stale = [k for k, (_, since) in self._items.items() if now - since > self.idle]
            closing = [self._items.pop(k)[0] for k in stale]
        for session in closing:
            session.close()


def _warm_key(path: str, signatures: Iterable[str]) -> Tuple[Any, ...]:
    return (path, tuple(signatures))


def disassemble_functions(
    session: Any, functions: List[Dict[str, Any]], names: Dict[int, str], index: Optional[DataIndex] = None
) -> List[Dict[str, Any]]:
    """``build_function`` for every function, surviving rizin crashes.

    A function whose commands crash rizin is retried once in a restarted
    session (the crash is cumulative, so it usually passes); if it crashes
    again it is kept without calls or CFG and marked ``"skipped"``. Raises
    AnalysisError when no restarts are left.
    """
    results = []
    for fn in functions:
        if is_import(fn.get("name", "")):
            results.append(build_function(fn, None, None, names))
            continue
        at = fn["offset"]
        for attempt in (1, 2):
            try:
                blocks, pdf = session.cmdj(f"afbj @ {at}"), session.cmdj(f"pdfj @ {at}")
                results.append(build_function(fn, blocks, pdf, names, index))
                break
            except AnalysisError:
                session.restart()
                if attempt == 2:
                    skipped = build_function(fn, [], {"ops": []}, names)
                    skipped["skipped"] = "rizin crashed while disassembling this function"
                    results.append(skipped)
    return results


def _configure(pipe: RizinPipe) -> None:
    for setting in ("e scr.color=0", "e scr.utf8=false", "e asm.bytes=false", "e scr.interactive=false"):
        pipe.cmd(setting)


def _timeout_error(timeout: float) -> AnalysisTimeout:
    return AnalysisTimeout(f"rizin did not finish within {int(timeout)} seconds")


def _guarded(
    timeout: float, path: str, binary: str, signatures: Iterable[str] = ()
) -> Tuple[Session, threading.Timer, threading.Event]:
    """Open an analysed session under a timer that stops it after ``timeout`` seconds."""
    timed_out = threading.Event()
    holder: Dict[str, Session] = {}

    def stop() -> None:
        timed_out.set()
        if "session" in holder:
            holder["session"].stop()

    timer = threading.Timer(timeout, stop)
    timer.start()
    try:
        holder["session"] = Session(path, binary, signatures)
    except AnalysisError:
        timer.cancel()
        if timed_out.is_set():
            raise _timeout_error(timeout) from None
        raise
    if timed_out.is_set():  # the timer fired while the first analysis ran
        timer.cancel()
        holder["session"].close()
        raise _timeout_error(timeout)
    return holder["session"], timer, timed_out


# ---------------------------------------------------------------------------
# Full analysis
# ---------------------------------------------------------------------------
def analyze(
    path: str,
    timeout: float = 600,
    binary: str = "rizin",
    decompile_seconds: float = 300,
    signatures: Iterable[str] = (),
    warm: Optional[WarmSessions] = None,
) -> Dict[str, Any]:
    """Disassemble the file at ``path``, then decompile within ``decompile_seconds``.

    ``signatures`` are extra FLIRT files applied after rizin's own. With
    ``warm``, the analysed session is kept for the decompilations on demand
    that usually follow.

    Raises AnalysisTimeout when the disassembly itself runs over ``timeout``
    seconds; the decompilation pass only ever shortens to fit what is left.
    """
    if not os.path.isfile(path):
        raise AnalysisError("Sample not found in the store.")
    started = time.monotonic()
    session, timer, timed_out = _guarded(timeout, path, binary, signatures)
    try:
        info = session.cmdj("ij") or {}
        functions = session.cmdj("aflj") or []
        functions.sort(key=lambda f: f.get("offset", 0))
        truncated = len(functions) > MAX_FUNCTIONS
        functions = functions[:MAX_FUNCTIONS]
        names = {f["offset"]: f.get("name", "") for f in functions}
        with open(path, "rb") as sample:
            index = DataIndex(session.cmdj("izj") or [], session.cmdj("iSj") or [], sample.read())
        results = disassemble_functions(session, functions, names, index)
        entries = session.cmdj("iej") or []
        entry = entries[0].get("vaddr") if entries else None
    except AnalysisError:
        timer.cancel()
        session.close()
        if timed_out.is_set():
            raise _timeout_error(timeout) from None
        raise

    keep = False
    try:
        main = next((fn["addr"] for fn in results if fn["name"] in ("main", "sym.main", "dbg.main")), None)
        deadline = min(started + timeout - 5, time.monotonic() + decompile_seconds)
        decompiled, stats = decompile_functions(session, results, deadline, first=(entry, main))
        keep = warm is not None and not timed_out.is_set() and stats["stopped"] != "error"
    finally:
        timer.cancel()
        if keep:
            warm.give(_warm_key(path, session.signatures), session)
        else:
            session.close()
    return {
        "engine": {"name": "rizin", "version": rizin_version(binary)},
        "info": summarize_info(info),
        "entry": entry,
        "functions": results,
        "truncated": truncated,
        "restarts": session.restarts,
        "crates": dict(index.crates.most_common()),
        "signatures": len(session.signatures),
        "decompiled": decompiled,
        "decompile": stats,
    }


def decompile_one(
    path: str,
    addr: int,
    timeout: float = 600,
    binary: str = "rizin",
    signatures: Iterable[str] = (),
    warm: Optional[WarmSessions] = None,
) -> Dict[str, Any]:
    """Pseudo-C of the function at ``addr`` (on demand, for functions the up-front pass skipped).

    With ``warm``, a session kept from an earlier request on the same file is
    reused (no new ``aaa``) and kept again afterwards.
    """
    if not os.path.isfile(path):
        raise AnalysisError("Sample not found in the store.")
    signatures = list(signatures)
    key = _warm_key(path, signatures)
    kept = warm.take(key) if warm is not None else None
    if kept is not None:
        timed_out = threading.Event()

        def stop() -> None:
            timed_out.set()
            kept.stop()

        timer = threading.Timer(timeout, stop)  # already analysed: only the decompilation is timed
        timer.start()
        try:
            return _decompile_in(kept, addr, timeout, timer, timed_out, warm, key)
        except _SessionLost:
            pass  # the kept session had died (rizin crash): analyse the file again below
    session, timer, timed_out = _guarded(timeout, path, binary, signatures)
    try:
        return _decompile_in(session, addr, timeout, timer, timed_out, warm, key)
    except _SessionLost as exc:
        raise AnalysisError(str(exc)) from None


class _SessionLost(AnalysisError):
    """rizin stopped answering in the middle of a request (not a timeout)."""


def _decompile_in(
    session: Any,
    addr: int,
    timeout: float,
    timer: threading.Timer,
    timed_out: threading.Event,
    warm: Optional[WarmSessions],
    key: Tuple[Any, ...],
) -> Dict[str, Any]:
    """Decompile ``addr`` in ``session``; keep the session warm afterwards when it is still usable."""
    healthy = False
    try:
        try:
            function = session.cmdj(f"afij @ {addr}") or []
            starts = bool(function) and function[0].get("offset") == addr
            result = build_decompiled(session.cmdj(f"pdgj @ {addr}")) if starts else None
        except AnalysisError as exc:
            if timed_out.is_set():
                raise _timeout_error(timeout) from None
            raise _SessionLost(str(exc)) from None
        healthy = True
        if not starts:
            raise AnalysisError(f"No function starts at 0x{addr:x}.")
        if result is None:
            raise AnalysisError(f"The decompiler produced no code for 0x{addr:x}.")
        return {"addr": addr, "engine": DECOMPILER, **result}
    finally:
        timer.cancel()
        if warm is not None and healthy and not timed_out.is_set():
            warm.give(key, session)
        else:
            session.close()
