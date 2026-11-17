"""Runs one script, in a process of its own (started by runner.py).

    stdin   {"code": "...", "args": {...}}
    fd 3    one line: the result as JSON, after a sentinel
    stdout, stderr   whatever the script prints: its log

The script defines ``main(args)`` and returns something JSON can hold.

Defence in depth, not the boundary: an import hook refuses the modules a
script has no business with (sockets, processes, native code). The boundary
is the container this process runs in: no network at all, a read-only
filesystem, no capabilities, and the limits runner.py sets on this process.
"""

import builtins
import json
import os
import sys

SENTINEL = "NIK-SANDBOX-RESULT:"
REFUSED = (
    "socket", "ssl", "subprocess", "multiprocessing", "ctypes", "_ctypes", "asyncio", "http", "urllib", "ftplib",
    "smtplib", "telnetlib", "xmlrpc", "socketserver", "select", "selectors", "signal", "pty", "fcntl", "mmap",
    "resource", "importlib", "pip", "venv", "ensurepip", "webbrowser", "shutil", "tempfile", "glob", "pathlib",
)  # fmt: skip
_import = builtins.__import__


def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):  # noqa: A002 - the signature of __import__
    root = name.split(".")[0]
    # Taking an address apart is computing: urllib.parse is the one part of urllib a script gets.
    parsing = name == "urllib.parse" or (name == "urllib" and tuple(fromlist or ()) == ("parse",))
    if level == 0 and root in REFUSED and not parsing:
        raise ImportError(f'"{root}" is not available to scripts: a script computes, it does not reach out')
    return _import(name, globals, locals, fromlist, level)


def emit(payload):
    with os.fdopen(3, "w", encoding="utf-8") as out:
        out.write(SENTINEL + json.dumps(payload) + "\n")


def run():
    try:
        request = json.loads(sys.stdin.read() or "{}")
        code, args = request["code"], request.get("args") or {}
    except (ValueError, KeyError, TypeError):
        return {"ok": False, "error": "The sandbox was given a request it cannot read"}
    try:
        compiled = compile(code, "<script>", "exec")
    except SyntaxError as error:
        return {"ok": False, "error": f"Line {error.lineno}: {error.msg}"}
    builtins.__import__ = guarded_import
    # What a script has no use for: opening files, starting an interactive session.
    for name in ("open", "input", "breakpoint", "exit", "quit", "help"):
        builtins.__dict__.pop(name, None)
    scope = {"__name__": "__script__", "__builtins__": builtins}
    try:
        exec(compiled, scope)  # noqa: S102 - this is what the sandbox is for
        main = scope.get("main")
        if not callable(main):
            return {"ok": False, "error": "The script defines no main(args)"}
        result = main(args)
        json.dumps(result)
    except BaseException as error:  # noqa: BLE001 - whatever the script raises is its failure, not ours
        if isinstance(error, (TypeError, ValueError)) and "JSON" in str(error):
            return {
                "ok": False,
                "error": "main(args) returned something that is not JSON: return dicts, lists, text, numbers",
            }
        line = None
        trace = error.__traceback__
        while trace is not None:
            if trace.tb_frame.f_code.co_filename == "<script>":
                line = trace.tb_lineno
            trace = trace.tb_next
        where = f"Line {line}: " if line else ""
        return {"ok": False, "error": f"{where}{type(error).__name__}: {str(error)[:500]}"}
    return {"ok": True, "result": result}


if __name__ == "__main__":
    emit(run())
