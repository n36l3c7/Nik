"""A collection (a zip) unpacked, in a process of its own: ``python -I unpack_job.py <mode> <zip> <request as JSON>``.

``server.py`` starts this for ``POST /unpack`` and ``POST /member``. A zip is hostile input: it is opened here
and nowhere else, with its memory and CPU time bounded and with the limits of ``nik_forensics/triage.py``.

``list``: every member is read once, in the order of the zip. It is hashed as it is written to a scratch file
that only this job knows (never under its own name), looked at (``parsers.recognise``, then the place it has in a
triage tree), and then either **kept** (a member some parser reads: moved to ``<files>/<sha256>.bin``, where the
worker holds what it was given, so the parse that follows needs no second transfer) or deleted (a program, an
archive, a file no parser reads). The answer is one JSON object per line:

    {"t": "member", "n", "path", "size", "sha256", "kind", "source", "parser", "executable", "kept",
     "host", "username", "profile", "skip"}                       ``skip``: the reason it was not read, when it was not
    {"t": "end", "members", "bytes", "recognised", "skipped", "executables", "unlisted", "password", "stopped", "error"}

``member``: one member by its path and SHA-256, written to the file ``out`` (a program that is listed and not kept,
fetched when someone asks to analyse it). Exit 0, 4 when the zip has no such member, 2 when it is not a zip.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

MARGIN = 256 * 1024 * 1024  # what is left free on the disk of the worker whatever it unpacks
PIECE = 1024 * 1024


def limits(member_max: int) -> None:
    try:
        import resource
    except ImportError:  # a development machine: nothing to bound with
        return
    memory = int(os.environ.get("FORENSICS_JOB_MEMORY_MB", "1536")) * 1024 * 1024
    seconds = int(os.environ.get("FORENSICS_JOB_SECONDS", "21600"))
    for what, soft in (
        (resource.RLIMIT_DATA, memory),
        (resource.RLIMIT_CPU, seconds),
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_FSIZE, member_max + PIECE),  # no file larger than a member may be
    ):
        try:
            _soft, hard = resource.getrlimit(what)
            wanted = soft if hard == resource.RLIM_INFINITY else min(soft, hard)
            resource.setrlimit(what, (wanted, hard if hard != resource.RLIM_INFINITY else wanted))
        except (ValueError, OSError):
            continue


class Said:
    def __init__(self) -> None:
        self.out = sys.stdout.buffer

    def __call__(self, event: dict) -> None:
        self.out.write(json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8", "replace") + b"\n")
        self.out.flush()


class Skipped(Exception):
    """A member that is not read: the reason, as a sentence."""


def extract(archive, info, target: str, cap: int) -> tuple[str, int, bytes]:
    """Write a member to ``target``: (SHA-256, size, its first 4096 bytes). The library reads no further than
    the size the member declares; ``cap`` is the one more guard."""
    digest = hashlib.sha256()
    size = 0
    head = b""
    try:
        with archive.open(info) as source, open(target, "wb") as out:
            while True:
                piece = source.read(PIECE)
                if not piece:
                    break
                if size == 0:
                    head = piece[:4096]
                size += len(piece)
                if size > cap:
                    raise Skipped("it expands to more than a member may")
                digest.update(piece)
                out.write(piece)
    except Skipped:
        raise
    except RuntimeError as error:
        raise Skipped(f"it cannot be opened: {str(error)[:100]}") from None
    except NotImplementedError:
        raise Skipped("it is compressed with a method the worker does not read") from None
    except (zipfile.BadZipFile, EOFError, OSError, ValueError, OverflowError) as error:
        raise Skipped(f"it cannot be read out of the zip ({type(error).__name__}: {str(error)[:100]})") from None
    except Exception as error:  # noqa: BLE001 - zlib and lzma raise their own: a member is skipped, the job goes on
        raise Skipped(f"it cannot be read out of the zip ({type(error).__name__}: {str(error)[:100]})") from None
    return digest.hexdigest(), size, head


def reader_of(target: str, name: str, described: dict) -> tuple[object | None, str, bool]:
    """(parser module, source, named only by its place) for a member: what its content says first, then the place
    it has in a triage tree."""
    from nik_forensics import parsers

    try:
        module, source = parsers.recognise(target, name)
    except parsers.UnknownParser:
        module, source = None, ""
    if module is not None:
        named = described.get("source", "")
        # A Chromium file does not say which browser it is of; the place does.
        if (
            module.KIND == described.get("kind")
            and module.KIND == "browser"
            and named in module.SOURCES
            and named.split(".")[-1] == source.split(".")[-1]
        ):
            source = named
        return module, source, False
    if described.get("source"):
        return parsers.by_source(described["kind"], described["source"]), described["source"], True
    return None, "", False


def list_members(path: str, request: dict, say: Said) -> int:
    from nik_forensics import triage

    total_cap = int(request["total"])
    member_max = min(int(request.get("member") or triage.MEMBER_MAX), triage.MEMBER_MAX)
    max_members = min(int(request.get("maxMembers") or triage.MAX_MEMBERS), triage.MAX_MEMBERS)
    files, scratch = str(request["files"]), str(request["scratch"])
    zip_name = str(request.get("fileName") or "")
    os.makedirs(files, exist_ok=True)
    os.makedirs(scratch, exist_ok=True)
    ending = {
        "t": "end",
        "members": 0,
        "bytes": 0,
        "recognised": 0,
        "skipped": 0,
        "executables": 0,
        "unlisted": 0,
        "password": False,
        "stopped": None,
        "error": None,
        "limits": {"total": total_cap, "member": member_max, "members": max_members},
    }
    try:
        archive = triage.Archive(path)
    except (zipfile.BadZipFile, OSError, EOFError, ValueError, NotImplementedError) as error:
        ending["error"] = f"This is not a zip Nik can open ({type(error).__name__}: {str(error)[:150]})"
        say(ending)
        return 3
    try:
        if archive.overlapping():
            ending["error"] = (
                "The members of this zip overlap: it holds more compressed data than its size, as a zip bomb does"
            )
            say(ending)
            return 3
        members = archive.members()
        ending["password"] = archive.try_password(members)
        held = os.path.join(scratch, "member")
        total = 0
        stopped = False
        listed = 0
        for info in members:
            if listed >= max_members:
                ending["unlisted"] = len(members) - listed
                ending["stopped"] = ending["stopped"] or f"only the first {max_members} members are listed"
                break
            name = triage.display_name(info)
            line = {
                "t": "member",
                "n": listed,
                "path": name,
                "size": info.file_size,
                "sha256": None,
                "kind": None,
                "source": None,
                "parser": None,
                "executable": False,
                "kept": False,
                "host": "",
                "username": "",
                "profile": "",
            }
            listed += 1
            reason = triage.refuse_name(name)
            if reason is None and triage.is_symlink(info):
                reason = "it is a symbolic link (it is never followed)"
            if reason is None and info.flag_bits & 0x1 and not archive.password:
                reason = (
                    "it is encrypted with AES, which the worker cannot open"
                    if info.compress_type == 99
                    else "it is encrypted and the password is not known"
                )
            if reason is None and info.file_size > member_max:
                reason = f"it is larger than the {member_max >> 30} GiB a member may be"
            if (
                reason is None
                and info.file_size >= triage.RATIO_FROM
                and info.compress_size > 0
                and info.file_size / info.compress_size > triage.RATIO_MAX
            ):
                reason = f"it expands {info.file_size // info.compress_size} times: it looks like a zip bomb"
            if reason is None and (stopped or total + info.file_size > total_cap):
                if not stopped:
                    ending["stopped"] = f"the collection expands to more than the {total_cap >> 20} MB allowed"
                stopped = True
                reason = (
                    "the collection is larger than the unpacked size allowed: "
                    "this member and the ones after it were not read"
                )
            if reason is None and shutil.disk_usage(scratch).free < info.file_size + MARGIN:
                reason = "the worker has no room on its disk for it"
                ending["stopped"] = ending["stopped"] or "the worker ran out of room on its disk"
            if reason is not None:
                line["skip"] = reason
                ending["skipped"] += 1
                say(line)
                continue
            try:
                sha256, size, head = extract(archive, info, held, member_max)
            except Skipped as skipped:
                line["skip"] = str(skipped)
                ending["skipped"] += 1
                say(line)
                continue
            total += size
            line.update(size=size, sha256=sha256)
            described = triage.describe(name, zip_name)
            line.update(host=described["host"], username=described["username"], profile=described["profile"])
            keep = False
            if triage.is_archive(head, name):
                line["skip"] = triage.ARCHIVE_SENTENCE
            elif triage.is_executable(head, name):
                line["executable"] = True
                ending["executables"] += 1
            else:
                module, source, by_place = reader_of(held, name, described)
                if module is not None:
                    line.update(kind=module.KIND, source=source, parser=module.NAME)
                    keep = True
                    ending["recognised"] += 1
                elif by_place:
                    line["skip"] = f"Nik has no reader for {source} in this version"
            if keep:
                target = os.path.join(files, f"{sha256}.bin")
                if os.path.exists(target):
                    os.unlink(held)
                else:
                    os.replace(held, target)
                line["kept"] = True
            else:
                os.unlink(held)
            if line.get("skip"):
                ending["skipped"] += 1
            say(line)
        ending["members"], ending["bytes"] = listed, total
    finally:
        archive.close()
        if os.path.exists(os.path.join(scratch, "member")):
            os.unlink(os.path.join(scratch, "member"))
    say(ending)
    return 0


def one_member(path: str, request: dict, say: Said) -> int:
    from nik_forensics import triage

    wanted, sha256, target = str(request["path"]), str(request["sha256"]), str(request["out"])
    cap = min(int(request.get("total") or triage.MEMBER_MAX), triage.MEMBER_MAX)
    try:
        archive = triage.Archive(path)
    except (zipfile.BadZipFile, OSError, EOFError, ValueError, NotImplementedError):
        say({"detail": "This is not a zip the worker can open"})
        return 2
    try:
        archive.try_password(archive.members())
        for info in archive.members():
            if triage.display_name(info) != wanted or info.file_size > cap:
                continue
            try:
                found, size, _head = extract(archive, info, target, cap)
            except Skipped as skipped:
                say({"detail": str(skipped)})
                return 4
            if found == sha256:
                say({"size": size})
                return 0
        say({"detail": "The collection holds no such member"})
        return 4
    finally:
        archive.close()


def main(argv: list[str]) -> int:
    mode, path, request = argv[1], argv[2], json.loads(argv[3])
    from nik_forensics import triage

    limits(min(int(request.get("member") or triage.MEMBER_MAX), triage.MEMBER_MAX))
    say = Said()
    if mode == "list":
        return list_members(path, request, say)
    if mode == "member":
        return one_member(path, request, say)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
