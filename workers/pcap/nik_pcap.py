"""Packet captures, read by Wireshark's own engine (tshark and sharkd).

- ``summarize(path, keylog)`` reads a capture once with tshark and returns
  what the incident keeps: counts, protocols, hosts, DNS, HTTP, TLS server
  names, POST requests, periodic connections (beacons), Expert Info and the
  exported objects with their SHA-256.
- ``Sessions`` keeps a ``sharkd`` process per open capture: the packet
  list with Wireshark's colours, the protocol tree with the bytes of each
  field, display filters, Follow Stream and Export Objects, as in Wireshark.

A capture is untrusted input: both tools run as an unprivileged user, in a
container without network or capabilities, with a time limit per request.
A TLS key log (``SSLKEYLOGFILE``) is written to /tmp only while it is in use.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import shutil
import statistics
import subprocess
import tempfile
import threading
import time
from collections import Counter, defaultdict
from typing import Any

TIMEOUT = float(os.environ.get("PCAP_TIMEOUT", "900"))
RPC_TIMEOUT = float(os.environ.get("PCAP_RPC_TIMEOUT", "300"))
MAX_SESSIONS = int(os.environ.get("PCAP_MAX_SESSIONS", "2"))
SESSION_IDLE = float(os.environ.get("PCAP_SESSION_IDLE", "900"))
OBJECTS_MAX = 500
OBJECT_HASH_BYTES = 200 * 1024 * 1024
LIST_MAX = 500

EXPORT_TAPS = ("eo:http", "eo:smb", "eo:ftp-data", "eo:tftp", "eo:imf", "eo:dicom")
FOLLOW = ("TCP", "UDP", "HTTP", "HTTP2", "TLS", "QUIC", "WebSocket", "SIP", "DCCP")
# sharkd methods the backend may call, and the taps it may request.
METHODS = {"status", "frames", "frame", "follow", "tap", "download", "check", "complete"}
TAPS = set(EXPORT_TAPS) | {"expert"}
FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "dns.flags.response",
    "dns.qry.name",
    "dns.a",
    "dns.aaaa",
    "http.host",
    "http.request.method",
    "http.request.full_uri",
    "tls.handshake.extensions_server_name",
    "_ws.col.Protocol",
)


class CaptureError(Exception):
    """The capture cannot be read (``status`` is the HTTP status to answer)."""

    def __init__(self, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.status = status


def _keylog_file(keylog: str | None) -> str | None:
    if not keylog:
        return None
    handle, path = tempfile.mkstemp(prefix="nik-keys-", suffix=".log")
    with os.fdopen(handle, "w", encoding="utf-8") as out:
        out.write(keylog)
    return path


def _public(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Summary (tshark, one pass)                                                  #
# --------------------------------------------------------------------------- #
def _tshark_rows(path: str, keys: str | None):
    command = [shutil.which("tshark") or "tshark", "-n", "-r", path, "-T", "fields", "-E", "separator=\t"]
    command += ["-E", "occurrence=a", "-E", "aggregator=,"]
    if keys:
        command += ["-o", f"tls.keylog_file:{keys}"]
    for name in FIELDS:
        command += ["-e", name]
    process = subprocess.Popen(  # noqa: S603 - fixed binary and arguments
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace"
    )
    deadline = time.monotonic() + TIMEOUT
    try:
        for line in process.stdout:
            if time.monotonic() > deadline:
                process.kill()
                raise CaptureError(f"tshark took more than {int(TIMEOUT)} s", 504)
            values = line.rstrip("\n").split("\t")
            yield dict(zip(FIELDS, values + [""] * (len(FIELDS) - len(values)), strict=False))
        process.wait(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()
    if process.returncode not in (0, None):
        error = (process.stderr.read() or "").strip().splitlines()
        raise CaptureError(error[-1][:300] if error else "tshark cannot read the capture")


def beacons(starts: dict[tuple[str, str, str], list[float]]) -> list[dict[str, Any]]:
    """Connections repeated at a regular interval: 6 or more, at least 5 s apart,
    with less than 15 % variation between the intervals."""
    found = []
    for (src, dst, port), times in starts.items():
        if len(times) < 6:
            continue
        times = sorted(times)
        gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
        mean = statistics.fmean(gaps)
        if mean < 5:
            continue
        jitter = statistics.pstdev(gaps) / mean
        if jitter <= 0.15:
            found.append(
                {
                    "source": src,
                    "destination": dst,
                    "port": port,
                    "count": len(times),
                    "interval": round(mean, 1),
                    "jitter": round(jitter, 3),
                    "first": times[0],
                    "last": times[-1],
                }
            )
    return sorted(found, key=lambda b: -b["count"])[:50]


def summarize(path: str, keylog: str | None = None) -> dict[str, Any]:
    keys = _keylog_file(keylog)
    try:
        packets, size, first, last = 0, 0, None, None
        protocols: Counter[str] = Counter()
        hosts: dict[str, dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})
        dns: dict[str, set[str]] = defaultdict(set)
        http: dict[str, dict[str, Any]] = {}
        sni: Counter[str] = Counter()
        posts: list[dict[str, Any]] = []
        starts: dict[tuple[str, str, str], list[float]] = defaultdict(list)
        for row in _tshark_rows(path, keys):
            packets += 1
            try:
                when = float(row["frame.time_epoch"])
            except ValueError:
                when = None
            if when is not None:
                first = when if first is None else min(first, when)
                last = when if last is None else max(last, when)
            length = int(row["frame.len"] or 0)
            size += length
            if row["_ws.col.Protocol"]:
                protocols[row["_ws.col.Protocol"]] += 1
            src = row["ip.src"] or row["ipv6.src"]
            dst = row["ip.dst"] or row["ipv6.dst"]
            for address in (src, dst):
                if address and "," not in address:
                    hosts[address]["packets"] += 1
                    hosts[address]["bytes"] += length
            if row["tcp.flags.syn"] in ("1", "True") and row["tcp.flags.ack"] in ("0", "False") and when is not None:
                starts[(src, dst, row["tcp.dstport"])].append(when)
            if row["dns.qry.name"]:
                answers = [a for a in (row["dns.a"] + "," + row["dns.aaaa"]).split(",") if a]
                for name in row["dns.qry.name"].split(","):
                    dns[name.lower()].update(answers if row["dns.flags.response"] in ("1", "True") else [])
            for name in filter(None, row["tls.handshake.extensions_server_name"].split(",")):
                sni[name.lower()] += 1
            # Responses repeat the request's URI: count request packets only.
            if row["http.request.full_uri"] and row["http.request.method"]:
                uri = row["http.request.full_uri"].split(",")[0]
                method = row["http.request.method"].split(",")[0]
                item = http.setdefault(uri, {"url": uri, "method": method, "host": row["http.host"], "count": 0})
                item["count"] += 1
                if method in ("POST", "PUT", "PATCH") and len(posts) < LIST_MAX:
                    posts.append({"frame": int(row["frame.number"]), "time": when, "method": method, "url": uri})
        if packets == 0:
            raise CaptureError("No packet could be read from the file")
        return {
            "packets": packets,
            "bytes": size,
            "first": first,
            "last": last,
            "protocols": [{"name": n, "packets": c} for n, c in protocols.most_common(40)],
            "hosts": [
                {"address": a, **v, "public": _public(a)}
                for a, v in sorted(hosts.items(), key=lambda kv: -kv[1]["bytes"])[:LIST_MAX]
            ],
            "dns": [{"name": n, "answers": sorted(a)} for n, a in sorted(dns.items())][:LIST_MAX],
            "http": sorted(http.values(), key=lambda h: -h["count"])[:LIST_MAX],
            "tlsServerNames": [{"name": n, "count": c} for n, c in sni.most_common(LIST_MAX)],
            "posts": posts,
            "beacons": beacons(starts),
        }
    finally:
        if keys:
            os.unlink(keys)


# --------------------------------------------------------------------------- #
# sharkd sessions                                                             #
# --------------------------------------------------------------------------- #
class Shark:
    """One ``sharkd -`` process with one capture loaded (JSON-RPC over stdio)."""

    def __init__(self, path: str, keylog: str | None) -> None:
        self.keys = _keylog_file(keylog)
        self.lock = threading.Lock()
        self.used = time.monotonic()
        self.next_id = 0
        self.process = subprocess.Popen(  # noqa: S603 - fixed binary
            [shutil.which("sharkd") or "sharkd", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        try:
            if self.keys:
                self.call("setconf", {"name": "tls.keylog_file", "value": self.keys}, timeout=30)
            self.call("load", {"file": path}, timeout=TIMEOUT)
        except Exception:
            self.close()
            raise

    def call(self, method: str, params: dict[str, Any] | None = None, timeout: float = RPC_TIMEOUT) -> Any:
        with self.lock:
            self.used = time.monotonic()
            self.next_id += 1
            request = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
            if params:
                request["params"] = params
            if self.process.poll() is not None:
                raise CaptureError("The capture reader stopped", 502)
            self.process.stdin.write(json.dumps(request) + "\n")
            self.process.stdin.flush()
            answer: list[str] = []
            reader = threading.Thread(target=lambda: answer.append(self.process.stdout.readline()), daemon=True)
            reader.start()
            reader.join(timeout)
            if reader.is_alive() or not answer or not answer[0]:
                self.process.kill()
                raise CaptureError(f"The capture reader did not answer within {int(timeout)} s", 504)
            reply = json.loads(answer[0])
            if "error" in reply:
                raise CaptureError(str(reply["error"].get("message") or "sharkd error"), 422)
            return reply.get("result")

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
        if self.keys and os.path.exists(self.keys):
            os.unlink(self.keys)


class Sessions:
    """Open captures by id: at most ``MAX_SESSIONS``, the least recently used is closed first."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.open: dict[str, tuple[Shark, str]] = {}

    def get(self, capture_id: str, path: str, keylog: str | None) -> Shark:
        fingerprint = hashlib.sha256(f"{path}\0{keylog or ''}".encode()).hexdigest()
        with self.lock:
            current = self.open.get(capture_id)
            if current and current[1] == fingerprint and current[0].process.poll() is None:
                return current[0]
            if current:
                current[0].close()
                del self.open[capture_id]
            while len(self.open) >= MAX_SESSIONS:
                oldest = min(self.open, key=lambda k: self.open[k][0].used)
                self.open.pop(oldest)[0].close()
        shark = Shark(path, keylog)
        with self.lock:
            self.open[capture_id] = (shark, fingerprint)
        return shark

    def drop(self, capture_id: str) -> None:
        with self.lock:
            current = self.open.pop(capture_id, None)
        if current:
            current[0].close()

    def expire(self) -> None:
        now = time.monotonic()
        with self.lock:
            stale = [k for k, (s, _) in self.open.items() if now - s.used > SESSION_IDLE]
            closing = [self.open.pop(k)[0] for k in stale]
        for shark in closing:
            shark.close()


SESSIONS = Sessions()
_FILTER = re.compile(r"^[\x20-\x7e]{0,2000}$")


def _clean_params(method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Only the parameters each method needs, with their types checked."""
    out: dict[str, Any] = {}
    if "filter" in params:
        value = str(params["filter"])
        if not _FILTER.match(value):
            raise CaptureError("Invalid display filter", 400)
        out["filter"] = value
    if method == "frames":
        skip, limit = int(params.get("skip") or 0), int(params.get("limit") or 200)
        if skip > 0:
            out["skip"] = skip
        out["limit"] = max(1, min(limit, 1000))
    elif method == "frame":
        out["frame"] = max(1, int(params.get("frame") or 1))
        out["proto"] = True
        out["bytes"] = True
    elif method == "follow":
        kind = str(params.get("follow") or "")
        if kind not in FOLLOW:
            raise CaptureError("Unsupported stream type", 400)
        out["follow"] = kind
    elif method == "tap":
        tap = str(params.get("tap0") or "")
        if tap not in TAPS:
            raise CaptureError("Unsupported tap", 400)
        out["tap0"] = tap
    elif method == "download":
        token = str(params.get("token") or "")
        if not re.fullmatch(r"eo:[a-z-]+_\d{1,6}", token) or token.rsplit("_", 1)[0] not in EXPORT_TAPS:
            raise CaptureError("Unsupported download", 400)
        out["token"] = token
    elif method == "complete":
        out["field"] = str(params.get("field") or "")[:100]
    return out


# Time column formats of the packet list. Columns are never taken from the
# caller: some custom column definitions crash sharkd.
TIME_FIELDS = {"absolute": "frame.time_utc:0", "delta": "frame.time_delta_displayed:0"}


def rpc(capture_id: str, path: str, keylog: str | None, method: str, params: dict[str, Any]) -> Any:
    if method not in METHODS:
        raise CaptureError("Unsupported method", 400)
    params = params or {}
    shark = SESSIONS.get(capture_id, path, keylog)
    clean = _clean_params(method, params)
    result = shark.call(method, clean or None)
    time_format = str(params.get("time") or "relative")
    if method == "frames" and time_format in TIME_FIELDS and isinstance(result, list):
        times = shark.call(method, {**clean, "column0": TIME_FIELDS[time_format]})
        by_number = {row["num"]: row["c"][0] for row in times or []}
        for row in result:
            if row.get("num") in by_number and len(row.get("c") or []) > 1:
                row["c"][1] = by_number[row["num"]]
    return result


def objects(capture_id: str, path: str, keylog: str | None) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Every exported object (with its SHA-256) and the Expert Info counts."""
    shark = SESSIONS.get(capture_id, path, keylog)
    found: list[dict[str, Any]] = []
    hashed = 0
    for tap in EXPORT_TAPS:
        result = shark.call("tap", {"tap0": tap}) or {}
        for item in (result.get("taps") or [{}])[0].get("objects") or []:
            if len(found) >= OBJECTS_MAX:
                break
            entry = {
                "tap": tap,
                "token": item.get("_download"),
                "frame": item.get("pkt"),
                "host": item.get("hostname") or "",
                "type": item.get("type") or "",
                "name": item.get("filename") or "",
                "size": int(item.get("len") or 0),
            }
            if entry["token"] and hashed + entry["size"] <= OBJECT_HASH_BYTES:
                data = base64.b64decode((shark.call("download", {"token": entry["token"]}) or {}).get("data") or "")
                entry["sha256"] = hashlib.sha256(data).hexdigest()
                hashed += len(data)
            found.append(entry)
    expert = (shark.call("tap", {"tap0": "expert"}) or {}).get("taps") or [{}]
    counts = Counter(d.get("s") for d in expert[0].get("details") or [])
    return found, {k: v for k, v in counts.items() if k}


def download(capture_id: str, path: str, keylog: str | None, token: str) -> dict[str, Any]:
    result = rpc(capture_id, path, keylog, "download", {"token": token}) or {}
    return {
        "name": result.get("file") or "object",
        "mime": result.get("mime") or "",
        "data": base64.b64decode(result.get("data") or ""),
    }
