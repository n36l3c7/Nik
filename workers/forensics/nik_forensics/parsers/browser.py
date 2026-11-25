"""Browser history: Chromium (Chrome, Edge, Brave, Opera), Firefox and Safari.

Sources, as ``<browser>.<what>``:

    chrome|edge|brave|opera . history    History: visits (``visits`` joined to ``urls``), downloads, and the
                                         terms searched (``keyword_search_terms``)
    chrome|edge|brave|opera . shortcuts  Shortcuts: the omnibox shortcuts
    chrome|edge|brave|opera . bookmarks  Bookmarks (a JSON file)
    firefox.places                       places.sqlite: visits, bookmarks, downloads (annotations)
    safari.history                       History.db: visits
    safari.downloads, safari.bookmarks   Downloads.plist, Bookmarks.plist
    <browser>.json, <browser>.csv        a generic export (an array of rows, or a Chrome Bookmarks file)

A Chromium file does not say which browser wrote it: ``sniff`` answers ``chrome.<what>`` and the source the
import gives wins. One record per row, whatever its time: a row with no usable time keeps ``ts`` None and is
counted in a note. Nothing is dropped in silence: a table the source should have and the file lacks, a table
that stops at a damaged page, a row that cannot be read and a limit that is hit are skips; ``in_file`` is the
sum of the ``count(*)`` of the tables read, so a clean file ends with ``read == in_file``.

The profile, the host and the user come from the import (``profile``, ``host``, ``username`` in the
parameters) and are part of the keys: two profiles never collide. A WAL or journal file next to the database
is not given to the worker: a database in WAL mode is said in a note. Standard library only.

The place of a record in its file (``loc``): ``{"table", "rowid"}`` for a row of a database (the real name of
the table: ``visits``, ``moz_historyvisits``, ``history_visits``, ``moz_bookmarks``, ``moz_annos``...);
``{"row": n}`` for a row of a JSON or CSV export, counted from 1 (the first row after the header, the first
element of the array); ``{"index": n}`` for an entry of a Safari download list (from 0); ``{"path", "index"}``
for a bookmark of a Chromium or Safari file: its folder and its position among the bookmarks of that folder,
from 0, in file order. A CSV row with more cells than the header is kept: the extra cells are in its data
under ``extra``, and a note counts such rows.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import plistlib
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote, urlsplit

from .. import sqlite_safe, viewing
from . import BadLocator, ViewError

NAME = "browser"
VERSION = "2"
KIND = "browser"

_CHROMIUM = ("chrome", "edge", "brave", "opera")
SOURCES = (
    *(f"{browser}.{what}" for browser in _CHROMIUM for what in ("history", "bookmarks", "shortcuts", "json", "csv")),
    "firefox.places",
    "firefox.json",
    "firefox.csv",
    "safari.history",
    "safari.downloads",
    "safari.bookmarks",
    "safari.json",
    "safari.csv",
)

# Rows read from one table, and the size of a text, JSON or plist file read whole.
MAX_ROWS = 2_000_000
MAX_FILE = 64 * 1024 * 1024
MAX_DEPTH = 100
MAX_URL = 8192  # a longer URL is cut before it is split for its domain; the URL itself is kept whole

CHROMIUM_REDIRECT_MASK = 0x40000000 | 0x80000000
FIREFOX_REDIRECT_TYPES = {5, 6}
WEBKIT_EPOCH_OFFSET_MS = 11644473600000
MAC_EPOCH_OFFSET_S = 978307200
# Unix ms of 9999-12-31: beyond it no calendar can print the date.
MAX_MS = 253402300799000

CHROME_ROOT_LABELS = {"bookmark_bar": "Bookmarks bar", "other": "Other bookmarks", "synced": "Synced bookmarks"}
SAFARI_ROOT_LABELS = {
    "BookmarksBar": "Favorites",
    "BookmarksMenu": "Bookmarks Menu",
    "com.apple.ReadingList": "Reading List",
}
FIREFOX_ROOT_LABELS = {
    "root________": "",
    "menu________": "Bookmarks Menu",
    "toolbar_____": "Bookmarks Toolbar",
    "unfiled_____": "Other Bookmarks",
    "mobile______": "Mobile Bookmarks",
    "tags________": "Tags",
}

# The columns of a generic export, lower-case with no separators (the names the old importer knew).
_ALIASES = {
    "url": ["url"],
    "title": ["title", "titolo"],
    "visitCount": ["visitcount", "visits"],
    "visitTime": ["visittime", "dataleggibile", "date", "timestamp", "data"],
    "name": ["name", "nome", "title", "titolo"],
    "folder": ["folder", "cartella"],
    "dateAdded": ["dateadded", "data", "date", "timestamp"],
    "text": ["text", "testo"],
    "contents": ["contents", "title", "titolo"],
    "lastAccessTime": ["lastaccesstime"],
    "hits": ["numberofhits", "hits"],
    "fileName": ["filename", "nomefile", "name", "nome", "targetpath", "file"],
    "downloadUrl": ["url", "source", "sourceurl", "from", "downloadurl"],
    "referrer": ["referrer", "referer", "taburl", "site", "sito"],
    "startTime": ["starttime", "date", "data", "timestamp", "downloadedat"],
    "totalBytes": ["totalbytes", "size", "bytes", "dimensione"],
}
_CONTAINERS = ("history", "bookmarks", "shortcuts", "downloads", "entries", "rows", "data", "items", "records")
_SEPARATORS = re.compile(r"[\s_-]+")


# --------------------------------------------------------------------------- #
# Times: the values of a bad row are None, never an exception                 #
# --------------------------------------------------------------------------- #
def _plausible(ms: float | None) -> int | None:
    return int(ms) if ms is not None and -MAX_MS <= ms <= MAX_MS else None


def _num(value: Any) -> float | None:
    if isinstance(value, (bytes, bytearray)):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if number == number else None  # not NaN


def webkit_to_ms(us: Any) -> int | None:
    """WebKit time (microseconds since 1601) as Unix ms."""
    number = _num(us)
    if number is None or number <= 0:
        return None
    return _plausible(round(number / 1000) - WEBKIT_EPOCH_OFFSET_MS)


def firefox_to_ms(us: Any) -> int | None:
    """Firefox PRTime (microseconds since 1970) as Unix ms."""
    number = _num(us)
    if number is None or number <= 0:
        return None
    return _plausible(round(number / 1000))


def mac_to_ms(seconds: Any) -> int | None:
    """Mac absolute time (seconds since 2001) as Unix ms."""
    number = _num(seconds)
    if number is None:
        return None
    try:
        return _plausible(round((number + MAC_EPOCH_OFFSET_S) * 1000))
    except (OverflowError, ValueError):
        return None


def any_to_ms(value: Any) -> int | None:
    """A time of a generic export: the size of a number says its epoch and unit, a text is a date."""
    if value is None or value == "":
        return None
    number = _num(value)
    if number is not None:
        if number > 1e14:
            return webkit_to_ms(number)
        if number > 1e11:
            return _plausible(round(number))
        if number > 1e8:
            return _plausible(round(number * 1000))
        return None
    text = str(value).strip().replace(" ", "T").replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return _plausible(round(moment.timestamp() * 1000))
    except (ValueError, OverflowError, OSError):
        return None


def _plist_ms(value: Any) -> int | None:
    if not isinstance(value, datetime):
        return None
    try:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return _plausible(round(value.timestamp() * 1000))
    except (ValueError, OverflowError, OSError):
        return None


# --------------------------------------------------------------------------- #
# Small helpers                                                               #
# --------------------------------------------------------------------------- #
def _s(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace").strip()
    return str(value).strip()


def _count(value: Any) -> int:
    number = _num(value)
    return round(number) if number is not None and number >= 0 else 0


def _int(value: Any) -> int:
    number = _num(value)
    try:
        return int(number) if number is not None else 0
    except (OverflowError, ValueError):
        return 0


def _file_name(path: Any) -> str:
    value = _s(path)
    if not value:
        return ""
    if value.lower().startswith("file:"):
        value = unquote(re.sub(r"^file:/*", "", value, flags=re.I))
    value = re.split(r"[?#]", value)[0]
    parts = [part for part in re.split(r"[\\/]", value) if part]
    return parts[-1] if parts else value


def _host_of(url: str) -> str:
    """The host of an http(s) URL, lower-case, no port; empty for any other URL."""
    try:
        parts = urlsplit(url)
        return (parts.hostname or "").lower() if parts.scheme.lower() in ("http", "https") else ""
    except ValueError:
        return ""


def _domain_of(url: Any) -> str:
    """The host of an http(s) or ftp URL for ``data["domain"]``: lower-case, no port, no leading ``www.``, IPv6 with
    no brackets, punycode as written. Empty for any other URL or one that cannot be split; it never raises."""
    if not isinstance(url, str) or not url:
        return ""
    try:
        parts = urlsplit(url.strip()[:MAX_URL])
        if parts.scheme.lower() not in ("http", "https", "ftp"):
            return ""
        host = (parts.hostname or "").lower()
    except ValueError:
        return ""
    return host.removeprefix("www.")


def _is_web(url: str) -> bool:
    return url.lower().startswith(("http://", "https://"))


def _digest(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8", "replace")).hexdigest()[:16]


def _pick(row: dict[str, Any], names: list[str]) -> Any:
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip() != "":
            return value
    return None


# --------------------------------------------------------------------------- #
# What the records of one import look like                                    #
# --------------------------------------------------------------------------- #
class _Emit:
    def __init__(self, ctx, browser: str) -> None:
        self.ctx = ctx
        self.browser = browser
        self.host = str(ctx.params.get("host") or "")
        self.username = str(ctx.params.get("username") or "")
        self.profile = str(ctx.params.get("profile") or "")
        self.no_time = 0
        self.no_url = 0
        self._seen: dict[str, int] = {}
        self.extra: list | None = None  # the cells a CSV row has past its header, for the record being made

    def key(self, kind: str, ident: Any, dedupe: bool = False) -> str:
        key = f"web:{self.host}:{self.username}:{self.browser}:{self.profile}:{kind}:{ident}"
        if dedupe:
            # Two bookmarks that are the same still are two rows: the second one is told apart by its order.
            seen = self._seen[key] = self._seen.get(key, 0) + 1
            if seen > 1:
                key = f"{key}~{seen}"
        return key

    def _record(self, kind, ident, ts, summary, data, loc, ioc=(), dedupe=False) -> None:
        if ts is None:
            self.no_time += 1
        data = {**data, "browser": self.browser, "profile": self.profile}
        domain = _domain_of(data.get("url"))
        if domain:
            data["domain"] = domain
        if kind == "download":  # the site the download came from, when it is another key than the URL
            site = _domain_of(data.get("referrer"))
            if site:
                data["referrerDomain"] = site
        if self.extra:
            data["extra"] = list(self.extra)
        self.ctx.record(
            key=self.key(kind, ident, dedupe),
            type=kind,
            ts=ts,
            host=self.host,
            username=self.username,
            summary=summary,
            data=data,
            loc=loc,
            ioc=ioc,
        )

    def visit(self, ident, ts, url, title, count, visit_id, from_id, transition, redirect, loc, dedupe=False) -> None:
        if not url:
            self.no_url += 1
        host = _host_of(url)
        data = {
            "url": url,
            "title": title,
            "visitCount": count,
            "visitId": visit_id,
            "fromVisitId": from_id,
            "transition": transition,
            "isRedirect": redirect,
        }
        self._record("visit", ident, ts, title or url, data, loc, [("domain", host)] if host else (), dedupe)

    def download(self, ident, loc, dedupe=False, **d) -> None:
        url = d["url"]
        host = _host_of(url)
        summary = f"{d['fileName']} <- {host}" if host else d["fileName"]
        self._record("download", ident, d["startTime"], summary, d, loc, [("url", url)] if _is_web(url) else (), dedupe)

    def bookmark(self, ident, ts, name, url, folder, loc) -> None:
        data = {"name": name, "url": url, "folder": folder, "dateAdded": ts}
        self._record("bookmark", ident, ts, name or url, data, loc, [("url", url)] if _is_web(url) else (), True)

    def shortcut(self, ident, ts, text, url, title, hits, loc, dedupe=False) -> None:
        data = {"text": text, "url": url, "title": title, "hits": hits}
        self._record("shortcut", ident, ts, text or url, data, loc, [("url", url)] if _is_web(url) else (), dedupe)

    def search(self, ident, ts, term, url, loc) -> None:
        self._record("search", ident, ts, term, {"term": term, "url": url}, loc, (), True)

    def notes(self) -> None:
        if self.no_time:
            self.ctx.note("row without a usable time", count=self.no_time, detail="kept with no time")
        if self.no_url:
            self.ctx.note("visit without a URL row", count=self.no_url, detail="its url id points at no row of urls")


# --------------------------------------------------------------------------- #
# The tables of a database                                                    #
# --------------------------------------------------------------------------- #
class _Db:
    """The tables of one database, the count of rows each says it holds, and what could not be read."""

    def __init__(self, ctx, conn: sqlite3.Connection, names: set[str]) -> None:
        self.ctx = ctx
        self.conn = conn
        self.names = names
        self.in_file = 0
        self.known = True

    def need(self, table: str, what: str = "") -> bool:
        """A table the source should have: when it is missing, rows may be lost with it."""
        if table in self.names:
            return True
        detail = f"{table}: the file has no such table" + (f", {what}" if what else "")
        self.ctx.skip("table missing", lost=0, detail=detail)
        return False

    def want(self, table: str, what: str) -> bool:
        """A table that only some versions have: when it is missing, nothing is lost."""
        if table in self.names:
            return True
        self.ctx.note("table missing", detail=f"{table}: {what}")
        return False

    def scan(self, table: str, sql: str, handle, count_sql: str | None = None) -> None:
        ctx = self.ctx
        total = sqlite_safe.scalar(self.conn, count_sql) if count_sql else sqlite_safe.count(self.conn, table)
        total = total if isinstance(total, int) else None
        if total is None:
            self.known = False
        else:
            self.in_file += total
        read = 0
        try:
            for row in sqlite_safe.rows(self.conn, sql):
                if read >= MAX_ROWS:
                    lost = max(total - read, 0) if total is not None else 0
                    ctx.skip("limit reached", lost=lost, detail=f"{table}: only the first {MAX_ROWS} rows were read")
                    break
                read += 1
                try:
                    handle(row)
                except Exception as exc:  # noqa: BLE001 - one bad row must not stop the table
                    rowid = row.get("rid", row.get("visit_id"))
                    ctx.skip("row cannot be read", lost=1, detail=f"{table} rowid {rowid}: {exc!r}"[:300])
        except sqlite3.DatabaseError as exc:
            lost = max(total - read, 0) if total is not None else 0
            ctx.skip("table cannot be read to its end", lost=lost, detail=f"{table} after {read} rows: {exc}")


def _chromium(db: _Db, out: _Emit, what: str) -> None:
    if what == "shortcuts":
        if db.need("omni_box_shortcuts"):
            db.scan(
                "omni_box_shortcuts",
                "SELECT rowid AS rid, id, text, url, contents, last_access_time, number_of_hits"
                " FROM omni_box_shortcuts",
                lambda r: out.shortcut(
                    _s(r["id"]) or r["rid"],
                    webkit_to_ms(r["last_access_time"]),
                    _s(r["text"]),
                    _s(r["url"]),
                    _s(r["contents"]),
                    _count(r["number_of_hits"]),
                    {"table": "omni_box_shortcuts", "rowid": r["rid"]},
                ),
            )
        return

    if db.need("visits", "the visits are not in this file") and db.need("urls", "the visits have no URL"):

        def visit(r):
            transition = _int(r["transition"])
            out.visit(
                r["visit_id"],
                webkit_to_ms(r["visit_time"]),
                _s(r["url"]),
                _s(r["title"]),
                _count(r["visit_count"]),
                r["visit_id"],
                r["from_visit"] or None,
                transition,
                (transition & CHROMIUM_REDIRECT_MASK) != 0,
                {"table": "visits", "rowid": r["visit_id"]},
            )

        db.scan(
            "visits",
            """SELECT v.id AS visit_id, v.from_visit AS from_visit, v.transition AS transition,
                      v.visit_time AS visit_time, u.url AS url, u.title AS title, u.visit_count AS visit_count
               FROM visits AS v LEFT JOIN urls AS u ON u.id = v.url ORDER BY v.id""",
            visit,
        )

    if db.need("downloads", "the downloads of this profile may be lost"):
        chain: dict[Any, str] = {}
        if db.need("downloads_url_chain", "the URLs of the downloads are missing"):
            try:
                for n, r in enumerate(
                    sqlite_safe.rows(db.conn, "SELECT id, url FROM downloads_url_chain ORDER BY id, chain_index")
                ):
                    if n >= MAX_ROWS:
                        break
                    chain[r["id"]] = _s(r["url"])  # the last one of the chain is where the file came from
            except sqlite3.DatabaseError as exc:
                db.ctx.skip("table cannot be read to its end", lost=0, detail=f"downloads_url_chain: {exc}")

        def download(r):
            ident = r["id"] if r.get("id") is not None else r["rid"]
            target = _s(r.get("target_path")) or _s(r.get("current_path"))
            url = chain.get(r.get("id")) or _s(r.get("tab_url"))
            out.download(
                ident,
                {"table": "downloads", "rowid": r["rid"]},
                fileName=_file_name(target) or _file_name(url) or "(unknown)",
                targetPath=target,
                url=url,
                referrer=_s(r.get("referrer")) or _s(r.get("tab_url")) or _s(r.get("site_url")) or url,
                startTime=webkit_to_ms(r.get("start_time")),
                endTime=webkit_to_ms(r.get("end_time")),
                totalBytes=_count(r.get("total_bytes")),
                receivedBytes=_count(r.get("received_bytes")),
                mimeType=_s(r.get("mime_type")),
                state=_int(r.get("state")),
            )

        db.scan("downloads", "SELECT rowid AS rid, * FROM downloads ORDER BY rowid", download)

    if db.want("keyword_search_terms", "this version of the browser keeps no search terms") and "urls" in db.names:

        def search(r):
            term = _s(r["term"])
            out.search(
                f"{r['url_id']}:{_digest(term)}",
                webkit_to_ms(r["last_visit_time"]),
                term,
                _s(r["url"]),
                {"table": "keyword_search_terms", "rowid": r["rid"]},
            )

        db.scan(
            "keyword_search_terms",
            """SELECT k.rowid AS rid, k.url_id AS url_id, k.term AS term, u.url AS url,
                      u.last_visit_time AS last_visit_time
               FROM keyword_search_terms AS k LEFT JOIN urls AS u ON u.id = k.url_id ORDER BY k.rowid""",
            search,
        )


def _firefox(db: _Db, out: _Emit) -> None:
    if db.need("moz_places", "the visits have no URL") and db.need(
        "moz_historyvisits", "the visits are not in this file"
    ):

        def visit(r):
            visit_type = _int(r["visit_type"])
            out.visit(
                r["visit_id"],
                firefox_to_ms(r["visit_date"]),
                _s(r["url"]),
                _s(r["title"]),
                _count(r["visit_count"]),
                r["visit_id"],
                r["from_visit"] or None,
                visit_type,
                visit_type in FIREFOX_REDIRECT_TYPES,
                {"table": "moz_historyvisits", "rowid": r["visit_id"]},
            )

        db.scan(
            "moz_historyvisits",
            """SELECT v.id AS visit_id, v.from_visit AS from_visit, v.visit_type AS visit_type,
                      v.visit_date AS visit_date, p.url AS url, p.title AS title, p.visit_count AS visit_count
               FROM moz_historyvisits AS v LEFT JOIN moz_places AS p ON p.id = v.place_id ORDER BY v.id""",
            visit,
        )

    if db.need("moz_bookmarks", "the bookmarks may be lost"):
        _firefox_bookmarks(db, out)

    if db.want("moz_annos", "this profile keeps no download annotations") and db.need(
        "moz_anno_attributes", "the downloads cannot be told from other annotations"
    ):
        _firefox_downloads(db, out)


def _firefox_bookmarks(db: _Db, out: _Emit) -> None:
    nodes: dict[Any, dict[str, Any]] = {}
    try:
        for n, r in enumerate(sqlite_safe.rows(db.conn, "SELECT id, parent, title, guid FROM moz_bookmarks")):
            if n >= MAX_ROWS:
                break
            nodes[r["id"]] = r
    except sqlite3.DatabaseError as exc:
        db.ctx.note("bookmark folders unknown", detail=f"moz_bookmarks cannot be read to its end: {exc}")

    def climb(parent_id):
        """The folders above a node, from the root down, and whether one of them is the tags root."""
        parts: list[str] = []
        current, guard, tagged = nodes.get(parent_id), 0, False
        while current is not None and guard < 50:
            if current.get("guid") == "tags________":
                tagged = True
            label = FIREFOX_ROOT_LABELS.get(current.get("guid"), _s(current.get("title")))
            if label:
                parts.insert(0, label)
            if not current.get("parent") or current["parent"] == current["id"]:
                break
            current = nodes.get(current["parent"])
            guard += 1
        return " > ".join(parts), tagged

    tags = 0

    def bookmark(r):
        nonlocal tags
        folder, tagged = climb(r["parent"])
        if tagged:
            tags += 1  # a tag is a second place for a bookmark that is already there, not a bookmark
            return
        out.bookmark(
            _digest(folder, _s(r["title"]), _s(r["url"])),
            firefox_to_ms(r["date_added"]),
            _s(r["title"]) or "(unnamed)",
            _s(r["url"]),
            folder or None,
            {"table": "moz_bookmarks", "rowid": r["rid"]},
        )

    db.scan(
        "moz_bookmarks",
        """SELECT b.id AS rid, b.title AS title, b.dateAdded AS date_added, b.parent AS parent, p.url AS url
           FROM moz_bookmarks AS b LEFT JOIN moz_places AS p ON p.id = b.fk WHERE b.type = 1 ORDER BY b.id""",
        bookmark,
        count_sql="SELECT count(*) FROM moz_bookmarks WHERE type = 1",
    )
    if tags:
        db.in_file -= tags
        db.ctx.note("tag entry, not a bookmark", count=tags, detail="the bookmark itself is in its own folder")


def _firefox_downloads(db: _Db, out: _Emit) -> None:
    def download(r):
        dest = _s(r["dest"])
        file_size = 0
        end_time = None
        state = 1
        if r["meta_json"]:
            try:
                meta = json.loads(r["meta_json"])
                file_size = _count(meta.get("fileSize"))
                end_time = _plausible(_num(meta.get("endTime"))) if meta.get("endTime") else None
                if isinstance(meta.get("state"), int):
                    state = meta["state"]
            except (ValueError, TypeError, AttributeError):
                pass  # a metaData that is not JSON: the defaults stand
        url = _s(r["source_url"])
        out.download(
            r["rid"],
            {"table": "moz_annos", "rowid": r["rid"]},
            fileName=_file_name(dest) or "(unknown)",
            targetPath=dest,
            url=url,
            referrer=url,
            # The date of the annotation, and the last visit of the place when it has none.
            startTime=firefox_to_ms(r["date_added"]) or firefox_to_ms(r["last_visit"]),
            endTime=end_time,
            totalBytes=file_size,
            receivedBytes=file_size,
            mimeType="",
            state=state,
        )

    db.scan(
        "moz_annos",
        """SELECT dest.id AS rid, p.url AS source_url, dest.content AS dest, dest.dateAdded AS date_added,
                  meta.content AS meta_json, p.last_visit_date AS last_visit
           FROM moz_annos AS dest
           JOIN moz_anno_attributes AS a_dest ON a_dest.id = dest.anno_attribute_id
            AND a_dest.name = 'downloads/destinationFileURI'
           LEFT JOIN moz_places AS p ON p.id = dest.place_id
           LEFT JOIN moz_anno_attributes AS a_meta ON a_meta.name = 'downloads/metaData'
           LEFT JOIN moz_annos AS meta ON meta.place_id = dest.place_id AND meta.anno_attribute_id = a_meta.id
           ORDER BY dest.id""",
        download,
        count_sql="""SELECT count(*) FROM moz_annos AS dest
                     JOIN moz_anno_attributes AS a ON a.id = dest.anno_attribute_id
                      AND a.name = 'downloads/destinationFileURI'""",
    )


def _safari(db: _Db, out: _Emit) -> None:
    if not (db.need("history_items", "the visits have no URL") and db.need("history_visits", "no visits in this file")):
        return

    def visit(r):
        source = r["redirect_source"]
        out.visit(
            r["visit_id"],
            mac_to_ms(r["visit_time"]),
            _s(r["url"]),
            _s(r["title"]),
            _count(r["visit_count"]),
            r["visit_id"],
            source or None,
            None,
            source is not None,
            {"table": "history_visits", "rowid": r["visit_id"]},
        )

    db.scan(
        "history_visits",
        """SELECT v.id AS visit_id, v.redirect_source AS redirect_source, v.visit_time AS visit_time,
                  v.title AS title, i.url AS url, i.visit_count AS visit_count
           FROM history_visits AS v LEFT JOIN history_items AS i ON i.id = v.history_item ORDER BY v.id""",
        visit,
    )


def _sqlite(path: str, ctx, out: _Emit, source: str) -> int | None:
    browser, what = source.split(".")
    if sqlite_safe.wal_mode(path):
        ctx.note("database in WAL mode", detail="rows still in the -wal file are not in this file")
    try:
        conn = sqlite_safe.open_ro(path)
    except (sqlite3.DatabaseError, OSError) as exc:
        ctx.skip("database cannot be opened", lost=0, detail=str(exc))
        return None
    try:
        try:
            names = sqlite_safe.tables(conn)
        except sqlite3.DatabaseError as exc:
            ctx.skip("database cannot be opened", lost=0, detail=f"the table list cannot be read: {exc}")
            return None
        db = _Db(ctx, conn, names)
        if browser == "firefox":
            _firefox(db, out)
        elif browser == "safari":
            _safari(db, out)
        else:
            _chromium(db, out, what)
        return db.in_file if db.known else None
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# JSON, plists, generic exports                                               #
# --------------------------------------------------------------------------- #
def _read_whole(path: str, ctx) -> bytes | None:
    size = os.path.getsize(path)
    if size > MAX_FILE:
        ctx.skip("limit reached", lost=0, detail=f"the file is {size} bytes: files over {MAX_FILE} are not read")
        return None
    with open(path, "rb") as handle:
        return handle.read(MAX_FILE + 1)


def _chrome_bookmarks(path: str, ctx, out: _Emit) -> int | None:
    data = _read_whole(path, ctx)
    if data is None:
        return None
    try:
        parsed = json.loads(data.decode("utf-8-sig", "replace"))
        roots = parsed.get("roots") if isinstance(parsed, dict) else None
        if not isinstance(roots, dict):
            raise ValueError('no "roots" in the file')
    except (ValueError, RecursionError) as exc:
        ctx.skip("file cannot be read", lost=0, detail=f"not a Chromium Bookmarks file: {exc}")
        return None
    leaves = 0
    placed: dict[str, int] = {}  # bookmarks met so far in each folder: the next one's place in it

    def walk(node, folder, depth, index):
        nonlocal leaves
        if depth > MAX_DEPTH:
            ctx.skip("limit reached", lost=0, detail=f"bookmarks nested deeper than {MAX_DEPTH} folders, in {folder}")
            return
        if not isinstance(node, dict):
            return
        if node.get("type") == "url":
            leaves += 1
            position = placed[folder] = placed.get(folder, -1) + 1
            url = _s(node.get("url"))
            if not url:
                ctx.skip(
                    "row cannot be read", lost=1, detail=f"bookmark without a URL in {folder}: {_s(node.get('name'))}"
                )
                return
            name = _s(node.get("name")) or "(unnamed)"
            out.bookmark(
                _digest(folder, name, url),
                webkit_to_ms(node.get("date_added")),
                name,
                url,
                folder or None,
                {"path": folder, "index": position},
            )
        elif isinstance(node.get("children"), list):
            name = _s(node.get("name"))
            inner = (f"{folder} > {name}" if folder else name) if name else folder
            for child in node["children"]:
                walk(child, inner, depth + 1, index)

    for root_key, root in roots.items():
        if isinstance(root, dict):
            label = CHROME_ROOT_LABELS.get(root_key, _s(root.get("name")) or root_key)
            for child in root.get("children") or []:
                walk(child, label, 0, 0)
    return leaves


def _plist(path: str, ctx, out: _Emit, what: str) -> int | None:
    data = _read_whole(path, ctx)
    if data is None:
        return None
    try:
        plist = plistlib.loads(data)
    except Exception as exc:  # noqa: BLE001 - plistlib raises several unrelated types on bad input
        ctx.skip("file cannot be read", lost=0, detail=f"not a property list: {type(exc).__name__}: {exc}")
        return None
    if what == "downloads":
        return _safari_downloads(plist, ctx, out)
    return _safari_bookmarks(plist, ctx, out)


def _safari_downloads(plist: Any, ctx, out: _Emit) -> int | None:
    entries = plist.get("DownloadHistory") if isinstance(plist, dict) else None
    if not isinstance(entries, list):
        ctx.skip("table missing", lost=0, detail='DownloadHistory: not a Safari Downloads.plist (no "DownloadHistory")')
        return None
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            ctx.skip("row cannot be read", lost=1, detail=f"DownloadHistory[{index}] is not a dictionary")
            continue
        try:
            url = _s(entry.get("DownloadEntryURL"))
            target = _s(entry.get("DownloadEntryPath"))
            end = _plist_ms(entry.get("DownloadEntryDateFinishedKey"))
            start = _plist_ms(entry.get("DownloadEntryDateAddedKey"))
            out.download(
                f"{_digest(url, target)}:{index}",
                {"index": index},
                fileName=_file_name(target) or _file_name(url) or "(unknown)",
                targetPath=target,
                url=url,
                referrer=url,
                startTime=start if start is not None else end,
                endTime=end,
                totalBytes=_count(entry.get("DownloadEntryProgressTotalToLoad")),
                receivedBytes=_count(entry.get("DownloadEntryProgressBytesSoFar")),
                mimeType="",
                state=1 if end is not None else 4,
            )
        except Exception as exc:  # noqa: BLE001
            ctx.skip("row cannot be read", lost=1, detail=f"DownloadHistory[{index}]: {exc!r}"[:300])
    return len(entries)


def _safari_bookmarks(plist: Any, ctx, out: _Emit) -> int | None:
    if not isinstance(plist, dict) or not isinstance(plist.get("Children"), list):
        ctx.skip("table missing", lost=0, detail="Children: not a Safari Bookmarks.plist (no root bookmark list)")
        return None
    leaves = 0
    placed: dict[str, int] = {}  # bookmarks met so far in each folder: the next one's place in it

    def walk(node, folder, depth):
        nonlocal leaves
        if not isinstance(node, dict):
            return
        if depth > MAX_DEPTH:
            ctx.skip("limit reached", lost=0, detail=f"bookmarks nested deeper than {MAX_DEPTH} folders, in {folder}")
            return
        kind = node.get("WebBookmarkType")
        if kind == "WebBookmarkTypeLeaf":
            leaves += 1
            position = placed[folder] = placed.get(folder, -1) + 1
            url = _s(node.get("URLString"))
            if not url:
                ctx.skip("row cannot be read", lost=1, detail=f"bookmark without a URL in {folder}")
                return
            uri = node.get("URIDictionary") if isinstance(node.get("URIDictionary"), dict) else {}
            reading = node.get("ReadingList") if isinstance(node.get("ReadingList"), dict) else {}
            name = _s(uri.get("title")) or _s(node.get("Title")) or "(unnamed)"
            out.bookmark(
                _digest(folder, name, url),
                _plist_ms(reading.get("DateAdded")),
                name,
                url,
                folder or None,
                {"path": folder, "index": position},
            )
        elif kind == "WebBookmarkTypeList" and isinstance(node.get("Children"), list):
            title = _s(node.get("Title"))
            label = SAFARI_ROOT_LABELS.get(title, title)
            path = (f"{folder} > {label}" if folder else label) if label else folder
            for child in node["Children"]:
                walk(child, path, depth + 1)

    for child in plist["Children"]:
        walk(child, "", 0)
    return leaves


def _normal(row: dict[Any, Any]) -> dict[str, Any]:
    return {_SEPARATORS.sub("", str(key).strip().lower()): value for key, value in row.items() if key is not None}


def _kind_of(rows: list[Any], hint: str) -> str:
    """What the rows of a generic export are: the container's name, else the columns they have."""
    if hint in ("history", "bookmarks", "shortcuts", "downloads"):
        return hint
    names: set[str] = set()
    for row in rows[:20]:
        if isinstance(row, dict):
            names |= set(_normal(row))
    if names & set(_ALIASES["folder"]):
        return "bookmarks"
    if names & {"contents", "hits", "numberofhits", "lastaccesstime"}:
        return "shortcuts"
    if names & {"filename", "nomefile", "targetpath", "totalbytes", "downloadurl", "sourceurl", "downloadedat"}:
        return "downloads"
    return "history"


def _text_rows(path: str, ctx, out: _Emit, what: str) -> int | None:
    data = _read_whole(path, ctx)
    if data is None:
        return None
    text = data.decode("utf-8-sig", "replace")
    hint = ""
    rows: Any = None
    if what == "json":
        try:
            parsed = json.loads(text)
        except (ValueError, RecursionError) as exc:
            ctx.skip("file cannot be read", lost=0, detail=f"not JSON: {exc}")
            return None
        if isinstance(parsed, dict) and isinstance(parsed.get("roots"), dict):
            return _chrome_bookmarks(path, ctx, out)
        if isinstance(parsed, list):
            rows = parsed
        elif isinstance(parsed, dict):
            for name in _CONTAINERS:
                if isinstance(parsed.get(name), list):
                    rows, hint = parsed[name], name
                    break
    else:
        try:
            csv.field_size_limit(MAX_FILE)
            rows = [dict(row) for row in csv.DictReader(io.StringIO(text))]
        except csv.Error as exc:
            ctx.skip("file cannot be read", lost=0, detail=f"not CSV: {exc}")
            return None
    if not isinstance(rows, list):
        ctx.skip("file cannot be read", lost=0, detail="expected an array of objects, or a CSV with a header row")
        return None
    kind = _kind_of(rows, hint)
    wide = 0
    for index, raw in enumerate(rows):
        loc = {"row": index + 1}  # the key below is built from ``index``, from 0: it must not change
        out.extra = None
        try:
            if not isinstance(raw, dict):
                raise ValueError("not an object")
            extra = raw.pop(None, None)  # the cells of a CSV row past its header (the reader keeps them under None)
            if extra:
                wide += 1
                out.extra = list(extra)
            row = _normal(raw)
            ident = f"{index}:{_digest(json.dumps(raw, sort_keys=True, default=str))}"
            if kind == "bookmarks":
                url = _s(_pick(row, _ALIASES["url"]))
                if not url:
                    raise LookupError("no URL")
                name = _s(_pick(row, _ALIASES["name"])) or "(unnamed)"
                folder = _s(_pick(row, _ALIASES["folder"]))
                out.bookmark(
                    _digest(folder, name, url),
                    any_to_ms(_pick(row, _ALIASES["dateAdded"])),
                    name,
                    url,
                    folder or None,
                    loc,
                )
            elif kind == "shortcuts":
                url = _s(_pick(row, _ALIASES["url"]))
                if not url:
                    raise LookupError("no URL")
                out.shortcut(
                    ident,
                    any_to_ms(_pick(row, _ALIASES["lastAccessTime"])),
                    _s(_pick(row, _ALIASES["text"])),
                    url,
                    _s(_pick(row, _ALIASES["contents"])),
                    _count(_pick(row, _ALIASES["hits"])),
                    loc,
                )
            elif kind == "downloads":
                name = _s(_pick(row, _ALIASES["fileName"]))
                url = _s(_pick(row, _ALIASES["downloadUrl"]))
                if not name and not url:
                    raise LookupError("no file name and no URL")
                out.download(
                    ident,
                    loc,
                    fileName=_file_name(name) or name or _file_name(url) or "(unknown)",
                    targetPath=name,
                    url=url,
                    referrer=_s(_pick(row, _ALIASES["referrer"])) or url,
                    startTime=any_to_ms(_pick(row, _ALIASES["startTime"])),
                    endTime=None,
                    totalBytes=_count(_pick(row, _ALIASES["totalBytes"])),
                    receivedBytes=0,
                    mimeType="",
                    state=1,
                )
            else:
                url = _s(_pick(row, _ALIASES["url"]))
                if not url:
                    raise LookupError("no URL")
                out.visit(
                    ident,
                    any_to_ms(_pick(row, _ALIASES["visitTime"])),
                    url,
                    _s(_pick(row, _ALIASES["title"])),
                    _count(_pick(row, _ALIASES["visitCount"])),
                    None,
                    None,
                    None,
                    False,
                    loc,
                )
        except LookupError as exc:
            ctx.skip("row without what it is about", lost=1, detail=f"row {index + 1}: {exc}")
        except Exception as exc:  # noqa: BLE001
            ctx.skip("row cannot be read", lost=1, detail=f"row {index + 1}: {exc!r}"[:300])
    out.extra = None
    if wide:
        ctx.note("row with more cells than the header", count=wide, detail="the extra cells are in its data, as extra")
    return len(rows)


# --------------------------------------------------------------------------- #
# What a file is, and the parse                                               #
# --------------------------------------------------------------------------- #
def _base(name: str) -> str:
    return os.path.basename(name.replace("\\", "/")).lower()


def _by_tables(path: str) -> str | None:
    conn = sqlite_safe.open_ro(path)
    try:
        names = sqlite_safe.tables(conn)
    finally:
        conn.close()
    if {"urls", "visits"} <= names:
        return "chrome.history"
    if "moz_places" in names:
        return "firefox.places"
    if "history_items" in names:
        return "safari.history"
    if "omni_box_shortcuts" in names:
        return "chrome.shortcuts"
    return None


def sniff(path: str, name: str, head: bytes) -> str | None:
    try:
        base = _base(name)
        if head.startswith(sqlite_safe.SQLITE_MAGIC):
            by_name = {
                "history": "chrome.history",
                "shortcuts": "chrome.shortcuts",
                "places.sqlite": "firefox.places",
                "history.db": "safari.history",
            }
            return by_name.get(base) or _by_tables(path)
        if base in ("bookmarks", "bookmarks.bak") and b'"roots"' in head:
            return "chrome.bookmarks"
        if base in ("downloads.plist", "bookmarks.plist") and _looks_like_plist(head):
            return "safari." + base.split(".")[0]
    except Exception:  # noqa: BLE001 - a file that cannot even be looked at is not this parser's
        return None
    return None


def _looks_like_plist(head: bytes) -> bool:
    start = head.removeprefix(b"\xef\xbb\xbf").lstrip()[:512]
    return (
        head.startswith(b"bplist00")
        or start.startswith(b"<plist")
        or (start.startswith(b"<?xml") and b"<plist" in start)
    )


def _detect(path: str) -> str | None:
    """The source of a file that came with none and whose name is not known: by its content alone."""
    with open(path, "rb") as handle:
        head = handle.read(4096)
    found = sniff(path, "", head)
    if found:
        return found
    if b'"roots"' in head:
        return "chrome.bookmarks"
    if _looks_like_plist(head) and os.path.getsize(path) <= MAX_FILE:
        try:
            with open(path, "rb") as handle:
                plist = plistlib.loads(handle.read())
        except Exception:  # noqa: BLE001
            return None
        if isinstance(plist, dict) and "DownloadHistory" in plist:
            return "safari.downloads"
        if isinstance(plist, dict) and "Children" in plist:
            return "safari.bookmarks"
    return None


def parse(path: str, ctx, source: str) -> None:
    if source not in SOURCES:
        source = _detect(path) or ""
        if not source:
            raise ValueError("The browser parser cannot tell what this file is: give its source")
    browser, what = source.split(".")
    ctx.source(
        NAME,
        VERSION,
        KIND,
        source,
        host=str(ctx.params.get("host") or ""),
        username=str(ctx.params.get("username") or ""),
    )
    out = _Emit(ctx, browser)
    if what in ("json", "csv"):
        in_file = _text_rows(path, ctx, out, what)
    elif what == "bookmarks" and browser != "safari":
        in_file = _chrome_bookmarks(path, ctx, out)
    elif browser == "safari" and what in ("downloads", "bookmarks"):
        in_file = _plist(path, ctx, out, what)
    else:
        in_file = _sqlite(path, ctx, out, source)
    out.notes()
    ctx.end(in_file=in_file)


# --------------------------------------------------------------------------- #
# The view of a record                                                        #
# --------------------------------------------------------------------------- #
def _whole_for_view(path: str) -> bytes:
    if os.path.getsize(path) > MAX_FILE:
        raise ViewError(f"The file is larger than {MAX_FILE} bytes: it is not read for a view")
    with open(path, "rb") as handle:
        return handle.read(MAX_FILE + 1)


def _bookmark_at(path: str, source: str, wanted: str, index: int) -> dict[str, Any]:
    """The bookmark at ``index`` among those of the folder ``wanted``, found by the walk of the parse (the same
    folder names, the same order, every bookmark of the folder counted whether it has a URL or not)."""
    found: list[dict[str, Any]] = []
    data = _whole_for_view(path)
    if source.startswith("safari"):
        try:
            plist = plistlib.loads(data)
        except Exception as exc:  # noqa: BLE001 - plistlib raises several unrelated types on bad input
            raise ViewError(f"The file is not a property list: {type(exc).__name__}") from None

        def walk_safari(node: Any, folder: str, depth: int) -> None:
            if not isinstance(node, dict) or depth > MAX_DEPTH or found:
                return
            kind = node.get("WebBookmarkType")
            if kind == "WebBookmarkTypeLeaf":
                if folder == wanted:
                    seen[0] += 1
                    if seen[0] == index + 1:
                        found.append(node)
            elif kind == "WebBookmarkTypeList" and isinstance(node.get("Children"), list):
                title = _s(node.get("Title"))
                label = SAFARI_ROOT_LABELS.get(title, title)
                inner = (f"{folder} > {label}" if folder else label) if label else folder
                for child in node["Children"]:
                    walk_safari(child, inner, depth + 1)

        seen = [0]
        for child in (plist.get("Children") or []) if isinstance(plist, dict) else []:
            walk_safari(child, "", 0)
        if not found:
            raise ViewError(f"The file holds no bookmark {index} in the folder {wanted or '(top level)'}")
        return found[0]
    try:
        parsed = json.loads(data.decode("utf-8-sig", "replace"))
    except (ValueError, RecursionError) as exc:
        raise ViewError(f"The file is not JSON: {str(exc)[:200]}") from None
    roots = parsed.get("roots") if isinstance(parsed, dict) else None
    if not isinstance(roots, dict):
        raise ViewError('The file is not a Chromium Bookmarks file (no "roots")')

    def walk_chrome(node: Any, folder: str, depth: int) -> None:
        if not isinstance(node, dict) or depth > MAX_DEPTH or found:
            return
        if node.get("type") == "url":
            if folder == wanted:
                seen[0] += 1
                if seen[0] == index + 1:
                    found.append(node)
        elif isinstance(node.get("children"), list):
            name = _s(node.get("name"))
            inner = (f"{folder} > {name}" if folder else name) if name else folder
            for child in node["children"]:
                walk_chrome(child, inner, depth + 1)

    seen = [0]
    for root_key, root in roots.items():
        if isinstance(root, dict):
            label = CHROME_ROOT_LABELS.get(root_key, _s(root.get("name")) or root_key)
            for child in root.get("children") or []:
                walk_chrome(child, label, 0)
    if not found:
        raise ViewError(f"The file holds no bookmark {index} in the folder {wanted or '(top level)'}")
    return found[0]


def _rows_of_json(data: bytes) -> list[Any]:
    try:
        parsed = json.loads(data.decode("utf-8-sig", "replace"))
    except (ValueError, RecursionError) as exc:
        raise ViewError(f"The file is not JSON: {str(exc)[:200]}") from None
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        for name in _CONTAINERS:
            if isinstance(parsed.get(name), list):
                return parsed[name]
    raise ViewError("The file holds no array of rows")


def _csv_row(text: str, number: int) -> dict[str, Any]:
    """The row ``number`` (from 1, the header not counted) of a CSV, as the parse reads it, with its raw lines."""
    seen: list[str] = []

    def tap():
        for line in io.StringIO(text):
            seen.append(line)
            yield line

    previous = csv.field_size_limit(MAX_FILE)
    row: dict[Any, Any] | None = None
    try:
        reader = csv.DictReader(tap())
        header = reader.fieldnames  # reads the header: the lines it took are not the row's
        seen.clear()
        total = 0
        for total, found in enumerate(reader, start=1):
            if total == number:
                row = found
                break
            seen.clear()
    except csv.Error as exc:
        raise ViewError(f"The CSV cannot be read up to the row {number}: {exc}") from None
    finally:
        csv.field_size_limit(previous)
    if row is None:
        raise ViewError(f"The file holds no row {number} (it holds {total if header else 0})")
    lines = list(seen)
    while lines and not lines[0].strip():
        lines.pop(0)
    first = reader.line_num - len(lines) + 1
    rows = [[str(name), "" if value is None else str(value)] for name, value in row.items() if name is not None]
    if None in row:
        rows.append(["extra", ", ".join(map(str, row[None]))])
    return {
        "kind": "fields",
        "title": f"Row {number} of the CSV, with its header",
        "where": {"row": number, "line": first},
        "rows": rows,
        "text": "".join(lines).rstrip("\r\n"),
        "first": first,
    }


def view(path: str, source: str, loc: dict) -> dict:
    """The row or the bookmark the record came from, by what its locator names (the module docstring says
    which): ``{"table", "rowid"}`` a row of a database (a visit with the row of its URL); ``{"row"}`` a row of a
    JSON or CSV export (from 1); ``{"index"}`` an entry of a Safari download list; ``{"path", "index"}`` a
    bookmark of a Chromium or Safari file."""
    if "table" in loc:
        return viewing.sqlite_row(path, str(loc.get("table") or ""), loc.get("rowid"))
    if "row" in loc:
        number = viewing.loc_int(loc, "row")
        if number < 1:
            raise ViewError("The rows are counted from 1: there is no row 0")
        if source.endswith(".csv"):
            return _csv_row(_whole_for_view(path).decode("utf-8-sig", "replace"), number)
        rows = _rows_of_json(_whole_for_view(path))
        if number > len(rows):
            raise ViewError(f"The file holds no row {number} (it holds {len(rows)})")
        row = rows[number - 1]
        where = {"row": number}
        if not isinstance(row, dict):
            return {"kind": "json", "title": f"Row {number} of the array", "where": where, "text": viewing.pretty(row)}
        return {"kind": "fields", "title": f"Row {number} of the array", "where": where, "rows": viewing.flatten(row)}
    if "path" in loc:
        folder = loc.get("path")
        if not isinstance(folder, str):
            raise BadLocator("The locator of the record has no folder")
        index = viewing.loc_int(loc, "index")
        node = _bookmark_at(path, source, folder, index)
        shown = folder or "(top level)"
        return {
            "kind": "fields",
            "title": f"Bookmark {index} of the folder {shown}",
            "where": {"path": folder, "index": index},
            "rows": [["folder", shown], *viewing.flatten(node)],
        }
    if "index" in loc:
        index = viewing.loc_int(loc, "index")
        try:
            plist = plistlib.loads(_whole_for_view(path))
        except Exception as exc:  # noqa: BLE001 - plistlib raises several unrelated types on bad input
            raise ViewError(f"The file is not a property list: {type(exc).__name__}") from None
        entries = plist.get("DownloadHistory") if isinstance(plist, dict) else None
        if not isinstance(entries, list) or index >= len(entries):
            raise ViewError(f"The file holds no download {index} in DownloadHistory")
        return {
            "kind": "fields",
            "title": f"Download {index} of DownloadHistory",
            "where": {"index": index},
            "rows": viewing.flatten(entries[index]),
        }
    raise BadLocator("The locator of the record names no table, row, index or folder")
