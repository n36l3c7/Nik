"""Browser artifact parser — port of ``sqliteParser.js`` + ``fileParsers.js``.

Produces the same normalized shapes the frontend stores under
``data.browser.browsers[id]``: ``history``, ``downloads``, ``bookmarks``,
``shortcuts``.
"""

from __future__ import annotations

import json
import plistlib
from datetime import datetime, timezone

from .common import (
    as_count,
    as_text,
    file_name_from_path,
    gen_id,
    has_tables,
    is_sqlite,
    normalize_row,
    open_sqlite,
    parse_csv,
    pick,
    query_rows,
)
from .timeutil import any_to_ms, firefox_to_ms, mac_to_ms, webkit_to_ms

CHROMIUM_REDIRECT_MASK = 0x40000000 | 0x80000000
FIREFOX_REDIRECT_TYPES = {5, 6}

CHROME_ROOT_LABELS = {
    "bookmark_bar": "Bookmarks bar",
    "other": "Other bookmarks",
    "synced": "Synced bookmarks",
}
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

HISTORY_ALIASES = {
    "url": ["url"],
    "title": ["title", "titolo"],
    "visitCount": ["visit_count", "visitcount", "visits"],
    "visitTime": ["visit_time", "visittime", "data_leggibile", "date", "timestamp", "data"],
}
BOOKMARK_ALIASES = {
    "name": ["name", "nome", "title", "titolo"],
    "url": ["url"],
    "folder": ["folder", "cartella"],
    "dateAdded": ["date_added", "dateadded", "data", "date", "timestamp"],
}
SHORTCUT_ALIASES = {
    "text": ["text", "testo"],
    "url": ["url"],
    "title": ["contents", "title", "titolo"],
    "lastAccessTime": ["last_access_time", "lastaccesstime"],
    "hits": ["number_of_hits", "hits"],
}
DOWNLOAD_ALIASES = {
    "fileName": ["file_name", "filename", "nome_file", "name", "nome", "target_path", "file"],
    "url": ["url", "source", "source_url", "from", "download_url"],
    "referrer": ["referrer", "referer", "tab_url", "site", "sito"],
    "startTime": ["start_time", "starttime", "date", "data", "timestamp", "downloaded_at"],
    "totalBytes": ["total_bytes", "size", "bytes", "dimensione"],
}


# --------------------------------------------------------------------------- #
# SQLite parsers                                                              #
# --------------------------------------------------------------------------- #
def parse_chromium_history(conn):
    rows = query_rows(
        conn,
        """SELECT u.url AS url, u.title AS title, u.visit_count AS visit_count,
                  v.id AS visit_id, v.from_visit AS from_visit,
                  v.transition AS transition, v.visit_time AS visit_time
           FROM urls AS u INNER JOIN visits AS v ON u.id = v.url
           ORDER BY v.visit_time DESC""",
    )
    out = []
    for r in rows:
        transition = int(r.get("transition") or 0)
        out.append(
            {
                "id": gen_id(),
                "url": r.get("url") or "",
                "title": r.get("title") or "",
                "visitCount": r.get("visit_count") or 0,
                "visitTime": webkit_to_ms(r.get("visit_time")),
                "visitId": r.get("visit_id"),
                "fromVisitId": r.get("from_visit") or None,
                "isRedirect": (transition & CHROMIUM_REDIRECT_MASK) != 0,
            }
        )
    return out


def parse_chromium_downloads(conn):
    if not has_tables(conn, ["downloads"]):
        return []
    chain = {}
    for r in query_rows(conn, "SELECT id, url, chain_index FROM downloads_url_chain ORDER BY id, chain_index"):
        chain[r["id"]] = r["url"]
    out = []
    for r in query_rows(conn, "SELECT * FROM downloads ORDER BY start_time DESC"):
        target = r.get("target_path") or r.get("current_path") or ""
        file_url = chain.get(r.get("id")) or r.get("tab_url") or ""
        site = r.get("referrer") or r.get("tab_url") or r.get("site_url") or file_url or ""
        out.append(
            {
                "id": gen_id(),
                "fileName": file_name_from_path(target) or file_name_from_path(file_url) or "(unknown)",
                "targetPath": target,
                "url": file_url,
                "referrer": site,
                "startTime": webkit_to_ms(r.get("start_time")),
                "endTime": webkit_to_ms(r.get("end_time")),
                "totalBytes": as_count(r.get("total_bytes")),
                "receivedBytes": as_count(r.get("received_bytes")),
                "mimeType": r.get("mime_type") or "",
                "state": int(r.get("state") or 0),
            }
        )
    return out


def parse_chromium_shortcuts(conn):
    if not has_tables(conn, ["omni_box_shortcuts"]):
        raise ValueError("Not a Chrome Shortcuts file (missing omni_box_shortcuts).")
    rows = query_rows(
        conn,
        """SELECT text, url, contents, last_access_time, number_of_hits
           FROM omni_box_shortcuts ORDER BY last_access_time DESC""",
    )
    return [
        {
            "id": gen_id(),
            "text": r.get("text") or "",
            "url": r.get("url") or "",
            "title": r.get("contents") or "",
            "lastAccessTime": webkit_to_ms(r.get("last_access_time")),
            "hits": r.get("number_of_hits") or 0,
        }
        for r in rows
    ]


def parse_firefox_history(conn):
    rows = query_rows(
        conn,
        """SELECT p.url AS url, p.title AS title, p.visit_count AS visit_count,
                  v.id AS visit_id, v.from_visit AS from_visit,
                  v.visit_type AS visit_type, v.visit_date AS visit_date
           FROM moz_places AS p INNER JOIN moz_historyvisits AS v ON v.place_id = p.id
           ORDER BY v.visit_date DESC""",
    )
    return [
        {
            "id": gen_id(),
            "url": r.get("url") or "",
            "title": r.get("title") or "",
            "visitCount": r.get("visit_count") or 0,
            "visitTime": firefox_to_ms(r.get("visit_date")),
            "visitId": r.get("visit_id"),
            "fromVisitId": r.get("from_visit") or None,
            "isRedirect": int(r.get("visit_type") or 0) in FIREFOX_REDIRECT_TYPES,
        }
        for r in rows
    ]


def parse_firefox_bookmarks(conn):
    if not has_tables(conn, ["moz_bookmarks", "moz_places"]):
        return []
    nodes = {r["id"]: r for r in query_rows(conn, "SELECT id, parent, title, type, guid FROM moz_bookmarks")}

    def folder_path(parent_id):
        parts, current, guard = [], nodes.get(parent_id), 0
        while current and guard < 50:
            label = FIREFOX_ROOT_LABELS.get(current.get("guid"), current.get("title") or "")
            if label:
                parts.insert(0, label)
            if not current.get("parent") or current["parent"] == current["id"]:
                break
            current = nodes.get(current["parent"])
            guard += 1
        return " > ".join(parts) or None

    def under_tags(parent_id):
        current, guard = nodes.get(parent_id), 0
        while current and guard < 50:
            if current.get("guid") == "tags________":
                return True
            if not current.get("parent") or current["parent"] == current["id"]:
                break
            current = nodes.get(current["parent"])
            guard += 1
        return False

    rows = query_rows(
        conn,
        """SELECT b.id AS id, b.title AS title, b.dateAdded AS date_added,
                  b.parent AS parent, p.url AS url
           FROM moz_bookmarks AS b INNER JOIN moz_places AS p ON p.id = b.fk
           WHERE b.type = 1 ORDER BY b.dateAdded DESC""",
    )
    out = []
    for r in rows:
        if under_tags(r.get("parent")):
            continue
        out.append(
            {
                "id": gen_id(),
                "name": r.get("title") or "(unnamed)",
                "url": r.get("url") or "",
                "folder": folder_path(r.get("parent")),
                "dateAdded": firefox_to_ms(r.get("date_added")),
            }
        )
    return out


def parse_firefox_downloads(conn):
    if not has_tables(conn, ["moz_annos", "moz_anno_attributes", "moz_places"]):
        return []
    rows = query_rows(
        conn,
        """SELECT p.url AS source_url, dest.content AS dest, dest.dateAdded AS date_added,
                  meta.content AS meta_json
           FROM moz_annos AS dest
           JOIN moz_places AS p ON p.id = dest.place_id
           JOIN moz_anno_attributes AS a_dest ON a_dest.id = dest.anno_attribute_id
             AND a_dest.name = 'downloads/destinationFileURI'
           LEFT JOIN moz_anno_attributes AS a_meta ON a_meta.name = 'downloads/metaData'
           LEFT JOIN moz_annos AS meta ON meta.place_id = dest.place_id
             AND meta.anno_attribute_id = a_meta.id
           ORDER BY dest.dateAdded DESC""",
    )
    out = []
    for r in rows:
        file_size, end_time, state = 0, None, 1
        if r.get("meta_json"):
            try:
                meta = json.loads(r["meta_json"])
                file_size = as_count(meta.get("fileSize"))
                end_time = int(meta["endTime"]) if meta.get("endTime") else None
                if isinstance(meta.get("state"), int):
                    state = meta["state"]
            except (ValueError, TypeError):
                pass
        out.append(
            {
                "id": gen_id(),
                "fileName": file_name_from_path(r.get("dest")) or "(unknown)",
                "targetPath": r.get("dest") or "",
                "url": r.get("source_url") or "",
                "referrer": r.get("source_url") or "",
                "startTime": firefox_to_ms(r.get("date_added")),
                "endTime": end_time,
                "totalBytes": file_size,
                "receivedBytes": file_size,
                "mimeType": "",
                "state": state,
            }
        )
    return out


def parse_safari_history(conn):
    """History.db: visits (Mac absolute time) joined with their history items."""
    rows = query_rows(
        conn,
        """SELECT i.url AS url, v.title AS title, i.visit_count AS visit_count,
                  v.id AS visit_id, v.redirect_source AS redirect_source,
                  v.visit_time AS visit_time
           FROM history_items AS i INNER JOIN history_visits AS v ON v.history_item = i.id
           ORDER BY v.visit_time DESC""",
    )
    return [
        {
            "id": gen_id(),
            "url": r.get("url") or "",
            "title": r.get("title") or "",
            "visitCount": r.get("visit_count") or 0,
            "visitTime": mac_to_ms(r.get("visit_time")),
            "visitId": r.get("visit_id"),
            "fromVisitId": r.get("redirect_source") or None,
            "isRedirect": r.get("redirect_source") is not None,
        }
        for r in rows
    ]


def parse_sqlite_source(data: bytes, engine: str, source_key: str) -> dict:
    with open_sqlite(data) as conn:
        if engine == "safari":
            if source_key != "history":
                raise ValueError("Safari downloads and bookmarks are .plist files, not SQLite.")
            if not has_tables(conn, ["history_items", "history_visits"]):
                raise ValueError("Not a Safari History.db (missing history_items/history_visits).")
            return {"history": parse_safari_history(conn)}
        if engine == "firefox":
            if not has_tables(conn, ["moz_places"]):
                raise ValueError("Not a Firefox places.sqlite (missing moz_places).")
            return {
                "history": parse_firefox_history(conn),
                "bookmarks": parse_firefox_bookmarks(conn),
                "downloads": parse_firefox_downloads(conn),
            }
        if source_key == "shortcuts":
            return {"shortcuts": parse_chromium_shortcuts(conn)}
        if not has_tables(conn, ["urls", "visits"]):
            raise ValueError("Not a Chrome History file (missing urls/visits).")
        return {"history": parse_chromium_history(conn), "downloads": parse_chromium_downloads(conn)}


# --------------------------------------------------------------------------- #
# Safari property lists (Downloads.plist / Bookmarks.plist)                   #
# --------------------------------------------------------------------------- #
def _plist_date_ms(value):
    """Unix ms of a plist date (plistlib returns naive UTC datetimes)."""
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return round(value.timestamp() * 1000)


def map_safari_downloads(plist):
    entries = plist.get("DownloadHistory") if isinstance(plist, dict) else None
    if not isinstance(entries, list):
        raise ValueError('Not a Safari Downloads.plist (missing "DownloadHistory").')
    out = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        url = as_text(entry.get("DownloadEntryURL"))
        target = as_text(entry.get("DownloadEntryPath"))
        end_time = _plist_date_ms(entry.get("DownloadEntryDateFinishedKey"))
        start_time = _plist_date_ms(entry.get("DownloadEntryDateAddedKey"))
        out.append(
            {
                "id": gen_id(),
                "fileName": file_name_from_path(target) or file_name_from_path(url) or "(unknown)",
                "targetPath": target,
                "url": url,
                "referrer": url,
                "startTime": start_time if start_time is not None else end_time,
                "endTime": end_time,
                "totalBytes": as_count(entry.get("DownloadEntryProgressTotalToLoad")),
                "receivedBytes": as_count(entry.get("DownloadEntryProgressBytesSoFar")),
                "mimeType": "",
                "state": 1 if end_time is not None else 4,
            }
        )
    return out


def map_safari_bookmarks(plist):
    if not isinstance(plist, dict) or not isinstance(plist.get("Children"), list):
        raise ValueError("Not a Safari Bookmarks.plist (missing the root bookmark list).")
    out = []

    def walk(node, folder_path, depth):
        if not isinstance(node, dict) or depth > 100:
            return
        kind = node.get("WebBookmarkType")
        if kind == "WebBookmarkTypeLeaf":
            url = as_text(node.get("URLString"))
            if not url:
                return
            uri = node.get("URIDictionary") if isinstance(node.get("URIDictionary"), dict) else {}
            reading = node.get("ReadingList") if isinstance(node.get("ReadingList"), dict) else {}
            out.append(
                {
                    "id": gen_id(),
                    "name": as_text(uri.get("title")) or as_text(node.get("Title")) or "(unnamed)",
                    "url": url,
                    "folder": folder_path or None,
                    "dateAdded": _plist_date_ms(reading.get("DateAdded")),
                }
            )
            return
        if kind != "WebBookmarkTypeList" or not isinstance(node.get("Children"), list):
            return
        title = as_text(node.get("Title"))
        label = SAFARI_ROOT_LABELS.get(title, title)
        path = (f"{folder_path} > {label}" if folder_path else label) if label else folder_path
        for child in node["Children"]:
            walk(child, path, depth + 1)

    for child in plist["Children"]:
        walk(child, "", 0)
    return out


def _is_plist(data: bytes) -> bool:
    head = data.removeprefix(b"\xef\xbb\xbf").lstrip()[:512]
    return (
        data.startswith(b"bplist00") or head.startswith(b"<plist") or (head.startswith(b"<?xml") and b"<plist" in head)
    )


def parse_safari_plist(data: bytes, source_key: str) -> dict:
    try:
        plist = plistlib.loads(data)
    except Exception as exc:  # plistlib raises several unrelated types on bad input
        raise ValueError("Malformed property list.") from exc
    if source_key == "downloads":
        return {"downloads": map_safari_downloads(plist)}
    if source_key == "bookmarks":
        return {"bookmarks": map_safari_bookmarks(plist)}
    raise ValueError("Safari history is a SQLite database (History.db), not a property list.")


# --------------------------------------------------------------------------- #
# Text (JSON / CSV) mappers                                                   #
# --------------------------------------------------------------------------- #
def map_history_rows(rows):
    out = []
    for raw in rows:
        row = normalize_row(raw)
        url = as_text(pick(row, HISTORY_ALIASES["url"]))
        if not url:
            continue
        out.append(
            {
                "id": gen_id(),
                "url": url,
                "title": as_text(pick(row, HISTORY_ALIASES["title"])),
                "visitCount": as_count(pick(row, HISTORY_ALIASES["visitCount"])),
                "visitTime": any_to_ms(pick(row, HISTORY_ALIASES["visitTime"])),
                "visitId": None,
                "fromVisitId": None,
                "isRedirect": False,
            }
        )
    return out


def _walk_bookmark_node(node, folder_path, out):
    if not isinstance(node, dict):
        return
    if node.get("type") == "url" and node.get("url"):
        out.append(
            {
                "id": gen_id(),
                "name": as_text(node.get("name")) or "(unnamed)",
                "url": node["url"],
                "folder": folder_path or None,
                "dateAdded": webkit_to_ms(node.get("date_added")),
            }
        )
        return
    if isinstance(node.get("children"), list):
        name = as_text(node.get("name"))
        path = (f"{folder_path} > {name}" if folder_path else name) if name else folder_path
        for child in node["children"]:
            _walk_bookmark_node(child, path, out)


def map_chrome_bookmarks(parsed):
    out = []
    for root_key, root in (parsed.get("roots") or {}).items():
        if not isinstance(root, dict):
            continue
        label = CHROME_ROOT_LABELS.get(root_key, as_text(root.get("name")) or root_key)
        for child in root.get("children") or []:
            _walk_bookmark_node(child, label, out)
    return out


def map_bookmark_rows(rows):
    out = []
    for raw in rows:
        row = normalize_row(raw)
        url = as_text(pick(row, BOOKMARK_ALIASES["url"]))
        if not url:
            continue
        folder = as_text(pick(row, BOOKMARK_ALIASES["folder"]))
        out.append(
            {
                "id": gen_id(),
                "name": as_text(pick(row, BOOKMARK_ALIASES["name"])) or "(unnamed)",
                "url": url,
                "folder": folder or None,
                "dateAdded": any_to_ms(pick(row, BOOKMARK_ALIASES["dateAdded"])),
            }
        )
    return out


def map_shortcut_rows(rows):
    out = []
    for raw in rows:
        row = normalize_row(raw)
        url = as_text(pick(row, SHORTCUT_ALIASES["url"]))
        if not url:
            continue
        out.append(
            {
                "id": gen_id(),
                "text": as_text(pick(row, SHORTCUT_ALIASES["text"])),
                "url": url,
                "title": as_text(pick(row, SHORTCUT_ALIASES["title"])),
                "lastAccessTime": any_to_ms(pick(row, SHORTCUT_ALIASES["lastAccessTime"])),
                "hits": as_count(pick(row, SHORTCUT_ALIASES["hits"])),
            }
        )
    return out


def map_download_rows(rows):
    out = []
    for raw in rows:
        row = normalize_row(raw)
        raw_name = as_text(pick(row, DOWNLOAD_ALIASES["fileName"]))
        url = as_text(pick(row, DOWNLOAD_ALIASES["url"]))
        referrer = as_text(pick(row, DOWNLOAD_ALIASES["referrer"]))
        if not raw_name and not url:
            continue
        out.append(
            {
                "id": gen_id(),
                "fileName": file_name_from_path(raw_name) or raw_name or file_name_from_path(url) or "(unknown)",
                "targetPath": raw_name,
                "url": url,
                "referrer": referrer or url,
                "startTime": any_to_ms(pick(row, DOWNLOAD_ALIASES["startTime"])),
                "endTime": None,
                "totalBytes": as_count(pick(row, DOWNLOAD_ALIASES["totalBytes"])),
                "receivedBytes": 0,
                "mimeType": "",
                "state": 1,
            }
        )
    return out


def _extract_rows(parsed, container_keys):
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        for key in container_keys:
            if isinstance(parsed.get(key), list):
                return parsed[key]
    return None


def _map_text(produces, parsed_json, csv_rows):
    kind = (produces or ["history"])[0]
    if "bookmarks" in (produces or []) and isinstance(parsed_json, dict) and isinstance(parsed_json.get("roots"), dict):
        return {"bookmarks": map_chrome_bookmarks(parsed_json)}
    rows = (
        csv_rows
        if csv_rows is not None
        else _extract_rows(
            parsed_json,
            ["history", "bookmarks", "shortcuts", "downloads", "entries", "rows", "data", "items", "records"],
        )
    )
    if not isinstance(rows, list):
        raise ValueError("Unrecognized JSON: expected an array of objects.")
    if kind == "bookmarks":
        return {"bookmarks": map_bookmark_rows(rows)}
    if kind == "shortcuts":
        return {"shortcuts": map_shortcut_rows(rows)}
    if kind == "downloads":
        return {"downloads": map_download_rows(rows)}
    return {"history": map_history_rows(rows)}


def parse_browser_source(data: bytes, engine: str, source_key: str, produces):
    """Parse an uploaded browser file → ({produced}, format)."""
    if not data:
        raise ValueError("The file is empty.")
    if is_sqlite(data):
        if engine == "chromium" and source_key == "bookmarks":
            raise ValueError("Chrome Bookmarks is a JSON file, not SQLite.")
        produced = parse_sqlite_source(data, engine, source_key)
        if sum(len(v) for v in produced.values()) == 0:
            raise ValueError("The database has no entries for this source.")
        return produced, "sqlite"

    if _is_plist(data):
        if engine != "safari":
            raise ValueError("This is a property list (.plist), not a file for this browser.")
        produced = parse_safari_plist(data, source_key)
        if sum(len(v) for v in produced.values()) == 0:
            raise ValueError("The property list has no entries.")
        return produced, "plist"

    text = data.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
        return _map_text(produces, parsed, None), "json"
    except json.JSONDecodeError:
        rows = parse_csv(text)
        if not rows:
            raise ValueError("Unrecognized file: not SQLite, JSON, or CSV.") from None
        return _map_text(produces, None, rows), "csv"
