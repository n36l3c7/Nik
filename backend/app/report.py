"""Incident report: a printable HTML document, and the same as PDF.

``build_html`` turns an incident (plus what the server knows about it: its
indicators, its samples' YARA and capa results, the organisation set in
Settings) into one self-contained HTML page styled for print — A4 pages, the
TLP label and page numbers in the margins. ``to_pdf`` renders it with
WeasyPrint. The browser shows the HTML as a preview and downloads the PDF;
API clients get either from ``POST /api/incidents/{id}/report``.

Sections (each can be left out): executive summary and key facts, flagged
events, MITRE ATT&CK techniques, indicators of compromise, malware samples,
event-log coverage, analyst notes, evidence appendix (every imported file
with its SHA-256 when known). Labels in English or Italian.
"""

from __future__ import annotations

import html
import logging
import re
from datetime import datetime, timezone
from typing import Any

# WeasyPrint and fontTools log every layout step at INFO: keep the api log readable.
for _noisy in ("weasyprint", "weasyprint.progress", "fontTools"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

SECTIONS = (
    "summary",
    "timeline",
    "attack",
    "iocs",
    "samples",
    "mails",
    "network",
    "eventlogs",
    "notes",
    "evidence",
)
TLP_LEVELS = ("clear", "green", "amber", "amber+strict", "red")
LANGS = ("en", "it")
MAX_IOCS = 500

# TLP 2.0 colours (FIRST): the label is printed in colour on black.
_TLP_COLOURS = {"clear": "#ffffff", "green": "#33ff00", "amber": "#ffc000", "amber+strict": "#ffc000", "red": "#ff2b2b"}

# Names of the techniques the built-in rules and YARA rules point to (capa
# reports carry their own names).
ATTACK_NAMES: dict[str, tuple[str, str]] = {
    "T1003": ("Credential Access", "OS Credential Dumping"),
    "T1021.001": ("Lateral Movement", "Remote Services: Remote Desktop Protocol"),
    "T1027": ("Defense Evasion", "Obfuscated Files or Information"),
    "T1027.002": ("Defense Evasion", "Obfuscated Files or Information: Software Packing"),
    "T1036": ("Defense Evasion", "Masquerading"),
    "T1036.007": ("Defense Evasion", "Masquerading: Double File Extension"),
    "T1046": ("Discovery", "Network Service Discovery"),
    "T1048": ("Exfiltration", "Exfiltration Over Alternative Protocol"),
    "T1053": ("Persistence", "Scheduled Task/Job"),
    "T1053.005": ("Persistence", "Scheduled Task/Job: Scheduled Task"),
    "T1055": ("Defense Evasion", "Process Injection"),
    "T1059": ("Execution", "Command and Scripting Interpreter"),
    "T1059.001": ("Execution", "Command and Scripting Interpreter: PowerShell"),
    "T1059.004": ("Execution", "Command and Scripting Interpreter: Unix Shell"),
    "T1059.005": ("Execution", "Command and Scripting Interpreter: Visual Basic"),
    "T1070.001": ("Defense Evasion", "Indicator Removal: Clear Windows Event Logs"),
    "T1070.003": ("Defense Evasion", "Indicator Removal: Clear Command History"),
    "T1071.001": ("Command and Control", "Application Layer Protocol: Web Protocols"),
    "T1078": ("Initial Access", "Valid Accounts"),
    "T1082": ("Discovery", "System Information Discovery"),
    "T1098": ("Persistence", "Account Manipulation"),
    "T1105": ("Command and Control", "Ingress Tool Transfer"),
    "T1110": ("Credential Access", "Brute Force"),
    "T1136.001": ("Persistence", "Create Account: Local Account"),
    "T1140": ("Defense Evasion", "Deobfuscate/Decode Files or Information"),
    "T1204.002": ("Execution", "User Execution: Malicious File"),
    "T1218": ("Defense Evasion", "System Binary Proxy Execution"),
    "T1485": ("Impact", "Data Destruction"),
    "T1486": ("Impact", "Data Encrypted for Impact"),
    "T1490": ("Impact", "Inhibit System Recovery"),
    "T1543": ("Persistence", "Create or Modify System Process"),
    "T1543.003": ("Persistence", "Create or Modify System Process: Windows Service"),
    "T1547.001": ("Persistence", "Boot or Logon Autostart Execution: Registry Run Keys"),
    "T1548": ("Privilege Escalation", "Abuse Elevation Control Mechanism"),
    "T1562": ("Defense Evasion", "Impair Defenses"),
    "T1562.001": ("Defense Evasion", "Impair Defenses: Disable or Modify Tools"),
    "T1562.002": ("Defense Evasion", "Impair Defenses: Disable Windows Event Logging"),
    "T1569.002": ("Execution", "System Services: Service Execution"),
    "T1622": ("Defense Evasion", "Debugger Evasion"),
}

_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

T = {
    "en": {
        "title": "Incident report",
        "ticket": "Ticket",
        "severity": "Severity",
        "status": "Status",
        "status_open": "open",
        "status_in_progress": "in progress",
        "status_closed": "closed",
        "assignee": "Assigned to",
        "host": "Host",
        "user": "User",
        "os": "Operating system",
        "created": "Opened",
        "created_by": "Opened by",
        "generated": "Generated",
        "by": "by",
        "window": "Suspicious activity",
        "not_set": "not set",
        "summary": "Executive summary",
        "no_summary": "No executive summary was written for this incident.",
        "facts": "Key facts",
        "flagged": "Flagged events",
        "iocs": "Indicators of compromise",
        "samples": "Malware samples",
        "techniques": "ATT&CK techniques",
        "detections": "SOC detections",
        "timeline": "Flagged events",
        "no_flags": "No event was flagged as part of the malicious activity.",
        "time": "Time",
        "source": "Source",
        "event": "Event",
        "comments": "Comments",
        "attack": "MITRE ATT&CK",
        "attack_intro": "Techniques suggested by capa, YARA and the SOC rules. They point to where to look and"
        " need an analyst's confirmation.",
        "no_attack": "No technique was suggested.",
        "technique": "Technique",
        "tactic": "Tactic",
        "evidence_of": "Seen in",
        "type": "Type",
        "value": "Value",
        "seen": "Seen in",
        "other": "Other incidents",
        "no_iocs": "No indicator outside the allowlist.",
        "more_iocs": "{n} more indicators are in the CSV / STIX / MISP export.",
        "file": "File",
        "size": "Size",
        "yara": "YARA",
        "capabilities": "capa",
        "no_samples": "No sample was analysed.",
        "mails": "E-mails",
        "message": "Message",
        "verdict": "Verdict",
        "findings": "Main findings",
        "no_mails": "No e-mail was analysed.",
        "verdicts": {"phishing": "phishing", "suspicious": "suspicious", "clean": "no strong signs"},
        "network": "Network",
        "url_scans": "Scanned addresses",
        "scope": "Content",
        "scope_flagged": "what the analysts flagged",
        "scope_all": "everything in the incident",
        "nothing_flagged": "Nothing was flagged here.",
        "address": "Address",
        "capture": "Capture",
        "packets": "Packets",
        "network_findings": "Findings",
        "no_network": "No network capture was analysed.",
        "browser_session": "isolated browser session (reconstructed)",
        "held": "submissions held, not sent",
        "posts": "POST requests",
        "beacons": "periodic connections (beacons)",
        "objects": "exported objects",
        "every": "every",
        "eventlogs": "Windows event logs",
        "channel": "Channel",
        "covers": "Covers",
        "records": "Kept / records",
        "cleared": "Cleared",
        "no_eventlogs": "No event log was imported.",
        "notes": "Analyst notes",
        "no_notes": "No notes.",
        "evidence": "Evidence appendix",
        "evidence_intro": "Every file imported into the incident. The SHA-256 is that of the original file.",
        "imported": "Imported",
        "rows": "Rows",
        "format": "Format",
        "sha256": "SHA-256",
        "no_evidence": "No file was imported.",
        "page": "Page",
        "of": "of",
        "yes": "yes",
    },
    "it": {
        "title": "Report dell'incidente",
        "ticket": "Ticket",
        "severity": "Severità",
        "status": "Stato",
        "status_open": "aperto",
        "status_in_progress": "in corso",
        "status_closed": "chiuso",
        "assignee": "Assegnato a",
        "host": "Host",
        "user": "Utente",
        "os": "Sistema operativo",
        "created": "Aperto il",
        "created_by": "Aperto da",
        "generated": "Generato il",
        "by": "da",
        "window": "Attività sospetta",
        "not_set": "non impostata",
        "summary": "Sintesi",
        "no_summary": "Nessuna sintesi è stata scritta per questo incidente.",
        "facts": "Dati principali",
        "flagged": "Eventi segnalati",
        "iocs": "Indicatori di compromissione",
        "samples": "Campioni malware",
        "techniques": "Tecniche ATT&CK",
        "detections": "Rilevamenti SOC",
        "timeline": "Eventi segnalati",
        "no_flags": "Nessun evento è stato segnalato come parte dell'attività malevola.",
        "time": "Ora",
        "source": "Fonte",
        "event": "Evento",
        "comments": "Commenti",
        "attack": "MITRE ATT&CK",
        "attack_intro": "Tecniche suggerite da capa, YARA e dalle regole SOC. Indicano dove guardare e vanno"
        " confermate da un analista.",
        "no_attack": "Nessuna tecnica suggerita.",
        "technique": "Tecnica",
        "tactic": "Tattica",
        "evidence_of": "Rilevata in",
        "type": "Tipo",
        "value": "Valore",
        "seen": "Visto in",
        "other": "Altri incidenti",
        "no_iocs": "Nessun indicatore fuori dalla allowlist.",
        "more_iocs": "Altri {n} indicatori sono nell'export CSV / STIX / MISP.",
        "file": "File",
        "size": "Dimensione",
        "yara": "YARA",
        "capabilities": "capa",
        "no_samples": "Nessun campione analizzato.",
        "mails": "E-mail",
        "message": "Messaggio",
        "verdict": "Verdetto",
        "findings": "Elementi principali",
        "no_mails": "Nessuna e-mail analizzata.",
        "verdicts": {"phishing": "phishing", "suspicious": "sospetta", "clean": "nessun segnale forte"},
        "network": "Rete",
        "url_scans": "Indirizzi analizzati",
        "scope": "Contenuto",
        "scope_flagged": "ciò che gli analisti hanno segnalato",
        "scope_all": "tutto il contenuto dell'incidente",
        "nothing_flagged": "Nessun elemento segnalato in questa sezione.",
        "address": "Indirizzo",
        "capture": "Cattura",
        "packets": "Pacchetti",
        "network_findings": "Elementi",
        "no_network": "Nessuna cattura di rete analizzata.",
        "browser_session": "sessione del browser isolato (ricostruita)",
        "held": "invii trattenuti, non inviati",
        "posts": "richieste POST",
        "beacons": "connessioni periodiche (beacon)",
        "objects": "oggetti esportati",
        "every": "ogni",
        "eventlogs": "Registri eventi Windows",
        "channel": "Canale",
        "covers": "Copre",
        "records": "Tenuti / record",
        "cleared": "Cancellato",
        "no_eventlogs": "Nessun registro eventi importato.",
        "notes": "Note degli analisti",
        "no_notes": "Nessuna nota.",
        "evidence": "Appendice delle prove",
        "evidence_intro": "Ogni file importato nell'incidente. Lo SHA-256 è quello del file originale.",
        "imported": "Importato",
        "rows": "Righe",
        "format": "Formato",
        "sha256": "SHA-256",
        "no_evidence": "Nessun file importato.",
        "page": "Pagina",
        "of": "di",
        "yes": "sì",
    },
}


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _ms(value: Any) -> str:
    if not isinstance(value, (int, float)) or value <= 0:
        return "—"
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _iso(value: Any) -> str:
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return "—"
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _size(n: Any) -> str:
    if not isinstance(n, (int, float)):
        return "—"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


_SOURCE_KINDS = {
    "browser": "Browser",
    "commands": "Commands",
    "endpoint": "Endpoint",
    "eventlog": "Event log",
    "mail": "Mail",
}


def _source(source: str) -> str:
    """``eventlog:Security`` → ``Event log · Security`` (as the IOCs tab shows it)."""
    kind, _, rest = str(source).partition(":")
    label = _SOURCE_KINDS.get(kind, kind.capitalize())
    return f"{label} · {rest}" if rest else label


def _table(headers: list[str], rows: list[list[str]], widths: list[str] | None = None) -> str:
    cols = "".join(f'<col style="width:{w}">' for w in widths) if widths else ""
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><colgroup>{cols}</colgroup><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _paragraphs(text: str) -> str:
    blocks = [b.strip() for b in re.split(r"\n\s*\n", text or "") if b.strip()]
    return "".join(f"<p>{esc(b).replace(chr(10), '<br>')}</p>" for b in blocks)


# --------------------------------------------------------------------------- #
# Data gathering                                                              #
# --------------------------------------------------------------------------- #
def attack_techniques(samples: list[dict[str, Any]], detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Techniques from capa capabilities, YARA rule metadata and SOC rule hits.

    ``samples``: ``[{fileName, yara: [...], capa: [...]}]``; ``detections``:
    ``[{label, count, attack: [ids]}]`` (sent by the app, which runs the rules).
    """
    found: dict[str, dict[str, Any]] = {}

    def add(technique_id: str, source: str, tactic: str = "", name: str = "") -> None:
        known = ATTACK_NAMES.get(technique_id, ("", ""))
        item = found.setdefault(
            technique_id, {"id": technique_id, "tactic": tactic or known[0], "name": name or known[1], "sources": []}
        )
        if not item["name"] and name:
            item["name"] = name
        if source not in item["sources"]:
            item["sources"].append(source)

    for sample in samples:
        label = sample.get("fileName") or str(sample.get("sha256", ""))[:12]
        for capability in sample.get("capa") or []:
            for entry in capability.get("attack") or []:
                if entry.get("id"):
                    name = entry.get("technique", "")
                    if entry.get("subtechnique"):
                        name = f"{name}: {entry['subtechnique']}"
                    add(entry["id"], f"capa · {capability.get('name')} ({label})", entry.get("tactic", ""), name)
        for match in sample.get("yara") or []:
            meta = match.get("meta") or {}
            text = " ".join(str(meta.get(k, "")) for k in ("mitre_attack", "attack", "mitre", "technique"))
            for technique_id in _TECHNIQUE.findall(text):
                add(technique_id, f"YARA · {match.get('rule')} ({label})")
    for detection in detections:
        for technique_id in detection.get("attack") or []:
            if _TECHNIQUE.fullmatch(str(technique_id)):
                add(str(technique_id), f"SOC · {detection.get('label')} ×{detection.get('count', 1)}")
    return sorted(found.values(), key=lambda t: t["id"])


def _capture_row(capture: dict[str, Any], t: dict[str, Any]) -> list[str]:
    kind = t["browser_session"] if capture.get("kind") == "browser" else "pcap"
    findings = []
    for held in capture.get("held") or []:
        findings.append(f'<div class="high">{esc(t["held"])}: {esc(held.get("method"))} {esc(held.get("url"))}</div>')
    if capture.get("posts"):
        findings.append(f"<div>{esc(capture['posts'])} {esc(t['posts'])}</div>")
    for beacon in capture.get("beacons") or []:
        findings.append(
            f'<div class="high">{esc(t["beacons"])}: {esc(beacon.get("destination"))}:{esc(beacon.get("port"))}'
            f" × {esc(beacon.get('count'))}, {esc(t['every'])} {esc(beacon.get('interval'))} s</div>"
        )
    if capture.get("objects"):
        findings.append(f"<div>{esc(capture['objects'])} {esc(t['objects'])}</div>")
    window = f"{_ms(capture.get('first'))} → {_ms(capture.get('last'))}" if capture.get("first") else ""
    return [
        f"{esc(capture.get('fileName'))}<br><span class='muted'>{esc(kind)}</span>"
        f"<br><span class='mono'>{esc(capture.get('sha256') or '')}</span>",
        f"{esc(capture.get('packets') or 0)}<br><span class='muted'>{esc(window)}</span>",
        "".join(findings) or "—",
    ]


SCOPES = ("flagged", "all")
# Sections of a flag that belong to a browser profile's data.
_BROWSER_SECTIONS = {"events", "bookmarks", "shortcuts"}


def flagged_scope(doc: dict) -> dict[str, set]:
    """What the analysts flagged, by kind, read from the flag keys.

    A sample, an e-mail, a capture or a scanned address counts when it was
    flagged itself or when something inside it was (an indicator or a
    function of a sample, a packet, a held submission or a beacon of a
    capture). ``iocs`` are the indicators flagged by hand, ``(type, value)``.
    The other sets name the sources that hold a flagged event, for the
    evidence appendix.
    """
    scope: dict[str, set] = {
        name: set()
        for name in ("samples", "mails", "captures", "urls", "iocs", "browsers", "shells", "categories", "channels")
    }
    for key, flag in (doc.get("flags") or {}).items():
        if not isinstance(flag, dict):
            continue
        parts = str(key).split(":")
        head = parts[0]
        if head == "sample" and len(parts) >= 2:
            scope["samples"].add(parts[1])
            if len(parts) >= 5 and parts[2] == "ioc":
                scope["iocs"].add((parts[3], ":".join(parts[4:])))
        elif head == "mail" and len(parts) >= 2:
            scope["mails"].add(parts[1])
        elif head in ("capture", "pcap", "held", "beacon") and len(parts) >= 2:
            scope["captures"].add(parts[1])
        elif head == "url" and len(parts) >= 2:
            scope["urls"].add(parts[1])
        elif head == "ioc" and len(parts) >= 3:
            scope["iocs"].add((parts[1], ":".join(parts[2:])))
        elif head == "evt" and len(parts) >= 2:
            scope["channels"].add(parts[1])
        section = str(flag.get("section") or "")
        source = str(flag.get("browserId") or "")
        if section in _BROWSER_SECTIONS and source:
            scope["browsers"].add(source)
        elif section == "commands" and source:
            scope["shells"].add(source)
        elif section.startswith("endpoint:"):
            scope["categories"].add(section.split(":", 1)[1])
    return scope


def _flagged_iocs(iocs: list[dict[str, Any]], wanted: set) -> list[dict[str, Any]]:
    """The indicators flagged by hand: their index rows, or a bare row for one the index does not hold."""
    rows = [i for i in iocs if (i.get("type"), i.get("value")) in wanted]
    known = {(i.get("type"), i.get("value")) for i in rows}
    rows += [
        {"type": kind, "value": value, "sources": [], "otherIncidents": 0} for kind, value in sorted(wanted - known)
    ]
    return rows


def evidence(doc: dict, scope: dict[str, set] | None = None) -> list[dict[str, Any]]:
    """Every imported file: tab, source, file name, format, rows, time, SHA-256.

    With ``scope`` (see ``flagged_scope``), only the sources that hold
    something flagged.
    """
    data = doc.get("data") or {}
    rows: list[dict[str, Any]] = []

    def keep(kind: str, value: Any) -> bool:
        return scope is None or value in scope[kind]

    def add(tab: str, source: str, meta: Any) -> None:
        if isinstance(meta, dict) and meta.get("fileName") and meta.get("format") != "demo":
            rows.append(
                {
                    "tab": tab,
                    "source": source,
                    "fileName": meta.get("fileName"),
                    "format": meta.get("format", ""),
                    "rows": meta.get("rows", meta.get("kept")),
                    "importedAt": meta.get("importedAt"),
                    "sha256": meta.get("sha256", ""),
                }
            )

    for browser_id, slot in ((data.get("browser") or {}).get("browsers") or {}).items():
        if not keep("browsers", browser_id):
            continue
        for profile in ((slot or {}).get("profiles") or {}).values():
            for source, meta in ((profile or {}).get("meta") or {}).items():
                add("Browser", f"{browser_id} · {profile.get('name', '')} · {source}", meta)
    for shell_id, slot in ((data.get("commands") or {}).get("shells") or {}).items():
        if not keep("shells", shell_id):
            continue
        for source, meta in ((slot or {}).get("meta") or {}).items():
            add("Commands", f"{shell_id} · {source}", meta)
    for category_id, category in ((data.get("endpoint") or {}).get("categories") or {}).items():
        if not keep("categories", category_id):
            continue
        for source, slot in ((category or {}).get("sources") or {}).items():
            add("Endpoint", f"{category_id} · {source}", (slot or {}).get("meta"))
    for channel, slot in ((data.get("eventlogs") or {}).get("channels") or {}).items():
        if keep("channels", channel):
            add("Event logs", channel, (slot or {}).get("meta"))
    for ref in ((data.get("network") or {}).get("captures") or []) if isinstance(data.get("network"), dict) else []:
        if isinstance(ref, dict) and ref.get("sha256") and keep("captures", ref.get("id")):
            rows.append(
                {
                    "tab": "Network",
                    "source": "isolated browser" if ref.get("kind") == "browser" else "capture",
                    "fileName": ref.get("fileName"),
                    "format": "pcapng" if ref.get("kind") == "browser" else "pcap",
                    "rows": ref.get("packets"),
                    "importedAt": ref.get("createdAt"),
                    "sha256": ref.get("sha256", ""),
                }
            )
    for ref in (data.get("mail") or {}).get("messages") or []:
        if isinstance(ref, dict) and keep("mails", ref.get("sha256")):
            rows.append(
                {
                    "tab": "Mail",
                    "source": ref.get("subject") or "",
                    "fileName": ref.get("fileName"),
                    "format": ref.get("format", "eml"),
                    "rows": None,
                    "importedAt": ref.get("importedAt"),
                    "sha256": ref.get("sha256", ""),
                }
            )
    for ref in (data.get("malware") or {}).get("samples") or []:
        if isinstance(ref, dict) and keep("samples", ref.get("sha256")):
            rows.append(
                {
                    "tab": "Malware",
                    "source": (ref.get("type") or {}).get("label", ""),
                    "fileName": ref.get("fileName"),
                    "format": "sample",
                    "rows": None,
                    "importedAt": ref.get("importedAt"),
                    "sha256": ref.get("sha256", ""),
                }
            )
    # One .evtx file can hold several channels: list it once.
    unique: dict[tuple, dict[str, Any]] = {}
    for row in rows:
        key = (row["tab"], row["fileName"], row["sha256"] or row["source"])
        unique.setdefault(key, row)
    return list(unique.values())


# --------------------------------------------------------------------------- #
# HTML                                                                        #
# --------------------------------------------------------------------------- #
_CSS = """
@page { size: A4; margin: 22mm 16mm 20mm;
  @top-left { content: string(org); font: 8pt sans-serif; color: #555; }
  @top-right { content: element(tlp); }
  @bottom-left { content: string(incident); font: 8pt sans-serif; color: #555; }
  @bottom-right { content: "PAGE " counter(page) " / " counter(pages); font: 8pt sans-serif; color: #555; } }
* { box-sizing: border-box; }
body { font-family: "DejaVu Sans", "Liberation Sans", Arial, sans-serif; font-size: 9.5pt; color: #1b1f24;
  line-height: 1.45; margin: 0; }
.org { string-set: org content(); }
.incident-name { string-set: incident content(); }
.tlp { position: running(tlp); display: inline-block; background: #000; font: bold 9pt sans-serif;
  padding: 2px 8px; letter-spacing: .04em; }
header.cover { border-bottom: 2px solid #1b1f24; padding-bottom: 10px; margin-bottom: 14px; display: flex;
  align-items: center; gap: 14px; }
header.cover img { max-height: 48px; max-width: 160px; }
header.cover .who { flex: 1; }
h1 { font-size: 20pt; margin: 0 0 2px; }
h2 { font-size: 13pt; margin: 22px 0 8px; padding-bottom: 3px; border-bottom: 1px solid #c9d1d9;
  break-after: avoid; }
.sub { color: #57606a; font-size: 9pt; }
dl.meta { display: grid; grid-template-columns: 34mm 1fr; gap: 2px 10px; margin: 0; }
dl.meta dt { color: #57606a; } dl.meta dd { margin: 0; }
.facts { display: flex; gap: 8px; margin: 8px 0; }
.fact { flex: 1; border: 1px solid #d0d7de; padding: 6px 8px; }
.fact b { display: block; font-size: 15pt; }
.fact span { color: #57606a; font-size: 8pt; text-transform: uppercase; letter-spacing: .04em; }
table { width: 100%; border-collapse: collapse; margin: 4px 0 8px; table-layout: fixed; }
th { text-align: left; font-size: 8pt; text-transform: uppercase; letter-spacing: .03em; color: #57606a;
  border-bottom: 1px solid #8c959f; padding: 3px 4px; }
td { border-bottom: 1px solid #eaeef2; padding: 3px 4px; vertical-align: top; overflow-wrap: anywhere; }
tr { break-inside: avoid; }
.mono, code { font-family: "DejaVu Sans Mono", "Liberation Mono", monospace; font-size: 8pt; }
.pill { display: inline-block; border: 1px solid #8c959f; padding: 0 4px; font-size: 7.5pt; margin: 0 2px 2px 0; }
.high { color: #b42318; font-weight: bold; }
.muted { color: #57606a; }
.comment { color: #57606a; font-size: 8.5pt; margin-top: 2px; }
@media screen { body { max-width: 210mm; margin: 0 auto; padding: 16px 20px; } .tlp { margin-bottom: 8px; } }
"""


def build_html(
    doc: dict,
    *,
    lang: str = "en",
    tlp: str = "amber",
    sections: list[str] | None = None,
    executive_summary: str = "",
    detections: list[dict[str, Any]] | None = None,
    iocs: list[dict[str, Any]] | None = None,
    samples: list[dict[str, Any]] | None = None,
    mails: list[dict[str, Any]] | None = None,
    branding: dict[str, Any] | None = None,
    generated_by: str = "",
    generated_at: str = "",
    scope: str = "flagged",
) -> str:
    """The report as one HTML page (see the module docstring).

    ``scope`` ``flagged`` (the default) keeps, in every section, what the
    analysts flagged: see ``flagged_scope``. ``all`` lists everything the
    incident holds.
    """
    t = T.get(lang, T["en"])
    wanted = [s for s in (sections or SECTIONS) if s in SECTIONS]
    tlp = tlp if tlp in TLP_LEVELS else "amber"
    branding = branding or {}
    detections = detections or []
    iocs = [i for i in (iocs or []) if not i.get("allowlisted")]
    samples = samples or []
    mails = mails or []
    data = doc.get("data") or {}
    only = flagged_scope(doc) if scope != "all" else None
    empty = "nothing_flagged" if only is not None else None
    if only is not None:
        samples = [s for s in samples if s.get("sha256") in only["samples"]]
        mails = [m for m in mails if m.get("sha256") in only["mails"]]
        iocs = _flagged_iocs(iocs, only["iocs"])
    flags = sorted(
        (f for f in (doc.get("flags") or {}).values() if isinstance(f, dict)),
        key=lambda f: f.get("time") or 0,
    )
    techniques = attack_techniques(samples, detections)
    name = doc.get("name") or doc.get("id") or ""
    tlp_label = f"TLP:{tlp.upper()}"
    out: list[str] = []

    logo = branding.get("logo") or ""
    org = branding.get("orgName") or ""
    out.append(
        f'<span class="tlp" style="color:{_TLP_COLOURS[tlp]}">{esc(tlp_label)}</span>'
        '<header class="cover">'
        + (f'<img src="{esc(logo)}" alt="">' if logo.startswith("data:image/") else "")
        + f'<div class="who"><div class="org sub">{esc(org)}</div>'
        f"<h1>{esc(t['title'])}</h1>"
        f'<div class="incident-name"><strong>{esc(name)}</strong></div></div></header>'
    )
    window = (
        f"{_ms(doc.get('suspiciousStart'))} → {_ms(doc.get('suspiciousEnd'))}"
        if doc.get("suspiciousStart") or doc.get("suspiciousEnd")
        else t["not_set"]
    )
    meta = [
        *([(t["ticket"], doc["ticketId"])] if doc.get("ticketId") else []),
        *([(t["severity"], doc["severity"])] if doc.get("severity") else []),
        (t["status"], t.get(f"status_{doc.get('status')}", t["status_open"])),
        *([(t["assignee"], doc["assignee"])] if doc.get("assignee") else []),
        (t["host"], doc.get("host") or "—"),
        (t["user"], doc.get("username") or "—"),
        (t["os"], doc.get("os") or "—"),
        (t["created"], _iso(doc.get("createdAt"))),
        (t["created_by"], doc.get("createdBy") or "—"),
        (t["window"], window),
        (t["generated"], f"{_iso(generated_at)} {t['by']} {generated_by}"),
        (t["scope"], t["scope_flagged"] if only is not None else t["scope_all"]),
    ]
    out.append('<dl class="meta">' + "".join(f"<dt>{esc(k)}</dt><dd>{esc(v)}</dd>" for k, v in meta) + "</dl>")

    if "summary" in wanted:
        out.append(f"<h2>{esc(t['summary'])}</h2>")
        out.append(_paragraphs(executive_summary) or f'<p class="muted">{esc(t["no_summary"])}</p>')
        facts = [
            (len(flags), t["flagged"]),
            (sum(int(d.get("count") or 0) for d in detections), t["detections"]),
            (len(iocs), t["iocs"]),
            (len(samples), t["samples"]),
            (len(techniques), t["techniques"]),
        ]
        out.append(
            '<div class="facts">'
            + "".join(f'<div class="fact"><b>{n}</b><span>{esc(label)}</span></div>' for n, label in facts)
            + "</div>"
        )

    if "timeline" in wanted:
        out.append(f"<h2>{esc(t['timeline'])}</h2>")
        if flags:
            rows = []
            for flag in flags:
                comments = "".join(
                    f'<div class="comment">“{esc(c.get("text"))}” — {esc(c.get("author"))}</div>'
                    for c in flag.get("comments") or []
                    if isinstance(c, dict)
                )
                detail = esc(flag.get("title") or flag.get("url") or "")
                rows.append(
                    [
                        f'<span class="mono">{esc(_ms(flag.get("time")))}</span>',
                        esc(" · ".join(filter(None, [flag.get("section"), flag.get("browserId")]))),
                        f"{detail}{comments}",
                        esc(flag.get("flaggedBy") or ""),
                    ]
                )
            out.append(_table([t["time"], t["source"], t["event"], t["by"]], rows, ["24%", "18%", "46%", "12%"]))
        else:
            out.append(f'<p class="muted">{esc(t["no_flags"])}</p>')

    if "attack" in wanted:
        out.append(f"<h2>{esc(t['attack'])}</h2>")
        if techniques:
            out.append(f'<p class="muted">{esc(t["attack_intro"])}</p>')
            rows = [
                [
                    f'<span class="mono">{esc(tech["id"])}</span>',
                    esc(tech["tactic"]),
                    esc(tech["name"]),
                    "".join(f'<span class="pill">{esc(s)}</span>' for s in tech["sources"][:6])
                    + (f' <span class="muted">+{len(tech["sources"]) - 6}</span>' if len(tech["sources"]) > 6 else ""),
                ]
                for tech in techniques
            ]
            out.append(_table([t["technique"], t["tactic"], "", t["evidence_of"]], rows, ["13%", "17%", "30%", "40%"]))
        else:
            out.append(f'<p class="muted">{esc(t["no_attack"])}</p>')

    if "iocs" in wanted:
        out.append(f"<h2>{esc(t['iocs'])}</h2>")
        if iocs:
            ordered = sorted(iocs, key=lambda i: (-(i.get("otherIncidents") or 0), i["type"], i["value"]))
            rows = [
                [
                    esc(i["type"]),
                    f'<span class="mono">{esc(i["value"])}</span>',
                    esc(", ".join(_source(src) for src in i.get("sources") or [])),
                    f'<span class="high">{i["otherIncidents"]}</span>' if i.get("otherIncidents") else "—",
                ]
                for i in ordered[:MAX_IOCS]
            ]
            out.append(_table([t["type"], t["value"], t["seen"], t["other"]], rows, ["9%", "47%", "32%", "12%"]))
            if len(ordered) > MAX_IOCS:
                out.append(f'<p class="muted">{esc(t["more_iocs"].format(n=len(ordered) - MAX_IOCS))}</p>')
        else:
            out.append(f'<p class="muted">{esc(t[empty or "no_iocs"])}</p>')

    if "samples" in wanted:
        out.append(f"<h2>{esc(t['samples'])}</h2>")
        if samples:
            rows = []
            for sample in samples:
                yara = ", ".join(str(m.get("rule")) for m in sample.get("yara") or [])
                rows.append(
                    [
                        f"{esc(sample.get('fileName'))}<br><span class='muted'>{esc(sample.get('typeLabel'))}"
                        f" · {esc(_size(sample.get('size')))}</span>",
                        f'<span class="mono">SHA-256 {esc(sample.get("sha256"))}<br>SHA-1 {esc(sample.get("sha1"))}'
                        f"<br>MD5 {esc(sample.get('md5'))}</span>",
                        esc(yara or "—"),
                        str(len(sample.get("capa") or [])) if sample.get("capa") is not None else "—",
                    ]
                )
            out.append(
                _table([t["file"], t["sha256"], t["yara"], t["capabilities"]], rows, ["24%", "46%", "18%", "12%"])
            )
        else:
            out.append(f'<p class="muted">{esc(t[empty or "no_samples"])}</p>')

    if "mails" in wanted:
        out.append(f"<h2>{esc(t['mails'])}</h2>")
        if mails:
            rows = []
            for mail in mails:
                verdict = mail.get("verdict") or "clean"
                label = t["verdicts"].get(verdict, verdict)
                rows.append(
                    [
                        f"{esc(mail.get('subject') or '—')}<br><span class='muted'>{esc(mail.get('from'))}"
                        f" · {esc(_ms(mail.get('date')))}</span><br><span class='muted'>{esc(mail.get('fileName'))}"
                        "</span>",
                        (f'<span class="high">{esc(label)}</span>' if verdict == "phishing" else esc(label))
                        + f"<br><span class='muted'>{esc(mail.get('score'))}/100</span>",
                        "".join(f"<div>{esc(f)}</div>" for f in mail.get("findings") or []) or "—",
                    ]
                )
            out.append(_table([t["message"], t["verdict"], t["findings"]], rows, ["38%", "14%", "48%"]))
        else:
            out.append(f'<p class="muted">{esc(t[empty or "no_mails"])}</p>')

    if "network" in wanted:
        out.append(f"<h2>{esc(t['network'])}</h2>")
        captures = [c for c in ((data.get("network") or {}).get("captures") or []) if isinstance(c, dict)]
        if only is not None:
            captures = [c for c in captures if c.get("id") in only["captures"]]
        if captures:
            out.append(
                _table(
                    [t["capture"], t["packets"], t["network_findings"]],
                    [_capture_row(c, t) for c in captures],
                    ["40%", "16%", "44%"],
                )
            )
        else:
            out.append(f'<p class="muted">{esc(t[empty or "no_network"])}</p>')
        urls = data.get("urls") if isinstance(data.get("urls"), dict) else {}
        scans = [u for u in urls.get("scans") or [] if isinstance(u, dict)]
        if only is not None:
            scans = [u for u in scans if u.get("id") in only["urls"]]
        if scans:
            out.append(f"<h3>{esc(t['url_scans'])}</h3>")
            rows = [
                [
                    f'<span class="mono">{esc(u.get("url"))}</span>',
                    f"{esc(u.get('verdict') or u.get('status'))}"
                    + (f" ({esc(u.get('score'))})" if u.get("verdict") else ""),
                ]
                for u in scans
            ]
            out.append(_table([t["address"], t["verdict"]], rows, ["76%", "24%"]))

    if "eventlogs" in wanted:
        out.append(f"<h2>{esc(t['eventlogs'])}</h2>")
        channels = (data.get("eventlogs") or {}).get("channels") or {}
        # Clears are computed on every channel (a System event can name another log).
        cleared = _cleared_channels(channels) if channels else {}
        if only is not None:
            channels = {name: slot for name, slot in channels.items() if name in only["channels"]}
        if channels:
            rows = []
            for channel, slot in sorted(channels.items()):
                meta = (slot or {}).get("meta") or {}
                rows.append(
                    [
                        esc(channel),
                        f'<span class="mono">{esc(_ms(meta.get("first")))} → {esc(_ms(meta.get("last")))}</span>',
                        f"{len((slot or {}).get('events') or [])} / {esc(meta.get('total', '—'))}",
                        f'<span class="high">{esc(", ".join(_ms(c) for c in cleared[channel]))}</span>'
                        if cleared.get(channel)
                        else "—",
                    ]
                )
            out.append(
                _table([t["channel"], t["covers"], t["records"], t["cleared"]], rows, ["34%", "36%", "12%", "18%"])
            )
        else:
            out.append(f'<p class="muted">{esc(t[empty or "no_eventlogs"])}</p>')

    if "notes" in wanted:
        out.append(f"<h2>{esc(t['notes'])}</h2>")
        notes = [n for n in doc.get("notes") or [] if isinstance(n, dict)]
        if notes:
            for note in notes:
                out.append(
                    f'<p class="sub">{esc(note.get("author"))} · {esc(_iso(note.get("createdAt")))}</p>'
                    + _paragraphs(note.get("text") or "")
                )
        else:
            out.append(f'<p class="muted">{esc(t["no_notes"])}</p>')

    if "evidence" in wanted:
        out.append(f"<h2>{esc(t['evidence'])}</h2>")
        items = evidence(doc, only)
        if items:
            out.append(f'<p class="muted">{esc(t["evidence_intro"])}</p>')
            rows = [
                [
                    f"{esc(e['tab'])}<br><span class='muted'>{esc(e['source'])}</span>",
                    f"{esc(e['fileName'])}<br><span class='muted'>{esc(e['format'])}"
                    + (f" · {esc(e['rows'])} {esc(t['rows'].lower())}" if e.get("rows") is not None else "")
                    + "</span>",
                    f'<span class="mono">{esc(_iso(e["importedAt"]))}</span>',
                    f'<span class="mono">{esc(e["sha256"] or "—")}</span>',
                ]
                for e in items
            ]
            out.append(_table([t["source"], t["file"], t["imported"], t["sha256"]], rows, ["20%", "26%", "16%", "38%"]))
        else:
            out.append(f'<p class="muted">{esc(t[empty or "no_evidence"])}</p>')

    title = f"{t['title']} — {name}"
    return (
        f'<!doctype html><html lang="{esc(lang)}"><head><meta charset="utf-8">'
        f"<title>{esc(title)}</title><style>{_CSS}</style></head><body>{''.join(out)}</body></html>"
    )


def _cleared_channels(channels: dict) -> dict[str, list[int]]:
    """Channel → times it was cleared (1102 clears Security, 104 names the log)."""
    cleared: dict[str, list[int]] = {}
    lookup = {name.lower(): name for name in channels}
    for channel, slot in channels.items():
        for event in (slot or {}).get("events") or []:
            if not isinstance(event, dict):
                continue
            if channel == "Security" and event.get("eventId") == 1102:
                target = "Security"
            elif channel == "System" and event.get("eventId") == 104:
                named = str((event.get("data") or {}).get("Channel") or "").lower()
                target = lookup.get(named, (event.get("data") or {}).get("Channel") or "System")
            else:
                continue
            cleared.setdefault(target, []).append(event.get("time"))
    return cleared


def to_pdf(document: str) -> bytes:
    """Render the report HTML to PDF (WeasyPrint, imported on first use)."""
    import weasyprint

    return weasyprint.HTML(string=document).write_pdf()
