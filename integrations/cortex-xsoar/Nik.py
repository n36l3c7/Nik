"""Cortex XSOAR integration for the Nik forensic analysis platform.

Talks to the Nik REST API (see the project README § "REST API"). Authenticates
with an API key sent in the ``X-API-Key`` header; the key's role/scopes decide
what each command may do (an analyst key covers incidents/notes/uploads; an
admin key is required for the audit-clear and any admin-data endpoints).
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

import urllib3
from typing import Any

urllib3.disable_warnings()

DEFAULT_MAX_FETCH = 50


class Client(BaseClient):
    """HTTP client for the Nik API. All calls carry the X-API-Key header."""

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        super().__init__(
            base_url=base_url.rstrip("/"),
            verify=verify,
            proxy=proxy,
            headers={"X-API-Key": api_key},
        )

    def ready(self) -> dict:
        return self._http_request("GET", "/api/ready")

    def list_incidents(self, limit=None, offset=None, query=None, host=None,
                       username=None, view=None) -> dict:
        params = assign_params(limit=limit, offset=offset, q=query, host=host,
                               username=username, view=view)
        return self._http_request("GET", "/api/incidents", params=params)

    def get_incident(self, incident_id: str) -> dict:
        return self._http_request("GET", f"/api/incidents/{incident_id}")

    def create_incident(self, doc: dict) -> dict:
        return self._http_request("POST", "/api/incidents", json_data=doc)

    def update_incident(self, incident_id: str, partial: dict) -> dict:
        return self._http_request("PATCH", f"/api/incidents/{incident_id}", json_data=partial)

    def delete_incident(self, incident_id: str) -> None:
        self._http_request("DELETE", f"/api/incidents/{incident_id}",
                           resp_type="response", ok_codes=(204, 404))

    def add_note(self, incident_id: str, text: str) -> dict:
        return self._http_request("POST", f"/api/incidents/{incident_id}/notes",
                                  json_data={"text": text})

    def delete_note(self, incident_id: str, note_id: str) -> None:
        self._http_request("DELETE", f"/api/incidents/{incident_id}/notes/{note_id}",
                           resp_type="response", ok_codes=(204, 404))

    def upload(self, incident_id: str, params: dict, filename: str, content: bytes) -> dict:
        return self._http_request(
            "POST", f"/api/incidents/{incident_id}/upload",
            params=params, files={"file": (filename, content)},
        )

    def list_audit(self, limit=None, query=None, actor=None, incident_id=None) -> dict:
        params = assign_params(limit=limit, q=query, actor=actor, incidentId=incident_id)
        return self._http_request("GET", "/api/audit", params=params)

    def get_settings(self) -> dict:
        return self._http_request("GET", "/api/settings")


# --------------------------------------------------------------------------- #
# Command handlers                                                            #
# --------------------------------------------------------------------------- #
def test_module(client: Client) -> str:
    """Validate the URL + API key by hitting a lightweight authed endpoint."""
    try:
        client.list_incidents(limit=1, view="summary")
    except DemistoException as exc:  # noqa: F405
        if exc.res is not None and exc.res.status_code in (401, 403):
            return "Authorization failed: check the API Key (and that it has the needed scope)."
        raise
    return "ok"


def _incident_summary(inc: dict) -> dict:
    """Light projection used for readable tables (a full doc can be huge)."""
    return {
        "id": inc.get("id"),
        "name": inc.get("name"),
        "host": inc.get("host"),
        "username": inc.get("username"),
        "os": inc.get("os"),
        "createdAt": inc.get("createdAt"),
        "updatedAt": inc.get("updatedAt"),
        "flags": len(inc.get("flags") or {}),
        "notes": len(inc.get("notes") or []),
    }


def get_incidents_command(client: Client, args: dict) -> CommandResults:  # noqa: F405
    res = client.list_incidents(
        limit=arg_to_number(args.get("limit")),  # noqa: F405
        offset=arg_to_number(args.get("offset")),  # noqa: F405
        query=args.get("query"),
        host=args.get("host"),
        username=args.get("username"),
        view=args.get("view", "summary"),
    )
    incidents = res.get("incidents", [])
    table = [_incident_summary(i) for i in incidents]
    return CommandResults(  # noqa: F405
        outputs_prefix="Nik.Incident",
        outputs_key_field="id",
        outputs=incidents,
        readable_output=tableToMarkdown(  # noqa: F405
            f"Nik incidents ({res.get('total', len(incidents))} total)", table,
            headers=["id", "name", "host", "username", "os", "flags", "notes", "updatedAt"],
        ),
        raw_response=res,
    )


def get_incident_command(client: Client, args: dict) -> CommandResults:  # noqa: F405
    incident_id = args["incident_id"]
    inc = client.get_incident(incident_id)
    return CommandResults(  # noqa: F405
        outputs_prefix="Nik.Incident",
        outputs_key_field="id",
        outputs=inc,
        readable_output=tableToMarkdown(f"Nik incident {incident_id}", _incident_summary(inc)),  # noqa: F405
        raw_response=inc,
    )


def create_incident_command(client: Client, args: dict) -> CommandResults:  # noqa: F405
    doc = assign_params(  # noqa: F405
        name=args.get("name"), host=args.get("host"),
        username=args.get("username"), os=args.get("os"),
    )
    inc = client.create_incident(doc)
    return CommandResults(  # noqa: F405
        outputs_prefix="Nik.Incident",
        outputs_key_field="id",
        outputs=inc,
        readable_output=f"Created Nik incident **{inc.get('name') or inc.get('id')}** (`{inc.get('id')}`).",
        raw_response=inc,
    )


def update_incident_command(client: Client, args: dict) -> CommandResults:  # noqa: F405
    incident_id = args["incident_id"]
    partial = assign_params(  # noqa: F405
        host=args.get("host"), username=args.get("username"), os=args.get("os"),
        suspiciousStart=arg_to_number(args.get("suspicious_start")),  # noqa: F405
        suspiciousEnd=arg_to_number(args.get("suspicious_end")),  # noqa: F405
    )
    inc = client.update_incident(incident_id, partial)
    return CommandResults(  # noqa: F405
        outputs_prefix="Nik.Incident",
        outputs_key_field="id",
        outputs=inc,
        readable_output=f"Updated Nik incident `{incident_id}`.",
        raw_response=inc,
    )


def delete_incident_command(client: Client, args: dict) -> CommandResults:  # noqa: F405
    incident_id = args["incident_id"]
    client.delete_incident(incident_id)
    return CommandResults(readable_output=f"Deleted Nik incident `{incident_id}`.")  # noqa: F405


def add_note_command(client: Client, args: dict) -> CommandResults:  # noqa: F405
    incident_id = args["incident_id"]
    note = client.add_note(incident_id, args["text"])
    outputs = {"incidentId": incident_id, **note}
    return CommandResults(  # noqa: F405
        outputs_prefix="Nik.Note",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=f"Added note `{note.get('id')}` to incident `{incident_id}`.",
        raw_response=note,
    )


def delete_note_command(client: Client, args: dict) -> CommandResults:  # noqa: F405
    incident_id, note_id = args["incident_id"], args["note_id"]
    client.delete_note(incident_id, note_id)
    return CommandResults(readable_output=f"Deleted note `{note_id}` from incident `{incident_id}`.")  # noqa: F405


def upload_artifact_command(client: Client, args: dict) -> CommandResults:  # noqa: F405
    incident_id = args["incident_id"]
    entry_id = args["entry_id"]
    file_info = demisto.getFilePath(entry_id)
    params = assign_params(  # noqa: F405
        tab=args["tab"], browser=args.get("browser"), shell=args.get("shell"),
        category=args.get("category"), source=args.get("source"),
    )
    with open(file_info["path"], "rb") as fh:
        content = fh.read()
    summary = client.upload(incident_id, params, file_info.get("name") or "upload", content)
    outputs = {"incidentId": incident_id, **summary}
    return CommandResults(  # noqa: F405
        outputs_prefix="Nik.Upload",
        outputs=outputs,
        readable_output=tableToMarkdown(f"Upload to Nik incident {incident_id}", summary),  # noqa: F405
        raw_response=summary,
    )


def get_audit_command(client: Client, args: dict) -> CommandResults:  # noqa: F405
    res = client.list_audit(
        limit=arg_to_number(args.get("limit")),  # noqa: F405
        query=args.get("query"), actor=args.get("actor"),
        incident_id=args.get("incident_id"),
    )
    entries = res.get("entries", [])
    return CommandResults(  # noqa: F405
        outputs_prefix="Nik.AuditEntry",
        outputs_key_field="id",
        outputs=entries,
        readable_output=tableToMarkdown(  # noqa: F405
            "Nik audit log", entries,
            headers=["at", "actor", "action", "details", "incidentName"],
        ),
        raw_response=res,
    )


def get_settings_command(client: Client, _args: dict) -> CommandResults:  # noqa: F405
    settings = client.get_settings()
    return CommandResults(  # noqa: F405
        outputs_prefix="Nik.Settings",
        outputs=settings,
        readable_output=tableToMarkdown(  # noqa: F405
            "Nik detection keywords", settings.get("keywords", []),
            headers=["label", "pattern", "severity"],
        ),
        raw_response=settings,
    )


def fetch_incidents(client: Client, last_run: dict, first_fetch: str, max_fetch: int):
    """Pull Nik incidents (newest updates) into XSOAR.

    Uses the summary list and an ``updatedAt`` high-water mark (ISO-8601 strings
    sort chronologically) to page forward and avoid duplicates.
    """
    last_fetch = last_run.get("last_fetch") or first_fetch
    res = client.list_incidents(limit=max_fetch, view="summary")
    incidents = sorted(res.get("incidents", []), key=lambda i: i.get("updatedAt") or "")

    xsoar_incidents = []
    new_high = last_fetch
    for inc in incidents:
        updated = inc.get("updatedAt") or ""
        if updated <= last_fetch:
            continue
        xsoar_incidents.append({
            "name": f"Nik: {inc.get('name') or inc.get('id')}",
            "occurred": updated,
            "dbotMirrorId": inc.get("id"),
            "rawJSON": json.dumps(inc),  # noqa: F405
        })
        if updated > new_high:
            new_high = updated

    return {"last_fetch": new_high}, xsoar_incidents


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = params.get("url", "")
    api_key = (params.get("credentials") or {}).get("password") or params.get("apikey")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(base_url, api_key, verify, proxy)

        if command == "test-module":
            return_results(test_module(client))  # noqa: F405

        elif command == "fetch-incidents":
            first_fetch = (arg_to_datetime(params.get("first_fetch", "3 days")) or  # noqa: F405
                           arg_to_datetime("3 days")).isoformat()  # noqa: F405
            max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH  # noqa: F405
            next_run, incidents = fetch_incidents(client, demisto.getLastRun(), first_fetch, max_fetch)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == "nik-get-incidents":
            return_results(get_incidents_command(client, args))  # noqa: F405
        elif command == "nik-get-incident":
            return_results(get_incident_command(client, args))  # noqa: F405
        elif command == "nik-create-incident":
            return_results(create_incident_command(client, args))  # noqa: F405
        elif command == "nik-update-incident":
            return_results(update_incident_command(client, args))  # noqa: F405
        elif command == "nik-delete-incident":
            return_results(delete_incident_command(client, args))  # noqa: F405
        elif command == "nik-add-note":
            return_results(add_note_command(client, args))  # noqa: F405
        elif command == "nik-delete-note":
            return_results(delete_note_command(client, args))  # noqa: F405
        elif command == "nik-upload-artifact":
            return_results(upload_artifact_command(client, args))  # noqa: F405
        elif command == "nik-get-audit":
            return_results(get_audit_command(client, args))  # noqa: F405
        elif command == "nik-get-settings":
            return_results(get_settings_command(client, args))  # noqa: F405
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as exc:  # noqa: BLE001
        return_error(f"Failed to execute {command} command.\nError:\n{exc}")  # noqa: F405


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
