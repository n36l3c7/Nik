"""Every route of the app, and the permission it asks for.

``EXPECTED`` is written by hand on purpose: a new route that is not in the
table fails the first test, so nobody adds one without deciding who may call
it. The second test reads the gate each route declares; the third calls every
route with one API key per role and checks who is let through.

What a route may expect:

- a tuple of permissions: the caller needs **one of** them;
- ``"signed-in"``: any account or key, whatever its roles;
- ``"session"``: a signed-in person (the session cookie), not an API key;
- ``"admin-session"``: a signed-in administrator, not an API key (what must
  not be done with a key alone: taking somebody's second factor away);
- ``"first-run"``: open while there is no account, admin only afterwards;
- ``"public"``: no authentication (sign-in, health, the API documentation;
  ``/api/metrics`` declares no gate either: it answers to its own scrape
  token and to nothing else, which ``test_health.py`` checks).
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from app.core import security
from app.core.permissions import PERMISSIONS, ROLE_PERMISSIONS, ROLES
from app.main import app as fastapi_app
from tests.conftest import make_key

EXPECTED: dict[tuple[str, str], tuple[str, ...] | str] = {
    ("GET", "/api/openapi.json"): "public",
    ("GET", "/api/docs"): "public",
    ("GET", "/docs/oauth2-redirect"): "public",
    ("GET", "/api/redoc"): "public",
    ("GET", "/api/health"): "public",
    ("GET", "/api/ready"): "public",
    ("GET", "/api/metrics"): "public",
    # A file of the store for the automation worker: the request proves it comes from a process of
    # this server (store_handover.py), and nginx does not publish /api/internal/.
    ("GET", "/api/internal/store/{kind}/{ref}"): "public",
    # The same proof: a file of the store as it is on the disk, for the copy on the second host.
    ("GET", "/api/internal/store-sealed"): "public",
    ("GET", "/api/auth/bootstrap"): "public",
    ("POST", "/api/auth/login"): "public",
    ("POST", "/api/auth/login/code"): "public",
    ("POST", "/api/auth/logout"): "public",
    ("GET", "/api/auth/me"): "session",
    ("GET", "/api/auth/session"): "session",
    ("POST", "/api/auth/session/stay"): "session",
    ("GET", "/api/auth/sessions"): "session",
    ("POST", "/api/auth/sessions/end-others"): "session",
    ("DELETE", "/api/auth/sessions/{session_id}"): "session",
    ("GET", "/api/auth/second-factor"): "session",
    ("POST", "/api/auth/second-factor/totp"): "session",
    ("POST", "/api/auth/second-factor/totp/confirm"): "session",
    ("POST", "/api/auth/second-factor/off"): "session",
    ("POST", "/api/auth/second-factor/recovery-codes"): "session",
    ("GET", "/api/auth/policy"): ("admin",),
    ("PUT", "/api/auth/policy"): ("admin",),
    ("POST", "/api/users"): "first-run",
    ("GET", "/api/users"): ("admin",),
    ("GET", "/api/users/names"): "signed-in",
    ("PUT", "/api/users/me/password"): "session",
    ("PATCH", "/api/users/{user_id}"): ("admin",),
    ("DELETE", "/api/users/{user_id}"): ("admin",),
    ("GET", "/api/users/{user_id}/sessions"): ("admin",),
    ("DELETE", "/api/users/{user_id}/sessions"): ("admin",),
    ("DELETE", "/api/users/{user_id}/sessions/{session_id}"): ("admin",),
    ("POST", "/api/users/{user_id}/second-factor/reset"): "admin-session",
    ("GET", "/api/keys"): ("admin",),
    ("POST", "/api/keys"): ("admin",),
    ("DELETE", "/api/keys/{key_id}"): ("admin",),
    ("GET", "/api/incidents"): ("read",),
    ("GET", "/api/incidents/{incident_id}"): ("read",),
    ("GET", "/api/incidents/by-number/{number}"): ("read",),
    ("POST", "/api/incidents"): ("write",),
    ("PATCH", "/api/incidents/{incident_id}"): ("write",),
    ("DELETE", "/api/incidents/{incident_id}"): ("write",),
    ("POST", "/api/incidents/{incident_id}/upload"): ("write",),
    # Host evidence (7.0): files sent in parts, and what was read out of them.
    ("POST", "/api/uploads"): ("write",),
    ("GET", "/api/uploads/{upload_id}"): ("write",),
    ("PUT", "/api/uploads/{upload_id}"): ("write",),
    ("DELETE", "/api/uploads/{upload_id}"): ("write",),
    ("POST", "/api/uploads/{upload_id}/complete"): ("write",),
    ("GET", "/api/incidents/{incident_id}/evidence/sources"): ("read",),
    ("GET", "/api/incidents/{incident_id}/evidence/sources/{source_id}"): ("read",),
    ("DELETE", "/api/incidents/{incident_id}/evidence/sources/{source_id}"): ("write",),
    ("POST", "/api/incidents/{incident_id}/evidence/sources/{source_id}/again"): ("write",),
    ("POST", "/api/incidents/{incident_id}/evidence/sources/{source_id}/seen"): ("write",),
    ("DELETE", "/api/incidents/{incident_id}/evidence/sources/{source_id}/seen"): ("write",),
    ("GET", "/api/incidents/{incident_id}/evidence/records"): ("read",),
    ("GET", "/api/incidents/{incident_id}/evidence/records/{record_id}"): ("read",),
    ("PUT", "/api/incidents/{incident_id}/evidence/marks"): ("write",),
    ("GET", "/api/incidents/{incident_id}/evidence/summary"): ("read",),
    ("GET", "/api/incidents/{incident_id}/evidence/detections"): ("read",),
    ("GET", "/api/incidents/{incident_id}/evidence/export"): ("read",),
    ("GET", "/api/incidents/{incident_id}/evidence/processes"): ("read",),
    ("GET", "/api/incidents/{incident_id}/evidence/processes/hosts"): ("read",),
    ("GET", "/api/incidents/{incident_id}/evidence/processes/{process_id}/tree"): ("read",),
    ("GET", "/api/incidents/{incident_id}/evidence/logons"): ("read",),
    ("GET", "/api/incidents/{incident_id}/evidence/logons/graph"): ("read",),
    ("GET", "/api/incidents/{incident_id}/evidence/histogram"): ("read",),
    ("GET", "/api/incidents/{incident_id}/evidence/stack"): ("read",),
    ("GET", "/api/incidents/{incident_id}/evidence/fields"): ("read",),
    ("GET", "/api/incidents/{incident_id}/evidence/records/{record_id}/view"): ("read",),
    ("GET", "/api/incidents/{incident_id}/evidence/sources/{source_id}/page"): ("read",),
    ("GET", "/api/incidents/{incident_id}/evidence/sources/{source_id}/find"): ("read",),
    ("GET", "/api/incidents/{incident_id}/evidence/sources/{source_id}/download"): ("evidence.download",),
    # A collection (a triage zip) listed, then imported on request; "Analyse" is as uploading a sample.
    ("GET", "/api/incidents/{incident_id}/evidence/collections/{source_id}"): ("read",),
    ("POST", "/api/incidents/{incident_id}/evidence/collections/{source_id}/import"): ("write",),
    ("POST", "/api/incidents/{incident_id}/evidence/collections/{source_id}/analyse"): ("write",),
    # Archiving (7.0): a closed incident, read-only and out of the lists; the rule is set by whoever may archive.
    ("POST", "/api/incidents/{incident_id}/archive"): ("incidents.archive",),
    ("DELETE", "/api/incidents/{incident_id}/archive"): ("incidents.archive",),
    ("GET", "/api/settings/archive"): ("admin", "incidents.archive"),
    ("PUT", "/api/settings/archive"): ("admin", "incidents.archive"),
    ("POST", "/api/incidents/{incident_id}/notes"): ("write",),
    ("PATCH", "/api/incidents/{incident_id}/notes/{note_id}"): ("write",),
    ("DELETE", "/api/incidents/{incident_id}/notes/{note_id}"): ("write",),
    ("GET", "/api/iocs/found/settings"): ("read",),
    ("PUT", "/api/iocs/found/settings"): ("admin",),
    ("GET", "/api/iocs/found/instances/{connection_id}"): ("connectors.manage",),
    ("PUT", "/api/iocs/found/instances/{connection_id}"): ("connectors.manage",),
    ("GET", "/api/incidents/{incident_id}/iocs/found"): ("read",),
    ("POST", "/api/incidents/{incident_id}/iocs/found/scan"): ("write",),
    ("POST", "/api/incidents/{incident_id}/iocs/found/remove"): ("write",),
    ("POST", "/api/incidents/{incident_id}/iocs/found/restore"): ("write",),
    ("GET", "/api/iocs"): ("read",),
    ("POST", "/api/iocs/parse"): ("read",),
    ("POST", "/api/iocs"): ("write",),
    ("PATCH", "/api/iocs/item"): ("write",),
    ("POST", "/api/iocs/tags"): ("write",),
    ("GET", "/api/iocs/lists/{list_id}/history"): ("read",),
    ("POST", "/api/iocs/remove"): ("write",),
    ("GET", "/api/iocs/lists"): ("read",),
    ("POST", "/api/iocs/lists"): ("write",),
    ("GET", "/api/iocs/lists/{list_id}"): ("read",),
    ("PATCH", "/api/iocs/lists/{list_id}"): ("write",),
    ("DELETE", "/api/iocs/lists/{list_id}"): ("write",),
    ("POST", "/api/iocs/lists/{list_id}/items"): ("write",),
    ("POST", "/api/iocs/lists/{list_id}/items/remove"): ("write",),
    ("GET", "/api/iocs/lists/{list_id}/feed"): ("read",),
    ("POST", "/api/iocs/export"): ("read",),
    ("POST", "/api/iocs/check"): ("write",),
    ("GET", "/api/iocs/checks"): ("read",),
    ("GET", "/api/iocs/checks/{check_id}"): ("read",),
    ("POST", "/api/iocs/checks/{check_id}/stop"): ("write",),
    ("POST", "/api/iocs/analyse"): ("write",),
    ("GET", "/api/iocs/alerts"): ("read",),
    ("POST", "/api/iocs/alerts/seen"): ("write",),
    ("POST", "/api/artifacts/mailboxes"): ("write",),
    ("GET", "/api/mailboxes/{mailbox_id}"): ("read",),
    ("GET", "/api/mailboxes/{mailbox_id}/messages"): ("read",),
    ("POST", "/api/mailboxes/{mailbox_id}/import"): ("write",),
    ("POST", "/api/mailboxes/{mailbox_id}/link"): ("write",),
    ("GET", "/api/incidents/{incident_id}/iocs"): ("read",),
    ("GET", "/api/iocs/lookup"): ("read",),
    ("GET", "/api/iocs/shared"): ("read",),
    ("GET", "/api/incidents/{incident_id}/iocs/export"): ("read",),
    ("GET", "/api/search"): ("read",),
    ("GET", "/api/query/schema"): "signed-in",
    ("POST", "/api/query/check"): "signed-in",
    ("POST", "/api/query"): "signed-in",
    ("POST", "/api/query/aggregate"): "signed-in",
    ("GET", "/api/automation/playbooks"): ("automation.run",),
    ("POST", "/api/automation/playbooks"): ("automation.edit",),
    ("GET", "/api/automation/playbooks/{playbook_id}"): ("automation.run",),
    ("PUT", "/api/automation/playbooks/{playbook_id}"): ("automation.edit",),
    ("DELETE", "/api/automation/playbooks/{playbook_id}"): ("automation.edit",),
    ("POST", "/api/automation/playbooks/{playbook_id}/versions"): ("automation.edit",),
    ("POST", "/api/automation/playbooks/{playbook_id}/validate"): ("automation.edit",),
    ("DELETE", "/api/automation/playbooks/{playbook_id}/draft"): ("automation.edit",),
    ("GET", "/api/automation/playbooks/{playbook_id}/branches"): ("automation.edit",),
    ("POST", "/api/automation/playbooks/{playbook_id}/branches"): ("automation.edit",),
    ("GET", "/api/automation/playbooks/{playbook_id}/branches/{branch_id}"): ("automation.edit",),
    ("PUT", "/api/automation/playbooks/{playbook_id}/branches/{branch_id}"): ("automation.edit",),
    ("DELETE", "/api/automation/playbooks/{playbook_id}/branches/{branch_id}"): ("automation.edit",),
    ("POST", "/api/automation/playbooks/{playbook_id}/branches/{branch_id}/push"): ("automation.edit",),
    ("GET", "/api/automation/playbooks/{playbook_id}/versions"): ("automation.run",),
    ("GET", "/api/automation/playbooks/{playbook_id}/versions/{number}"): ("automation.run",),
    ("POST", "/api/automation/playbooks/{playbook_id}/versions/{number}/restore"): ("automation.edit",),
    ("PUT", "/api/automation/playbooks/{playbook_id}/enabled"): ("automation.edit",),
    ("POST", "/api/automation/playbooks/{playbook_id}/run"): ("automation.run",),
    ("POST", "/api/automation/playbooks/{playbook_id}/debug"): ("automation.debug",),
    ("POST", "/api/automation/runs/{run_id}/debug"): ("automation.debug",),
    ("POST", "/api/automation/playbooks/{playbook_id}/hook"): ("automation.edit",),
    ("DELETE", "/api/automation/playbooks/{playbook_id}/hook"): ("automation.edit",),
    # The address a system outside starts a playbook at: the token in the path is the credential.
    ("POST", "/api/automation/hooks/{token}"): "public",
    ("GET", "/api/automation/playbooks/{playbook_id}/export"): ("automation.edit",),
    ("POST", "/api/automation/playbooks/import"): ("automation.edit",),
    ("GET", "/api/automation/catalog"): ("automation.run",),
    ("GET", "/api/automation/runs"): ("automation.run",),
    ("GET", "/api/automation/runs/{run_id}"): ("automation.run",),
    ("POST", "/api/automation/runs/{run_id}/stop"): ("automation.run",),
    ("POST", "/api/automation/runs/{run_id}/steps/{step_id}/resolve"): ("automation.run",),
    ("GET", "/api/automation/approvals"): ("automation.run",),
    ("POST", "/api/automation/approvals/{approval_id}"): ("automation.run",),
    ("GET", "/api/incidents/{incident_id}/runs"): ("automation.run",),
    # The field registry: read by whoever reads incidents, changed by who configures them.
    ("GET", "/api/fields"): ("read",),
    ("POST", "/api/fields"): ("incidents.configure",),
    ("GET", "/api/fields/{name}"): ("read",),
    ("PATCH", "/api/fields/{name}"): ("incidents.configure",),
    ("DELETE", "/api/fields/{name}"): ("incidents.configure",),
    ("GET", "/api/incidents/{incident_id}/fields"): ("read",),
    ("PATCH", "/api/incidents/{incident_id}/fields"): ("write",),
    ("GET", "/api/incident-types"): ("read",),
    ("POST", "/api/incident-types"): ("incidents.configure",),
    ("GET", "/api/incident-types/{type_id}"): ("read",),
    ("PUT", "/api/incident-types/{type_id}"): ("incidents.configure",),
    ("DELETE", "/api/incident-types/{type_id}"): ("incidents.configure",),
    ("GET", "/api/script-buttons/scripts"): ("incidents.configure", "automation.run"),
    ("POST", "/api/incidents/{incident_id}/script-buttons/plan"): ("automation.run",),
    ("POST", "/api/incidents/{incident_id}/script-buttons/run"): ("automation.run",),
    ("POST", "/api/incidents/{incident_id}/script-buttons/status"): ("automation.run",),
    ("GET", "/api/incidents/{incident_id}/linked"): ("read",),
    ("GET", "/api/incidents/{incident_id}/chart"): ("read",),
    ("GET", "/api/incidents/{incident_id}/context"): ("automation.run",),
    ("GET", "/api/incidents/{incident_id}/war-room"): ("read",),
    ("GET", "/api/incidents/{incident_id}/war-room/{entry_id}"): ("read",),
    ("POST", "/api/incidents/{incident_id}/war-room"): ("write",),
    ("PUT", "/api/incidents/{incident_id}/war-room/{entry_id}/tags"): ("write",),
    # A line of the War Room is a note (write) or a command (automation.run): the route sorts it out.
    ("POST", "/api/incidents/{incident_id}/war-room/command"): ("read",),
    ("GET", "/api/playground"): ("automation.run",),
    ("POST", "/api/playground/command"): ("automation.run",),
    ("GET", "/api/playground/{entry_id}"): ("automation.run",),
    ("DELETE", "/api/playground"): ("automation.run",),
    # Tasks. Completing or skipping one is for whom it is for, whatever their roles (tasks.may_complete).
    ("GET", "/api/tasks"): ("read",),
    ("GET", "/api/tasks/count"): ("read",),
    ("GET", "/api/tasks/{task_id}"): ("read",),
    ("GET", "/api/incidents/{incident_id}/work-plan"): ("read",),
    ("POST", "/api/incidents/{incident_id}/tasks"): ("write",),
    ("POST", "/api/tasks/{task_id}/complete"): ("read",),
    ("POST", "/api/tasks/{task_id}/skip"): ("read",),
    ("PUT", "/api/tasks/{task_id}/assignee"): ("write",),
    # SLA timers of an incident, and what an account was told.
    ("GET", "/api/incidents/{incident_id}/timers"): ("read",),
    ("POST", "/api/incidents/{incident_id}/timers/{field}/{what}"): ("write",),
    # Dashboards: everyone has their own; sharing one is a permission.
    ("GET", "/api/dashboards"): ("read",),
    ("POST", "/api/dashboards"): ("read",),
    ("POST", "/api/dashboards/import"): ("read",),
    ("GET", "/api/dashboards/{dashboard_id}"): ("read",),
    ("PUT", "/api/dashboards/{dashboard_id}"): ("read",),
    ("DELETE", "/api/dashboards/{dashboard_id}"): ("read",),
    ("POST", "/api/dashboards/{dashboard_id}/duplicate"): ("read",),
    ("GET", "/api/dashboards/{dashboard_id}/export"): ("read",),
    ("POST", "/api/dashboards/{dashboard_id}/report"): ("read",),
    ("PUT", "/api/dashboards/{dashboard_id}/sharing"): ("dashboards.share",),
    # Saved filters of the incident list: everyone has their own; sharing one is an administrator's.
    ("GET", "/api/filters"): ("read",),
    ("POST", "/api/filters"): ("read",),
    ("PUT", "/api/filters/default/{entity}"): ("read",),
    ("DELETE", "/api/filters/default/{entity}"): ("read",),
    ("PUT", "/api/filters/{filter_id}"): ("read",),
    ("DELETE", "/api/filters/{filter_id}"): ("read",),
    ("PUT", "/api/filters/{filter_id}/sharing"): ("admin",),
    # What the quick view of the list reads of an incident.
    ("GET", "/api/incidents/{incident_id}/quick"): ("read",),
    # Script signatures: read with the rules, changed by who manages them.
    ("GET", "/api/script-signatures"): ("read", "rules.manage"),
    ("POST", "/api/script-signatures"): ("rules.manage",),
    ("POST", "/api/script-signatures/validate"): ("rules.manage",),
    ("PUT", "/api/script-signatures/{signature_id}"): ("rules.manage",),
    ("POST", "/api/script-signatures/{signature_id}/restore"): ("rules.manage",),
    ("DELETE", "/api/script-signatures/{signature_id}"): ("rules.manage",),
    # Content packs.
    ("GET", "/api/packs"): ("content.manage",),
    ("GET", "/api/packs/items"): ("content.manage",),
    ("POST", "/api/packs/dependencies"): ("content.manage",),
    ("POST", "/api/packs/export"): ("content.manage",),
    ("POST", "/api/packs/inspect"): ("content.manage",),
    ("POST", "/api/packs/import"): ("content.manage",),
    ("GET", "/api/packs/{pack_id}/download"): ("content.manage",),
    ("DELETE", "/api/packs/{pack_id}"): ("content.manage",),
    ("GET", "/api/packs/{pack_id}/logo"): ("content.manage",),
    ("GET", "/api/packs/{pack_id}/uninstall"): ("content.manage",),
    ("POST", "/api/packs/bulk/plan"): ("content.manage",),
    ("POST", "/api/packs/bulk/apply"): ("content.manage",),
    # The catalogue of packs: reading it and taking a pack from it is for who manages content;
    # where it is read from, and the key it is trusted by, is the admin's.
    ("GET", "/api/packs/catalogue"): ("content.manage",),
    ("POST", "/api/packs/catalogue/refresh"): ("content.manage",),
    ("POST", "/api/packs/catalogue/{pack_id}/inspect"): ("content.manage",),
    ("GET", "/api/packs/catalogue/{pack_id}/logo"): ("content.manage",),
    ("PUT", "/api/packs/catalogue/address"): ("admin",),
    # Lists: read by whoever reads incidents, changed by whoever manages lists.
    ("GET", "/api/lists"): ("read",),
    ("GET", "/api/lists/{name}"): ("read",),
    ("GET", "/api/lists/{name}/export"): ("read",),
    ("POST", "/api/lists"): ("lists.manage",),
    ("PUT", "/api/lists/pointers"): ("lists.manage",),
    ("PUT", "/api/lists/{name}"): ("lists.manage",),
    ("DELETE", "/api/lists/{name}"): ("lists.manage",),
    ("PUT", "/api/lists/{name}/items"): ("lists.manage",),
    ("POST", "/api/lists/{name}/items"): ("lists.manage",),
    ("DELETE", "/api/lists/{name}/items"): ("lists.manage",),
    ("POST", "/api/lists/{name}/import"): ("lists.manage",),
    # Classifiers and mappers: whoever manages connectors.
    ("GET", "/api/mappers"): ("connectors.manage",),
    ("GET", "/api/mappers/targets"): ("connectors.manage",),
    ("PUT", "/api/mappers"): ("connectors.manage",),
    ("DELETE", "/api/mappers/{mapper_id}"): ("connectors.manage",),
    ("POST", "/api/mappers/try"): ("connectors.manage",),
    ("GET", "/api/classifiers/{connection_id}"): ("connectors.manage",),
    ("PUT", "/api/classifiers/{connection_id}"): ("connectors.manage",),
    ("POST", "/api/classifiers/try"): ("connectors.manage",),
    # Fetching: whoever manages connectors. Choosing a mirroring that sends (Out, In-out) in an instance
    # (PUT /api/automation/instances/{id}) and applying one also need automation.run: checked in the routes.
    ("GET", "/api/fetch"): ("connectors.manage",),
    ("PUT", "/api/fetch/{connection_id}"): ("connectors.manage",),
    ("POST", "/api/fetch/{connection_id}/run"): ("connectors.manage",),
    ("POST", "/api/fetch/{connection_id}/resume"): ("connectors.manage",),
    ("POST", "/api/fetch/{connection_id}/reset"): ("connectors.manage",),
    ("GET", "/api/fetch/{connection_id}/items"): ("connectors.manage",),
    ("GET", "/api/fetch/{connection_id}/sample"): ("connectors.manage",),
    ("GET", "/api/fetch/{connection_id}/mirror"): ("connectors.manage",),
    ("POST", "/api/fetch/{connection_id}/mirror/apply"): ("connectors.manage",),
    # Pre-processing rules: whoever configures incidents.
    ("GET", "/api/preprocess-rules"): ("incidents.configure",),
    ("POST", "/api/preprocess-rules"): ("incidents.configure",),
    ("PUT", "/api/preprocess-rules/order"): ("incidents.configure",),
    ("POST", "/api/preprocess-rules/try"): ("incidents.configure",),
    ("PUT", "/api/preprocess-rules/{rule_id}"): ("incidents.configure",),
    ("DELETE", "/api/preprocess-rules/{rule_id}"): ("incidents.configure",),
    # Mirroring. Starting one that sends also needs automation.run (checked in the route).
    ("GET", "/api/incidents/{incident_id}/mirror"): ("read",),
    ("POST", "/api/incidents/{incident_id}/mirror"): ("write",),
    ("PATCH", "/api/incidents/{incident_id}/mirror"): ("write",),
    ("DELETE", "/api/incidents/{incident_id}/mirror"): ("write",),
    ("POST", "/api/incidents/{incident_id}/mirror/sync"): ("write",),
    ("GET", "/api/mirror/queue"): ("connectors.manage",),
    ("POST", "/api/mirror/queue/{job_id}/retry"): ("connectors.manage",),
    ("GET", "/api/notifications"): ("read",),
    ("POST", "/api/notifications/read"): ("read",),
    ("GET", "/api/automation/connectors"): ("connectors.manage",),
    ("POST", "/api/automation/connectors"): ("connectors.manage",),
    ("POST", "/api/automation/connectors/check"): ("connectors.manage",),
    ("GET", "/api/automation/connectors/samples"): ("connectors.manage",),
    ("GET", "/api/automation/connectors/{connector_id}"): ("connectors.manage",),
    ("DELETE", "/api/automation/connectors/{connector_id}"): ("connectors.manage",),
    ("GET", "/api/automation/connectors/{connector_id}/instances"): ("connectors.manage",),
    ("GET", "/api/automation/connectors/{connector_id}/logo"): ("read",),
    ("PUT", "/api/automation/connectors/{connector_id}/logo"): ("connectors.manage",),
    ("DELETE", "/api/automation/connectors/{connector_id}/logo"): ("connectors.manage",),
    ("POST", "/api/automation/connectors/{connector_id}/instances"): ("connectors.manage",),
    ("GET", "/api/automation/instances"): ("connectors.manage", "automation.run", "automation.edit"),
    ("POST", "/api/automation/instances"): ("connectors.manage",),
    ("PUT", "/api/automation/instances/{connection_id}"): ("connectors.manage",),
    ("DELETE", "/api/automation/instances/{connection_id}"): ("connectors.manage",),
    ("POST", "/api/automation/instances/{connection_id}/test"): ("connectors.manage",),
    ("POST", "/api/automation/instances/{connection_id}/keys/test"): ("connectors.manage",),
    ("DELETE", "/api/automation/instances/{connection_id}/answers"): ("connectors.manage",),
    # Stored credentials: who manages the instances and their keys, and nobody else.
    ("POST", "/api/automation/instances/{connection_id}/credentials"): ("connectors.manage",),
    ("GET", "/api/automation/credentials"): ("connectors.manage",),
    ("POST", "/api/automation/credentials"): ("connectors.manage",),
    ("PUT", "/api/automation/credentials/{credential_id}"): ("connectors.manage",),
    ("DELETE", "/api/automation/credentials/{credential_id}"): ("connectors.manage",),
    ("GET", "/api/automation/state"): ("automation.run",),
    ("PUT", "/api/automation/state"): ("admin",),
    ("GET", "/api/automation/data-classes"): ("automation.run",),
    ("PUT", "/api/automation/playbooks/{playbook_id}/egress"): ("admin",),
    ("PUT", "/api/automation/playbooks/{playbook_id}/data-allow"): ("admin",),
    ("GET", "/api/automation/settings"): ("admin",),
    ("PUT", "/api/automation/settings"): ("admin",),
    ("GET", "/api/automation/scripts"): ("automation.edit",),
    ("POST", "/api/automation/scripts"): ("automation.edit",),
    ("GET", "/api/automation/scripts/{script_id}"): ("automation.edit",),
    ("GET", "/api/automation/scripts/{script_id}/versions/{number}"): ("automation.edit",),
    ("PUT", "/api/automation/scripts/{script_id}"): ("automation.edit",),
    ("DELETE", "/api/automation/scripts/{script_id}"): ("automation.edit",),
    ("POST", "/api/automation/scripts/{script_id}/test"): ("automation.edit",),
    ("POST", "/api/automation/scripts/{script_id}/versions"): ("automation.edit",),
    ("GET", "/api/automation/scripts/{script_id}/export"): ("automation.edit",),
    ("POST", "/api/automation/scripts/import"): ("automation.edit",),
    ("POST", "/api/incidents/{incident_id}/report"): ("read",),
    ("GET", "/api/jobs/{job_id}"): ("read",),
    # Bulk actions: who may change things or run playbooks; each action asks for its own permission.
    ("POST", "/api/incidents/bulk/plan"): ("write", "automation.run", "incidents.archive"),
    ("POST", "/api/incidents/bulk"): ("write", "automation.run", "incidents.archive"),
    ("POST", "/api/artifacts/bulk/plan"): ("write", "automation.run", "incidents.archive"),
    ("POST", "/api/artifacts/bulk"): ("write", "automation.run", "incidents.archive"),
    ("POST", "/api/iocs/bulk/plan"): ("write", "automation.run", "incidents.archive"),
    ("POST", "/api/iocs/bulk"): ("write", "automation.run", "incidents.archive"),
    ("GET", "/api/bulk"): ("read",),
    ("GET", "/api/bulk/fields"): ("read",),
    ("GET", "/api/bulk/settings"): ("admin",),
    ("PUT", "/api/bulk/settings"): ("admin",),
    ("GET", "/api/bulk/{job_id}"): ("read",),
    ("GET", "/api/bulk/{job_id}/items"): ("read",),
    ("GET", "/api/bulk/{job_id}/result.csv"): ("read",),
    ("POST", "/api/bulk/{job_id}/cancel"): ("write", "automation.run", "incidents.archive"),
    ("POST", "/api/bulk/{job_id}/retry"): ("write", "automation.run", "incidents.archive"),
    ("POST", "/api/incidents/{incident_id}/samples"): ("write",),
    ("POST", "/api/samples/{sha256}/reanalyse"): ("write",),
    ("GET", "/api/samples/{sha256}/code"): ("read",),
    ("POST", "/api/samples/{sha256}/code"): ("write",),
    ("GET", "/api/samples/{sha256}/capabilities"): ("read",),
    ("POST", "/api/samples/{sha256}/capabilities"): ("write",),
    ("GET", "/api/samples/{sha256}/code/functions/{addr}"): ("read",),
    ("GET", "/api/samples/{sha256}/code/functions/{addr}/decompiled"): ("read",),
    ("GET", "/api/samples/{sha256}"): ("read",),
    ("GET", "/api/samples/{sha256}/strings"): ("read",),
    ("GET", "/api/samples/{sha256}/download"): ("read",),
    ("DELETE", "/api/incidents/{incident_id}/samples/{sha256}"): ("write",),
    ("POST", "/api/incidents/{incident_id}/mails"): ("write",),
    ("GET", "/api/mails/{sha256}"): ("read",),
    ("POST", "/api/mails/{sha256}/reanalyse"): ("write",),
    ("GET", "/api/mails/{sha256}/source"): ("read",),
    ("GET", "/api/mails/{sha256}/attachments/{path}/bytes"): ("read",),
    ("GET", "/api/mails/{sha256}/attachments/{path}/download"): ("read",),
    ("POST", "/api/incidents/{incident_id}/mails/{sha256}/attachments/{path}/sample"): ("write",),
    ("DELETE", "/api/incidents/{incident_id}/mails/{sha256}"): ("write",),
    ("GET", "/api/previews/status"): ("read",),
    ("POST", "/api/mails/{sha256}/attachments/{path}/preview"): ("read",),
    ("POST", "/api/browser/sessions"): ("write",),
    ("POST", "/api/browser/sessions/{session_id}/action"): ("write",),
    ("GET", "/api/browser/sessions/{session_id}/network"): ("read",),
    ("DELETE", "/api/browser/sessions/{session_id}"): ("write",),
    ("POST", "/api/incidents/{incident_id}/captures"): ("write",),
    ("GET", "/api/incidents/{incident_id}/captures"): ("read",),
    ("GET", "/api/captures/{capture_id}"): ("read",),
    ("POST", "/api/captures/{capture_id}/rpc"): ("read",),
    ("GET", "/api/captures/{capture_id}/objects/download"): ("read",),
    ("POST", "/api/incidents/{incident_id}/captures/{capture_id}/objects/sample"): ("write",),
    ("GET", "/api/captures/{capture_id}/file"): ("read",),
    ("GET", "/api/captures/{capture_id}/har"): ("read",),
    ("GET", "/api/captures/{capture_id}/requests"): ("read",),
    ("GET", "/api/captures/{capture_id}/requests/{entry_id}"): ("read",),
    ("PUT", "/api/captures/{capture_id}/keylog"): ("write",),
    ("DELETE", "/api/captures/{capture_id}/keylog"): ("write",),
    ("POST", "/api/captures/{capture_id}/reanalyse"): ("write",),
    ("DELETE", "/api/incidents/{incident_id}/captures/{capture_id}"): ("write",),
    ("GET", "/api/artifacts"): ("read",),
    ("GET", "/api/artifacts/lookup"): ("read",),
    ("GET", "/api/artifacts/{artifact_id}"): ("read",),
    ("POST", "/api/artifacts/files"): ("write",),
    ("POST", "/api/artifacts/mails"): ("write",),
    ("POST", "/api/artifacts/captures"): ("write",),
    ("POST", "/api/artifacts/{artifact_id}/attachments/{path}/sample"): ("write",),
    ("POST", "/api/artifacts/{artifact_id}/objects/sample"): ("write",),
    ("POST", "/api/artifacts/{artifact_id}/links"): ("write",),
    ("POST", "/api/artifacts/{artifact_id}/analyse-as"): ("write",),
    ("DELETE", "/api/artifacts/{artifact_id}/links/{incident_id}"): ("write",),
    ("PUT", "/api/artifacts/{artifact_id}/expiry"): ("write",),
    ("PUT", "/api/artifacts/{artifact_id}/tags"): ("write",),
    ("DELETE", "/api/artifacts/{artifact_id}"): ("write",),
    ("POST", "/api/artifacts/export"): ("read",),
    ("POST", "/api/artifacts/import"): ("admin",),
    ("POST", "/api/artifacts/urls"): ("write",),
    ("GET", "/api/urls/{scan_id}"): ("read",),
    ("POST", "/api/urls/{scan_id}/rescan"): ("write",),
    ("GET", "/api/urls/{scan_id}/screenshot"): ("read",),
    ("GET", "/api/urls/{scan_id}/scripts/{index}"): ("read",),
    ("GET", "/api/urls/{scan_id}/scripts/{index}/download"): ("read",),
    ("GET", "/api/enrichment/sources"): ("read",),
    ("PUT", "/api/enrichment/guard"): ("admin",),
    ("DELETE", "/api/enrichment/old-keys/{key_id}"): ("admin",),
    ("GET", "/api/enrichment"): ("read",),
    ("GET", "/api/enrichment/raw"): ("read",),
    ("POST", "/api/enrichment/check"): ("write",),
    ("GET", "/api/samples/{sha256}/annotations"): ("read",),
    ("PUT", "/api/samples/{sha256}/annotations/{addr}"): ("write",),
    ("GET", "/api/yara-rules"): ("read", "rules.manage"),
    ("POST", "/api/yara-rules"): ("rules.manage",),
    ("PUT", "/api/yara-rules/{rule_id}"): ("rules.manage",),
    ("DELETE", "/api/yara-rules/{rule_id}"): ("rules.manage",),
    ("POST", "/api/yara-rules/validate"): ("rules.manage",),
    ("GET", "/api/flirt-signatures"): ("read", "rules.manage"),
    ("POST", "/api/flirt-signatures"): ("rules.manage",),
    ("PUT", "/api/flirt-signatures/{signature_id}"): ("rules.manage",),
    ("DELETE", "/api/flirt-signatures/{signature_id}"): ("rules.manage",),
    ("GET", "/api/capa-rules"): ("read", "rules.manage"),
    ("POST", "/api/capa-rules/validate"): ("rules.manage",),
    ("POST", "/api/capa-rules"): ("rules.manage",),
    ("PUT", "/api/capa-rules/{rule_id}"): ("rules.manage",),
    ("DELETE", "/api/capa-rules/{rule_id}"): ("rules.manage",),
    # Sigma rules (7.0): any reader lists them; changing, switching and trying them is rules.manage.
    ("GET", "/api/sigma/rules"): ("read", "rules.manage"),
    ("POST", "/api/sigma/rules"): ("rules.manage",),
    ("GET", "/api/sigma/rules/summary"): ("read", "rules.manage"),
    ("POST", "/api/sigma/rules/validate"): ("rules.manage",),
    ("POST", "/api/sigma/rules/try"): ("rules.manage",),
    ("POST", "/api/sigma/rules/bulk"): ("rules.manage",),
    ("POST", "/api/sigma/rules/recheck"): ("rules.manage",),
    ("GET", "/api/sigma/rules/{rule_id}"): ("read", "rules.manage"),
    ("PUT", "/api/sigma/rules/{rule_id}"): ("rules.manage",),
    ("PATCH", "/api/sigma/rules/{rule_id}"): ("rules.manage",),
    ("POST", "/api/sigma/rules/{rule_id}/reset"): ("rules.manage",),
    ("DELETE", "/api/sigma/rules/{rule_id}"): ("rules.manage",),
    ("GET", "/api/webhooks"): ("admin",),
    ("POST", "/api/webhooks"): ("admin",),
    ("DELETE", "/api/webhooks/{webhook_id}"): ("admin",),
    ("GET", "/api/audit"): ("audit.read",),
    ("POST", "/api/audit"): ("read",),
    ("DELETE", "/api/audit"): "admin-session",
    ("GET", "/api/audit/chain"): ("audit.read",),
    ("POST", "/api/audit/chain/verify"): ("audit.read",),
    ("GET", "/api/audit/forwarding"): ("admin",),
    ("PUT", "/api/audit/forwarding"): "admin-session",
    ("POST", "/api/audit/forwarding/test"): "admin-session",
    ("GET", "/api/health/details"): ("admin",),
    ("PUT", "/api/health/thresholds"): "admin-session",
    ("POST", "/api/health/metrics-token"): "admin-session",
    ("DELETE", "/api/health/metrics-token"): "admin-session",
    ("GET", "/api/settings"): "signed-in",
    ("PUT", "/api/settings"): ("write",),
    ("GET", "/api/backup/export"): ("admin",),
    ("POST", "/api/backup/import"): ("admin",),
    ("GET", "/api/backups"): ("admin",),
    ("PUT", "/api/backups/settings"): "admin-session",
    ("PUT", "/api/backups/passphrase"): "admin-session",
    ("GET", "/api/system/keys"): ("admin",),
    ("GET", "/api/system/keys/{name}/rotation"): ("admin",),
    ("POST", "/api/system/keys/{name}/rotation"): "admin-session",
    ("DELETE", "/api/system/keys/{name}/rotation"): "admin-session",
    ("GET", "/api/storage/encryption"): ("admin",),
    ("POST", "/api/storage/encryption"): ("admin",),
    ("POST", "/api/backups/run"): ("admin",),
    ("POST", "/api/backups/destination/test"): ("admin",),
    ("POST", "/api/backups/{backup_id}/verify"): ("admin",),
    ("DELETE", "/api/backups/{backup_id}"): "admin-session",
    ("GET", "/api/backups/{backup_id}/download"): "admin-session",
    # Recovery to a moment and the standby: reading and asking for work, like the backups.
    ("GET", "/api/recovery"): ("admin",),
    ("PUT", "/api/recovery/settings"): "admin-session",
    ("POST", "/api/recovery/base"): ("admin",),
    ("POST", "/api/recovery/test"): ("admin",),
    ("GET", "/api/storage"): ("admin",),
    ("GET", "/api/workers"): ("admin",),
}


def _routes(routes=None, prefix: str = ""):
    """Every (method, path, route) of the app, through the routers it includes."""
    for route in fastapi_app.routes if routes is None else routes:
        inner = getattr(route, "original_router", None)
        if inner is not None:  # a router included with a prefix
            yield from _routes(inner.routes, prefix + (getattr(route.include_context, "prefix", "") or ""))
            continue
        for method in sorted(getattr(route, "methods", None) or {"WEBSOCKET"}):
            if method not in ("HEAD", "OPTIONS"):
                yield method, prefix + route.path, route


def _declared(route) -> tuple[str, ...] | str:
    """The gate a route declares through its dependencies."""
    dependant = getattr(route, "dependant", None)
    found: list[tuple[str, ...] | str] = []

    def walk(node) -> None:
        if node.call is security.admin_session:
            found.append("admin-session")
            return
        if hasattr(node.call, "permissions"):
            found.append(tuple(node.call.permissions) or "signed-in")
        elif node.call is security.principal:
            found.append("signed-in")
        elif node.call is security.current_user:
            found.append("session")
        for sub in node.dependencies:
            walk(sub)

    if dependant is not None:
        walk(dependant)
    for gate in found:  # a permission wins over the plain sign-in it is built on
        if isinstance(gate, tuple) or gate == "admin-session":
            return gate
    return found[0] if found else "public"


def test_every_route_is_in_the_table_and_the_table_has_no_stale_entry():
    actual = {(method, path) for method, path, _ in _routes()}
    missing = sorted(actual - set(EXPECTED))
    assert not missing, f"routes without an entry in EXPECTED (decide who may call them): {missing}"
    stale = sorted(set(EXPECTED) - actual)
    assert not stale, f"entries of EXPECTED for routes that no longer exist: {stale}"
    for gate in EXPECTED.values():
        if isinstance(gate, tuple):
            assert gate and set(gate) <= set(PERMISSIONS), gate


def test_every_route_declares_the_gate_the_table_expects():
    wrong = {}
    for method, path, route in _routes():
        expected = EXPECTED[(method, path)]
        if expected == "first-run":  # checked by hand in the handler; see the test below
            expected = "public"
        declared = _declared(route)
        if declared != expected:
            wrong[(method, path)] = (declared, expected)
    assert not wrong, f"(declared, expected): {wrong}"


def _url(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "x", path)


@pytest.mark.parametrize("role", ROLES)
def test_each_role_reaches_what_its_permissions_allow_and_nothing_else(admin: TestClient, role: str):
    """A permission gate answers 403 before anything else is looked at, so a
    call that is let through answers something else (often 404 or 422: the
    ids and bodies sent here are made up)."""
    key = make_key(admin, label=role, roles=[role])
    granted = ROLE_PERMISSIONS[role]
    caller = TestClient(fastapi_app)
    wrong = []
    for (method, path), expected in EXPECTED.items():
        if expected in ("public", "session", "admin-session"):
            continue
        body = {} if method in ("POST", "PUT", "PATCH") else None
        if expected == "first-run":  # the handler checks the caller itself, after reading the body
            body = {"username": f"made-by-{role}", "password": "password1"}
        status = caller.request(method, _url(path), headers=key, json=body).status_code
        if expected == "signed-in":
            allowed = True
        elif expected == "first-run":
            allowed = "admin" in granted
        else:
            allowed = bool(granted & set(expected))
        if allowed and status in (401, 403):
            wrong.append((method, path, status, "should be let through"))
        if not allowed and status != 403:
            wrong.append((method, path, status, "should be refused with 403"))
    assert not wrong, wrong


def test_nothing_but_the_public_routes_answers_without_signing_in(client: TestClient):
    wrong = []
    for (method, path), expected in EXPECTED.items():
        if expected in ("public", "first-run"):
            continue
        body = {} if method in ("POST", "PUT", "PATCH") else None
        status = client.request(method, _url(path), json=body).status_code
        if status != 401:
            wrong.append((method, path, status))
    assert not wrong, wrong


def test_a_session_route_refuses_an_api_key(admin: TestClient):
    key = make_key(admin, label="adm", roles=["admin"])
    caller = TestClient(fastapi_app)
    for (method, path), expected in EXPECTED.items():
        if expected in ("session", "admin-session"):
            assert caller.request(method, _url(path), headers=key, json={}).status_code == 401, (method, path)


def test_an_admin_session_route_refuses_a_signed_in_account_that_is_no_admin(admin: TestClient):
    created = admin.post("/api/users", json={"username": "anna", "password": "password1", "roles": ["analyst"]})
    assert created.status_code == 201
    anna = TestClient(fastapi_app)
    assert anna.post("/api/auth/login", json={"username": "anna", "password": "password1"}).status_code == 200
    for (method, path), expected in EXPECTED.items():
        if expected == "admin-session":
            assert anna.request(method, _url(path), json={}).status_code == 403, (method, path)
            assert admin.request(method, _url(path), json={}).status_code not in (401, 403), (method, path)
