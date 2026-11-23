# User guide

How to do everything in Nik, screen by screen, for the analysts who use it every day.

New to Nik? Start with [Your first incident](../get-started/first-incident.md): ten minutes, start to end.

<div class="grid cards" markdown>

-   **Basics**

    ---

    The screen, the search and the filters, the dashboards.

    [Find your way around](screen.md) ·
    [Search, filters and saved views](search.md) ·
    [Dashboards and My tasks](dashboards.md)

-   **Incidents**

    ---

    Open, triage, work and close a case, alone or many at once.

    [Work an incident](incidents.md) ·
    [Summary, timeline and War Room](war-room.md) ·
    [Act on many at once](bulk.md) ·
    [Reports and exports](reports.md)

-   **Evidence**

    ---

    Bring files in and read each kind in its own page.

    [Add evidence](evidence.md) ·
    [E-mail](mail.md) ·
    [Malware](malware.md) ·
    [Network capture](network.md) ·
    [Links](url.md) ·
    [Host evidence](host.md)

-   **Indicators**

    ---

    Addresses, domains and hashes: their verdict, where else they were seen, your lists.

    [Indicators of an incident](indicators.md) ·
    [The Indicators page](indicator-library.md) ·
    [Lists and the allowlist](lists.md)

-   **Automation**

    ---

    Playbooks, scripts, commands and the products Nik talks to.

    [Your first playbook](playbooks.md) ·
    [Triggers and events](triggers.md) ·
    [Scripts and the Playground](scripts.md) ·
    [War Room commands](commands.md) ·
    [Connectors and mirroring](connectors.md) ·
    [Content packs](packs.md)

-   **Set up Nik**

    ---

    Shape Nik to your team: types of incident, rules, sources, accounts.

    [Types, fields and pages](types.md) ·
    [Detection and rules](detection.md) ·
    [Threat intelligence](threat-intel.md) ·
    [Accounts, roles and sign-in](accounts.md)

</div>

## What you can do depends on your roles

An account holds one or more roles. A button you may not use is not shown, or is greyed with the reason.

| Role | In short |
|---|---|
| Viewer | Reads everything, changes nothing. The header says **read-only**. |
| Analyst | Works incidents, evidence and indicators; runs playbooks. |
| Playbooks | Builds playbooks and scripts. |
| Connectors | Installs connectors and their instances. |
| Rules | Keeps the YARA, capa, FLIRT and script signatures. |
| Audit | Reads the audit log. |
| Dashboards | Shares dashboards. |
| Admin | Everything. |

The full table is in [Accounts, roles and sign-in](accounts.md).

## Related

- [Get started](../get-started/index.md)
- [Query language](../reference/query-language.md)
- [API](../reference/api.md)
- [Run the server](../admin/index.md)
