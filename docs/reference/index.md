# Reference

The exact details: every variable, the query language, the playbook nodes, the events, the file formats, the API, and how Nik is built and secured.

<div class="grid cards" markdown>

-   :material-tune-variant: **[Environment variables](configuration.md)**

    ---

    Every variable of the backend, the Compose file, the workers (the forensics worker too) and the scripts, with its default.

-   :material-magnify: **[Query language](query-language.md)**

    ---

    The syntax of the search box, saved views, dashboards and the API.

-   :material-sitemap: **[Playbook nodes and expressions](playbook-nodes.md)**

    ---

    Every node of the playbook editor and the `{{ }}` expression language.

-   :material-lightning-bolt: **[Events](events.md)**

    ---

    The events that start playbooks and webhooks, and what each carries, `evidence.detected` included.

-   :material-package-variant: **[Connector and pack format](connector-format.md)**

    ---

    The YAML of a connector and the layout of a content pack, with its Sigma rules.

-   :material-api: **[API](api.md)**

    ---

    Authentication, API keys, conventions, the main routes, host evidence (records, uploads in parts, Sigma rules, archive), bulk jobs and uploads.

-   :material-shield-lock: **[Security](security.md)**

    ---

    The threat model, how hostile content and host evidence are contained, what leaves the server, the hardening checklist.

-   :material-layers-triple: **[Architecture](architecture.md)**

    ---

    What runs where, the services, the data model, how each analysis works, how host evidence is read.

-   :material-code-braces: **[Developer guide](developer.md)**

    ---

    Local development, tests, and how to extend Nik: a parser of host evidence, Sigma log sources, tabs, automation.

</div>

## Related

- [User guide](../guide/index.md) — how to work in Nik
- [Run the server](../admin/index.md) — install, back up, upgrade, try a release on a copy
- [Changelog](../changelog.md)
