# Build your own

Make Nik do what your team needs: a playbook, a script, an integration with a product, or a pack that carries them to another Nik.

Each tutorial starts from nothing and ends with something that works, tested.

<div class="grid cards" markdown>

-   **A playbook from scratch**

    ---

    When a phishing incident comes in: find its indicators, check them, tag and assign it, and ask before blocking.

    [Build the playbook](playbook.md)

-   **A script**

    ---

    A piece of Python run in the sandbox, used as a node, a War Room command and a button.

    [Write the script](script.md)

-   **An integration (connector)**

    ---

    A YAML file that teaches Nik a product's HTTP API: commands, alerts fetched as incidents, mirroring.

    [Write the connector](connector.md)

-   **A content pack**

    ---

    Connectors, playbooks, scripts, mappers and lists in one file, installed and updated on any Nik.

    [Make the pack](pack.md)

</div>

## Which one?

| You want to… | Build | Because |
| --- | --- | --- |
| React to something that happens in Nik, in several steps, with a person deciding at some point | A **playbook** | It is started by an event, a schedule, a request or a person, and can wait, ask, loop and handle errors |
| Compute something the expression language cannot (parse a format, group, score, compare two lists) | A **script** | Free Python, in a sandbox with no network: it only computes on what it is given |
| Talk to a product Nik does not know (read, change, bring its alerts in, keep tickets in step) | A **connector** | The only way to reach another system with its credentials; its commands become nodes and War Room commands |
| Give all of that to another Nik, or keep it in a repository with versions | A **pack** | One file, inspected item by item before it is installed, updated by version |

!!! tip "They build on each other"
    A script does not reach the network: a connector does. A connector does nothing by itself: a playbook or a War Room command runs its commands. A pack carries them all. A typical integration is all four: a connector for the product, a script for what its answers need, a playbook that uses both, in a pack.

What each needs:

| Build | Role |
| --- | --- |
| Playbook, script | **Playbooks** (or **Admin**) |
| Connector, instance | **Connectors** (or **Admin**) |
| Pack | **Admin** (`content.manage`) |
| Opening hosts or classes of data for a playbook | **Admin** |

## Related

- [Your first playbook](../playbooks.md)
- [Playbook nodes and expressions](../../reference/playbook-nodes.md)
- [Connector and pack format](../../reference/connector-format.md)
- [Events](../../reference/events.md)
