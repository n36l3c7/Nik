# SentinelOne SIEM

The Singularity Data Lake of SentinelOne (its SIEM) and the alerts of the Singularity Operations Center. This
connector runs searches in the Data Lake and brings the alerts in as incidents. It has 5 commands.

The queries were written from SentinelOne's own reference of the API, the one the console shows to a signed-in
user; the alerts are not in that reference (see below). Nothing here was run against a real console: the
connector says `verified: false` until someone has.

Deep Visibility, the custom detection rules (STAR) and the alerts those rules raise are commands of the other
connector, **SentinelOne EDR**: they are part of the Management API, which takes the token another way.

## The token

The API token of a **service user** of the console (Settings, Users, Service Users), sent as a bearer token, as
the reference asks for the Data Lake. Its scope is an account or a site: the Data Lake refuses a token of global
scope. It needs the permission to search events, and to view and update alerts.
An instance can take the token from a stored credential (Settings, Automation, Credentials) instead of holding it
itself.

No command of this connector keeps a file. The files of an endpoint (the file of a threat, fetched files, the
output of a script, a forensic collection) are commands of SentinelOne EDR, which unpacks the archives the agents
upload with the password the request set.

## Commands

| Command | What it does | |
| --- | --- | --- |
| `run-query` | Run a PowerQuery over a time range and read the rows it gives: `columns`, `rows`, `matches`, `count`. | |
| `search-events` | The events that match a filter over a time range, in order of time, as the Event Search lists them. | |
| `list-saved-searches` | The searches saved in the Event Search, private to the token's user or shared in its scope. | |
| `get-alert` | One alert of the Singularity Operations Center. | |
| `update-alert` | Set the status of an alert: NEW, IN_PROGRESS, RESOLVED, FALSE_POSITIVE. | Changes |

A query is launched, asked for every two seconds until all its steps are done (280 seconds at most), then deleted,
as the reference asks. The Data Lake answers a query from the server that started it: the tag it gives at launch
(`X-Dataset-Query-Forward-Tag`) is sent back with the following requests. A low priority is asked for, which has
the more generous limits.

The reference says the result of a query is "an object" and describes it no further. The columns and the rows of
a PowerQuery are read where SentinelOne's own code on GitHub (purple-mcp) reads them; `search-events` gives the
result as it comes, in `data`.

## What an alert comes in as

Fetching asks for the alerts detected since five minutes before the last one it read, 100 at a time. Nothing
public says in what order the alerts come nor how to ask for an order: where more than 100 alerts are detected
between two cycles, some are not read. The mapper makes an incident with the name, the description, the severity
and the status of the alert, and the alert and the host in the context.

## Left out on purpose

- **Data tables and writing saved searches**: they configure the Data Lake, which a playbook has no reason to do.
- **The other kinds of query** the same API launches (facet values, top facets, plots, distributions): they draw
  the charts of the console. A PowerQuery counts and groups what a playbook needs.

## What the reference does not say

- **The alerts.** `/web/api/v2.1/unifiedalerts/graphql` is not in the reference. `get-alert` and the fetch are
  written from SentinelOne's own code on GitHub; `update-alert` (the mutation and the ids of its actions) from
  the Cortex XSOAR integration, the only public source for it. These are the least certain parts of the two
  packs.
- **The result of a query**, as said above.

## Mirroring (new in 1.2, needs Nik 6.10)

In the *Fetch* part of an instance, *Mirroring* says which way the incidents it fetches are kept in step with their
alerts: *None* (as before), *In*, *Out* or *In-out*. The object is the alert the incident was made from, by its id.
Only the two commands this connector already had for one alert are used; mirroring makes no other request.

| | What | With |
| --- | --- | --- |
| In | the alert is read again every two minutes and goes through the incoming mapper as a fetched one does: its name, description, severity and **status** | `get-alert` |
| Out | the status of the incident is set as the status of the alert | `update-alert` |

How the two vocabularies meet is in the mappers of the pack, which are yours to change:

| SentinelOne | Nik |
| --- | --- |
| status `NEW` · `IN_PROGRESS` · `RESOLVED` | status open · in progress · closed (both ways) |
| status `FALSE_POSITIVE` | closed, with the close reason *False positive* (both ways) |

Things to know:

- **No notes.** `get-alert` asks for no notes of an alert, and nothing that could be read says how to ask for
  them or how to add one: comments are not mirrored either way. A note tagged `mirror` is not sent.
- **Out is the less certain half.** `update-alert` is known from the Cortex XSOAR integration only (see above). It
  is the same request the command made before this version; setting a status twice leaves the alert as setting it
  once, so an update cut by a restart is sent again. Try it on a test alert first.
- An alert the console answers nothing for (`alert: null`) is taken as gone: it is said once on the incident and
  read no more. What the console really answers for an alert that was deleted is not written anywhere that could
  be read.
- A field a person set in Nik is kept when the alert says otherwise, unless the mapper marks it as winning over
  edits.
- With these mappers, an alert that is already in progress or resolved when it is fetched makes an incident that
  starts so, as before.
