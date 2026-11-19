# VirusTotal

VirusTotal analyses files, URLs, domains and IP addresses with over 70 antivirus engines and
blocklisting services, and keeps what it learnt of each: detections, relationships between indicators, sandbox
behaviour, what the community said. This connector gives its API v3 to playbooks: 229 commands.

It was written from VirusTotal's API reference (<https://docs.virustotal.com/reference/overview>), one
endpoint after the other, and **was not run against the service**: it is marked "not verified" until someone
runs "Test the connection" and the commands they need with a real key.

## The key

An instance asks for one thing: the **API key** of a VirusTotal account. Sign up at
<https://www.virustotal.com/gui/join-us>, then open the user menu (top right) and choose *API key*. The key
is sent in the `x-apikey` header and carries every privilege of the account: a playbook can do with it what
the account can.

Every request goes to `www.virustotal.com`. Whatever is looked up or submitted through the public API is
added to VirusTotal's dataset and can be seen by its community: do not send indicators that hold
confidential or personal information.

## What a free key gives

VirusTotal states these limits for the public API:

- **500 requests a day, 4 requests a minute**;
- it must not be used in commercial products or services, nor in business workflows that do not contribute
  new files;
- several accounts must not be registered to get round the limits.

A request refused for the rate (429) is tried again by Nik. A list read page by page spends one request for
each page: the commands read 5 pages at most, of 10 items (40 where the reference says a page may hold 40).
Code Insights (`analyse-code`) has a limit of its own, 50 requests a day.

## Verdicts

`get-file-report`, `get-url-reputation`, `get-domain-report` and `get-ip-report` are the reputation commands
(`!file`, `!url`, `!domain` and `!ip` in the War Room ask them too). Their `verdict` is derived from
`last_analysis_stats` as Nik's own enrichment does:

- **malicious**: 3 engines or more say malicious;
- **suspicious**: 1 or 2 say malicious, or any says suspicious;
- **harmless**: none of the above, and at least one engine says harmless;
- **unknown**: nothing else, or VirusTotal does not have the indicator (a 404 is an answer here, not a
  failure).

`summary` counts the engines by what they said. A URL report is asked for by an identifier (the SHA-256 of
the canonical URL, or the URL in base64 without padding) that an expression cannot compute: so
`get-url-reputation` asks the search endpoint, which takes the URL as it is, and `get-url-report` takes the
identifier (the `id` of a search result, or the part between `u-` and the last `-` of an analysis id).

## Relationships

VirusTotal links its objects: the domains a file contacted, the files downloaded from a URL, the
resolutions of an IP address. The API has two endpoints for each kind of object, and so does the connector,
with the relationship as a choice:

- `list-<object>-related-objects`: the related objects, whole;
- `list-<object>-related-descriptors`: their type and id only (cheaper to read).

`<object>` is one of `file`, `url`, `domain`, `ip`, `comment`, `analysis`, `file-behaviour`, `collection`,
`graph`, `saved-search`, `user`, `group`, `attack-tactic`, `attack-technique`, `yara-rule`,
`livehunt-ruleset`, `port-info`, `port-analysis`, and the `private-…` ones. A relationship that holds one
object (the parent of a domain, the owner of a graph) comes back as a list of one. The choices are the
relationships the reference documents; `get-metadata` gives the full list VirusTotal has. Many relationships
of files, URLs, domains and IP addresses are for VirusTotal Enterprise users only (for a file: everything
but behaviours, bundled_files, collections, comments, contacted_domains, contacted_ips, contacted_urls,
dropped_files, execution_parents, graphs, pe_resource_children, pe_resource_parents and votes): a free key
is refused those.

## Waiting for a result

A scan answers at once with the id of an analysis. `scan-url` (or `rescan-file`, `rescan-url`…) then
`wait-for-analysis` gives the result when it is completed, without holding a worker in between;
`get-analysis` reads it as it is now. The same pair exists for ZIP files (`create-zip-file`,
`wait-for-zip-file`), Retrohunt jobs, private analyses and operations.

## Commands that need a paid plan

111 commands are marked *premium*: the reference gives them to paying users only, or they belong to a
product sold apart. Nik does not enforce it: VirusTotal refuses a key without the privilege.

- **Ports and services**: `list-ip-technologies`, `get-port-info`, `list-port-info-related-objects`, `list-port-info-related-descriptors`, `get-port-analysis`, `list-port-analysis-related-objects`, `list-port-analysis-related-descriptors`.
- **Sample download**: `get-file-download-url`.
- **Intelligence search**: `search-intelligence`, `get-search-snippet`.
- **Collections: listing, exports and search**: `list-collections`, `export-collection-iocs`, `export-collection-related-iocs`, `export-collection-aggregations`, `search-collection-iocs`.
- **ZIP files of samples**: `create-zip-file`, `get-zip-file`, `wait-for-zip-file`, `get-zip-file-download-url`.
- **Livehunt**: `list-livehunt-rulesets`, `create-livehunt-ruleset`, `delete-all-livehunt-rulesets`, `get-livehunt-ruleset`, `update-livehunt-ruleset`, `check-livehunt-ruleset-editor`, `revoke-livehunt-ruleset-editor`, `delete-livehunt-ruleset`, `list-livehunt-ruleset-related-objects`, `list-livehunt-ruleset-related-descriptors`, `grant-livehunt-ruleset-editors`, `transfer-livehunt-ruleset`, `list-livehunt-notifications`, `delete-livehunt-notifications`, `get-livehunt-notification`, `delete-livehunt-notification`, `list-livehunt-notification-files`.
- **Retrohunt**: `list-retrohunt-jobs`, `create-retrohunt-job`, `get-retrohunt-job`, `wait-for-retrohunt-job`, `delete-retrohunt-job`, `abort-retrohunt-job`, `list-retrohunt-job-matches`.
- **Private scanning**: `list-private-files`, `get-private-file-upload-url`, `rescan-private-file`, `get-private-file-report`, `delete-private-file`, `list-private-file-related-objects`, `list-private-file-related-descriptors`, `list-private-analyses`, `get-private-analysis`, `wait-for-private-analysis`, `list-private-analysis-related-objects`, `list-private-analysis-related-descriptors`, `get-private-file-behaviour`, `list-private-file-behaviours`, `list-private-file-behaviour-related-objects`, `list-private-file-behaviour-related-descriptors`, `get-private-file-behaviour-summary`, `get-private-file-mitre-trees`, `get-private-file-behaviour-html`, `scan-private-url`, `get-private-url-report`, `list-private-url-related-objects`, `list-private-url-related-descriptors`, `create-private-zip-file`, `get-private-zip-file`, `wait-for-private-zip-file`, `get-private-zip-file-download-url`.
- **Feeds**: `get-feed-behaviour-html`.
- **Groups, quotas, service accounts and the audit log**: `get-group`, `update-group`, `list-group-administrators`, `update-group-user-roles`, `check-group-administrator`, `list-group-users`, `check-group-member`, `remove-group-user`, `add-group-users`, `list-group-related-objects`, `list-group-related-descriptors`, `get-group-api-usage`, `list-group-quota-consumers`, `create-service-account`, `list-service-accounts`, `get-service-account`, `update-service-accounts`, `list-activity-log`.
- **VT Monitor, for software publishers**: `list-monitor-items`, `create-monitor-folder`, `get-monitor-upload-url`, `get-monitor-item`, `delete-monitor-item`, `update-monitor-item-details`, `get-monitor-item-download-url`, `list-monitor-item-analyses`, `get-monitor-item-owner`, `list-monitor-item-comments`, `list-monitor-statistics`, `list-monitor-events`.
- **VT Monitor, for antivirus partners**: `list-monitor-partner-hashes`, `list-monitor-partner-hash-analyses`, `list-monitor-partner-hash-items`, `add-monitor-partner-hash-comment`, `get-monitor-partner-comment`, `update-monitor-partner-comment`, `delete-monitor-partner-comment`, `get-monitor-partner-file-download-url`, `get-monitor-partner-bundle-download-url`, `list-monitor-partner-statistics`.

Among the others, some answers are fuller for a paying account (submission details, more relationships),
and the group commands need an account that belongs to a group.

## What is not here

The connector format sends and reads text and JSON, not files. These endpoints of the reference are
therefore left out:

- uploading a file: `POST /files`, `POST /private/files`, and a file to `POST /monitor/items`
  (`create-monitor-folder` covers the folder case; the commands that give an upload address are here);
- downloading a file as it is: `GET /files/{id}/download`, the PCAP, EVTX and memory dump of a sandbox
  run (public, private and feed), the two ZIP downloads, the Monitor downloads and the daily detections
  bundle. The commands that give a signed download address are here: the address is on another host, to be
  fetched by another step;
- the feed batches (`/feeds/files`, `file_behaviours`, `domains`, `ip_addresses`, `urls`, by the minute and
  by the hour): they are compressed archives behind a redirect;
- granting view or edit rights on a graph (`POST /graphs/{id}/relationships/viewers` and `…/editors`): the
  reference does not say what the request holds.
