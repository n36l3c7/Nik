# VirusTotal

VirusTotal analyses files, URLs, domains and IP addresses with over 70 antivirus engines and
blocklisting services, and keeps what it learnt of each: detections, relationships between indicators, sandbox
behaviour, what the community said. This connector gives its API v3 to playbooks: 258 commands.

It was written from VirusTotal's API reference (<https://docs.virustotal.com/reference/overview>), one
endpoint after the other, and **was not run against the service**: it is marked "not verified" until someone
runs "Test the connection" and the commands they need with a real key.

## The key

An instance asks for one thing: the **API key** of a VirusTotal account. Sign up at
<https://www.virustotal.com/gui/join-us>, then open the user menu (top right) and choose *API key*. The key
is sent in the `x-apikey` header and carries every privilege of the account: a playbook can do with it what
the account can.

Every request goes to `www.virustotal.com`. A download may be answered with a redirect to a signed address
on VirusTotal's storage: it is followed to `vtsamples.commondatastorage.googleapis.com`, the one storage host
the reference shows, and the key is never sent there (see *Files*). Whatever is looked up or submitted through the public API is
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
Beside `count` (how many were read) and `truncated`, a list gives `total`: how many VirusTotal says there
are (`meta.count` of the first page), empty when the answer does not say.
Code Insights (`analyse-code`) has a limit of its own, 50 requests a day.

## Verdicts

`get-file-report`, `get-url-reputation`, `get-domain-report` and `get-ip-report` are the reputation commands
(`!file`, `!url`, `!domain` and `!ip` in the War Room ask them too). Their `verdict` is derived from
`last_analysis_stats` as Nik's own look-up code did:

- **malicious**: 3 engines or more say malicious;
- **suspicious**: 1 or 2 say malicious, or any says suspicious;
- **harmless**: none of the above, and at least one engine says harmless;
- **unknown**: nothing else, or VirusTotal does not have the indicator (a 404 is an answer here, not a
  failure).

`summary` is the line Nik's own look-up writes: `7/88 engines flag it, 1 suspicious` (those that say
malicious over all that answered, then the suspicious ones when there are any), or `not in VirusTotal`.
In version 1 of this connector it read "7 malicious, 1 suspicious, 60 harmless, 20 undetected"; the counts
are still there one by one (`malicious`, `suspicious`, `harmless`, `undetected`, and `total`).

Beside the verdict, each of these commands gives what the look-up shows:

- `engines`: the engines that flag the indicator, as `{engine, category, result}`, those that say malicious
  first, each group by name (capital letters before small ones); `all_engines`: every engine, those first;
- `stats`, `total`, `reputation`, `last_analysis` (milliseconds), `tags` (12 at most), `link` (the page of
  the indicator in VirusTotal's interface, also when VirusTotal does not have it);
- an address: `country`, `asn`, `owner`, `network`;
- a domain: `registrar`, `created`, `categories`;
- a URL: `categories`, `final_url`, `title`, `http_status`, `url`;
- a file: `name`, `names` (8 at most), `type`, `size`, `label` (the suggested threat label), `signer`,
  `created`, `first_seen`, `last_seen`;
- `attributes`: everything VirusTotal answered, as it came.

Resolutions, communicating files, contacted domains and addresses, and comments are commands of their own
(`list-ip-related-objects`, `list-file-related-objects`, `list-file-comments`…): one request each.

A URL report is asked for by an identifier: the SHA-256 of the canonical URL, or the URL in base64 without
padding. `get-url-reputation` takes the URL and computes the second (`GET /urls/{id}`, as Nik's own look-up
does; in version 1 it asked the search endpoint). `get-url-report` takes the identifier (the `id` a report
or a search result gives, or the part between `u-` and the last `-` of an analysis id) and gives the same
outputs.

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

## Files

Three commands send a file Nik holds, named by its artifact (`file-<sha256>`) or its SHA-256: `scan-file`
(the file joins VirusTotal's dataset), `scan-private-file` and `upload-monitor-file`. Each asks a person
first, as every command that changes something outside does, and the data guard judges the file before it
leaves. The reference takes 32 MB at most this way: for a larger file (650 MB at most, and no more than Nik
itself accepts as an upload) ask `get-file-upload-url`, `get-private-file-upload-url` or
`get-monitor-upload-url` first and give the address to the `upload_url` argument. In the reference that
address is on `www.virustotal.com`, is good for one upload, and takes the same request, key included. Its
example begins with `http://`: Nik sends nothing over plain HTTP, and refuses an address on another host
than the instance's with a message that names it.

The `download-…` commands keep what VirusTotal answers as an artifact of Nik, with its name, type, size and
SHA-256. Nothing opens, unpacks or runs it: a sample stays a sample, a ZIP keeps its password, a feed batch
stays compressed (bzip2: one JSON object a line; a `.tar.bz2` of 60 of them for an hour).

- `download-file`: a sample, by its hash.
- `download-file-behaviour-pcap`, `-evtx`, `-memdump`: what a sandbox run left; the same three for a private
  file (`download-private-file-behaviour-…`) and for a run of the behaviour feed (`download-feed-behaviour-…`,
  by the token the feed gives).
- `download-zip-file`, `download-private-zip-file`: a ZIP made with `create-zip-file` or
  `create-private-zip-file`, once `wait-for-zip-file` or `wait-for-private-zip-file` says it is finished.
- `download-monitor-item`, `download-monitor-partner-file`, `download-monitor-partner-bundle` (the daily CSV
  of an engine; `date` for an earlier day).
- `download-feed-file`: a file of the file feed, by the token of its `download_url`.
- `download-file-feed`, `download-file-behaviour-feed`, `download-domain-feed`, `download-ip-feed`,
  `download-url-feed`, and each with `-hourly`: a batch of a feed. `time` is the minute (`YYYYMMDDhhmm`) or
  the hour (`YYYYMMDDhh`) in UTC; left empty it is the latest the reference says exists, 60 minutes or 2
  hours ago. A minute that has no batch answers 404 and the step fails: the reference says to go on with the
  next minute.

The reference says that `GET /files/{id}/download`, the two ZIP downloads and the feed batches answer with a
redirect to a signed address, and shows such an address once: on
`vtsamples.commondatastorage.googleapis.com`, for a file. That host is the only other one the connector may
reach, and a redirect is followed only to it; the key is not sent with the redirected request. The reference
does not name the host of a ZIP file, of a feed batch or of a Monitor file, and does not say whether the
PCAP, EVTX, memory dump, feed file and Monitor downloads redirect at all. If one of them redirects elsewhere, the step
fails and its message names the host: that is the name to add to `more_hosts` in the connector file. The
commands that give the signed address itself (`get-file-download-url`, `get-zip-file-download-url`…) are
still here.

## Waiting for a result

A scan answers at once with the id of an analysis. `scan-url` (or `rescan-file`, `rescan-url`…) then
`wait-for-analysis` gives the result when it is completed, without holding a worker in between;
`get-analysis` reads it as it is now. The same pair exists for ZIP files (`create-zip-file`,
`wait-for-zip-file`), Retrohunt jobs, private analyses and operations. Between two tries a command waits the seconds its poll
says, or longer when VirusTotal's answer carries a `Retry-After` header: Nik honours it by itself.

## Commands that need a paid plan

139 commands are marked *premium*: the reference gives them to paying users only, or they belong to a
product sold apart. Nik does not enforce it: VirusTotal refuses a key without the privilege.

- **Ports and services**: `list-ip-technologies`, `get-port-info`, `list-port-info-related-objects`, `list-port-info-related-descriptors`, `get-port-analysis`, `list-port-analysis-related-objects`, `list-port-analysis-related-descriptors`.
- **Sample download**: `get-file-download-url`, `download-file`.
- **What a sandbox run left**: `download-file-behaviour-pcap`, `download-file-behaviour-evtx`, `download-file-behaviour-memdump`.
- **Intelligence search**: `search-intelligence`, `get-search-snippet`.
- **Collections: listing, exports and search**: `list-collections`, `export-collection-iocs`, `export-collection-related-iocs`, `export-collection-aggregations`, `search-collection-iocs`.
- **ZIP files of samples**: `create-zip-file`, `get-zip-file`, `wait-for-zip-file`, `get-zip-file-download-url`, `download-zip-file`.
- **Livehunt**: `list-livehunt-rulesets`, `create-livehunt-ruleset`, `delete-all-livehunt-rulesets`, `get-livehunt-ruleset`, `update-livehunt-ruleset`, `check-livehunt-ruleset-editor`, `revoke-livehunt-ruleset-editor`, `delete-livehunt-ruleset`, `list-livehunt-ruleset-related-objects`, `list-livehunt-ruleset-related-descriptors`, `grant-livehunt-ruleset-editors`, `transfer-livehunt-ruleset`, `list-livehunt-notifications`, `delete-livehunt-notifications`, `get-livehunt-notification`, `delete-livehunt-notification`, `list-livehunt-notification-files`.
- **Retrohunt**: `list-retrohunt-jobs`, `create-retrohunt-job`, `get-retrohunt-job`, `wait-for-retrohunt-job`, `delete-retrohunt-job`, `abort-retrohunt-job`, `list-retrohunt-job-matches`.
- **Private scanning**: `list-private-files`, `get-private-file-upload-url`, `scan-private-file`, `rescan-private-file`, `get-private-file-report`, `delete-private-file`, `list-private-file-related-objects`, `list-private-file-related-descriptors`, `list-private-analyses`, `get-private-analysis`, `wait-for-private-analysis`, `list-private-analysis-related-objects`, `list-private-analysis-related-descriptors`, `get-private-file-behaviour`, `list-private-file-behaviours`, `list-private-file-behaviour-related-objects`, `list-private-file-behaviour-related-descriptors`, `get-private-file-behaviour-summary`, `get-private-file-mitre-trees`, `get-private-file-behaviour-html`, `download-private-file-behaviour-pcap`, `download-private-file-behaviour-evtx`, `download-private-file-behaviour-memdump`, `scan-private-url`, `get-private-url-report`, `list-private-url-related-objects`, `list-private-url-related-descriptors`, `create-private-zip-file`, `get-private-zip-file`, `wait-for-private-zip-file`, `get-private-zip-file-download-url`, `download-private-zip-file`.
- **Feeds** (a licence for each feed): `get-feed-behaviour-html`, `download-feed-behaviour-pcap`, `download-feed-behaviour-evtx`, `download-feed-behaviour-memdump`, `download-feed-file`, `download-file-feed`, `download-file-feed-hourly`, `download-file-behaviour-feed`, `download-file-behaviour-feed-hourly`, `download-domain-feed`, `download-domain-feed-hourly`, `download-ip-feed`, `download-ip-feed-hourly`, `download-url-feed`, `download-url-feed-hourly`.
- **Groups, quotas, service accounts and the audit log**: `get-group`, `update-group`, `list-group-administrators`, `update-group-user-roles`, `check-group-administrator`, `list-group-users`, `check-group-member`, `remove-group-user`, `add-group-users`, `list-group-related-objects`, `list-group-related-descriptors`, `get-group-api-usage`, `list-group-quota-consumers`, `create-service-account`, `list-service-accounts`, `get-service-account`, `update-service-accounts`, `list-activity-log`.
- **VT Monitor, for software publishers**: `list-monitor-items`, `create-monitor-folder`, `upload-monitor-file`, `get-monitor-upload-url`, `get-monitor-item`, `delete-monitor-item`, `update-monitor-item-details`, `get-monitor-item-download-url`, `download-monitor-item`, `list-monitor-item-analyses`, `get-monitor-item-owner`, `list-monitor-item-comments`, `list-monitor-statistics`, `list-monitor-events`.
- **VT Monitor, for antivirus partners**: `list-monitor-partner-hashes`, `list-monitor-partner-hash-analyses`, `list-monitor-partner-hash-items`, `add-monitor-partner-hash-comment`, `get-monitor-partner-comment`, `update-monitor-partner-comment`, `delete-monitor-partner-comment`, `get-monitor-partner-file-download-url`, `download-monitor-partner-file`, `get-monitor-partner-bundle-download-url`, `download-monitor-partner-bundle`, `list-monitor-partner-statistics`.

`scan-file` is not among them: the reference does not reserve it. Among the others, some answers are fuller
for a paying account (submission details, more relationships), and the group commands need an account that
belongs to a group.

## What is not here

- Granting view or edit rights on a graph (`POST /graphs/{id}/relationships/viewers` and `…/editors`): the
  reference does not say what the request holds. Reading, checking and revoking those rights are here.
- A file is sent and kept whole, never read: a feed batch is not unpacked into its lines, and a ZIP is not
  opened. What is inside is for a script or another tool to read.
- A download whose signed address is on a host the reference does not name (see *Files*): the command is
  here, and fails with the name of the host until that host is added.
