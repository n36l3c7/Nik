# GreyNoise

GreyNoise runs sensors across the internet and records who scans and attacks
everything: the addresses that are "noise", what they look for, and which of
them are harmless (search engines, security researchers) or malicious. It
also keeps the list of the addresses of common business services (BSI, once
called RIOT), which are rarely worth an alert.

This connector asks GreyNoise about an address and reads the rest of its
API: GNQL searches, CVEs and tags, callback addresses, blocklists, event
feeds, Threat Briefs, the sessions and detections of your own sensors, and
the files GreyNoise gives for download (captures, the list of business
services, the Psychic models). It has 75 commands.

## The key

The API key of a GreyNoise account, sent in the `key` header. Sign up at
[viz.greynoise.io](https://viz.greynoise.io/); the key is in the account.

The key is optional. Without one, only `get-community-ip`,
`get-public-rss-feed` and `ping` are of use: GreyNoise answers the Community
API to anyone, a few addresses a day. An instance that has no key sends no
`key` header at all.

## The free plan

As GreyNoise states it for the Community API:

- without a key, a limited number of look-ups a day, after which it answers
  429;
- with the key of a free account, 50 searches a week, counted together with
  the searches made in the Visualizer;
- an account created with a free e-mail address (Gmail, Hotmail, ProtonMail,
  iCloud and the like) has no access with an API key.

`get-community-ip` is the command `!ip` asks. Its verdict and its summary
are the ones Nik's own look-up code gave for GreyNoise, and the rule is
written in the file:

| What GreyNoise answers | Verdict | Summary |
| --- | --- | --- |
| 404, or an answer that holds nothing | unknown | not seen scanning the internet |
| `riot` is set | harmless | common business service (*name*), or (known) when it gives no name |
| `classification` is `malicious` | malicious | malicious internet scanner (*name*) |
| `classification` is `benign` | harmless | benign internet scanner (*name*) |
| anything else | unknown | *classification* internet scanner (*name*) |

In the last three rows the summary is "not seen scanning the internet" when
`noise` is not set, and the name is left out when GreyNoise gives none or
says "unknown". The link is the page of the address in the Visualizer.

## Commands that need a paid plan

Every command except `get-community-ip`, `ping`, `get-public-rss-feed` and
`list-tags` is marked as needing a paid plan. Many need, beyond a plan, one
entitlement or add-on module: where the reference names it, the description
of the command says so.
GreyNoise answers 403 to a key that may not use an endpoint; when the plan
gives only a part, the answer names the fields left out (`restricted_fields`)
or the query that was run in place of yours (`adjusted_query`).

| Group | Commands |
| --- | --- |
| IP look-up | `get-ip`, `get-ips`, `get-ip-timeline` |
| GNQL | `search-gnql`, `search-gnql-metadata`, `get-gnql-stats`, `count-gnql`, `export-gnql-ips`, `validate-gnql`, `list-gnql-fields` |
| Recall | `get-gnql-timeseries`, `get-gnql-timeseries-stats` |
| CVEs and tags | `list-cves`, `get-cves`, `get-cve`, `get-tag-activity` |
| Compare | `diff-workspaces`, `diff-workspace-stats`, `start-unique-ips-job`, `get-unique-ips-job` |
| Callback | `get-callback-ip`, `list-callback-ips`, `export-callback-ips`, `get-callback-overview` |
| IOC feeds | `download-gnql-file`, `get-gnql-file-metadata`, `delete-gnql-file-subscription`, `list-feed-profiles`, `download-callback-file`, `get-callback-file-metadata` |
| Sessions | `search-sessions`, `list-session-fields`, `count-sessions`, `get-session-connections`, `get-session-timeseries`, `get-session-unique-values`, `get-session`, `download-session-pcap`, `download-sessions-pcap`, `export-session-data` |
| Business services | `get-bsi-trust-stats`, `get-bsi-company-stats`, `get-bsi-category-stats`, `get-bsi-ip`, `get-bsi-ips`, `download-bsi-file` |
| Blocklists | `create-blocklist`, `list-blocklists`, `update-blocklist`, `get-blocklist`, `delete-blocklist`, `get-blocklist-ips` |
| Event feeds | `search-feed-events`, `fetch-feed-events`, `acknowledge-feed-events`, `list-feed-consumers`, `create-feed-consumer`, `reset-feed-consumer`, `delete-feed-consumer` |
| Threat Briefs | `list-articles`, `list-article-categories`, `get-article`, `get-rss-feed-url`, `generate-rss-feed-url` |
| Tactics | `search-tactics-detections`, `get-tactics-detection`, `list-tactics-destination-ips`, `list-tactics-files`, `get-host-artifact-content` |
| Psychic | `download-psychic-model`, `download-psychic-snapshot` |

`list-tags` is not marked: the reference states no plan for it. Whether the
key of a free account may read it was not confirmed.

## Commands that change something at GreyNoise

`create-blocklist`, `update-blocklist`, `delete-blocklist`,
`acknowledge-feed-events`, `create-feed-consumer`, `reset-feed-consumer`,
`delete-feed-consumer`, `generate-rss-feed-url` (the old feed address stops
working) and `delete-gnql-file-subscription`. `download-gnql-file` and
`get-gnql-file-metadata` are among them too: the first request for a query
subscribes the workspace to it, and subscriptions are limited.

## Commands that keep a file

Six commands download a file. Nik keeps it as a file artifact, as it came,
and gives its name, type, size, SHA-256 and artifact; nothing opens it.

| Command | The file |
| --- | --- |
| `download-session-pcap` | the packets of one session (`session-<id>.pcap`) |
| `download-sessions-pcap` | the packets of the sessions that match a query, one page or up to 1 000 sessions (`sessions.pcap`) |
| `export-session-data` | one session as a PCAP, or the raw payload of its source or of its destination |
| `download-bsi-file` | the list of business services of a day, gzipped JSON, one record a line |
| `download-psychic-model` | a Psychic model of a day or of a range of 30 days at most, in the binary format or as a MaxMind DB |
| `download-psychic-snapshot` | the prepared Psychic snapshot of the last 7 or 30 days |

The two export commands (`download-sessions-pcap`, `export-session-data`)
read the sessions of your own sensors only: GreyNoise refuses them for the
demo data. A file larger than the limit of an upload in Nik is refused and
nothing is kept.

The reference describes each of these as the file itself in the answer of
`api.greynoise.io`. It names no storage host and no redirect, so the
connector reaches no other host. Should a real run be refused because
GreyNoise redirects a download elsewhere, the message names the host to add
to `more_hosts`.

## Good to know

- Several commands ask for the UUID of the workspace: in the Visualizer, the
  user menu, **Plan details**, under the name of the workspace.
- `search-gnql` and `search-gnql-metadata` read 5 000 addresses at most;
  `export-gnql-ips` gives every address in one answer, the addresses alone.
- The files of `download-gnql-file`, `download-callback-file` and
  `get-session-unique-values` are kept as text, the first 200 000 characters.
- `get-rss-feed-url` gives the address of the private feed, which is itself
  the credential: whoever has it reads the feed.

## Not here

- The private RSS feed itself (`/v3/articles/rss/{token}`): its address
  holds the token that opens it, and an argument of a command is not a
  secret. `get-rss-feed-url` gives the address for a feed reader.
- The CSV form of `search-gnql` and of the Recall commands: they are read as
  JSON.

## Not verified

This connector was written from GreyNoise's API reference
([docs.greynoise.io/reference](https://docs.greynoise.io/reference)) and is
tested against the examples that reference gives. It was not run against the
service.
