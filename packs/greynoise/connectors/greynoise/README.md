# GreyNoise

GreyNoise runs sensors across the internet and records who scans and attacks
everything: the addresses that are "noise", what they look for, and which of
them are harmless (search engines, security researchers) or malicious. It
also keeps the list of the addresses of common business services (BSI, once
called RIOT), which are rarely worth an alert.

This connector asks GreyNoise about an address and reads the rest of its
API: GNQL searches, CVEs and tags, callback addresses, blocklists, event
feeds, Threat Briefs, and the sessions and detections of your own sensors.

## The key

The API key of a GreyNoise account, sent in the `key` header. Sign up at
[viz.greynoise.io](https://viz.greynoise.io/); the key is in the account.

The key is optional. Without one, only `get-community-ip`,
`get-public-rss-feed` and `ping` are of use: GreyNoise answers the Community
API to anyone, a few addresses a day.

## The free plan

As GreyNoise states it for the Community API:

- without a key, a limited number of look-ups a day, after which it answers
  429;
- with the key of a free account, 50 searches a week, counted together with
  the searches made in the Visualizer;
- an account created with a free e-mail address (Gmail, Hotmail, ProtonMail,
  iCloud and the like) has no access with an API key.

`get-community-ip` is the command `!ip` asks. Its verdict is the one Nik's
own enrichment gives for GreyNoise: **harmless** for a common business
service and for what GreyNoise classifies as benign, **malicious** for what
it classifies as malicious, **unknown** for the rest and for an address
GreyNoise has not seen.

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
| Sessions | `search-sessions`, `list-session-fields`, `count-sessions`, `get-session-connections`, `get-session-timeseries`, `get-session-unique-values`, `get-session` |
| Business services | `get-bsi-trust-stats`, `get-bsi-company-stats`, `get-bsi-category-stats`, `get-bsi-ip`, `get-bsi-ips` |
| Blocklists | `create-blocklist`, `list-blocklists`, `update-blocklist`, `get-blocklist`, `delete-blocklist`, `get-blocklist-ips` |
| Event feeds | `search-feed-events`, `fetch-feed-events`, `acknowledge-feed-events`, `list-feed-consumers`, `create-feed-consumer`, `reset-feed-consumer`, `delete-feed-consumer` |
| Threat Briefs | `list-articles`, `list-article-categories`, `get-article`, `get-rss-feed-url`, `generate-rss-feed-url` |
| Tactics | `search-tactics-detections`, `get-tactics-detection`, `list-tactics-destination-ips`, `list-tactics-files`, `get-host-artifact-content` |

`list-tags` is not marked: the reference states no plan for it. Whether the
key of a free account may read it was not confirmed.

## Commands that change something at GreyNoise

`create-blocklist`, `update-blocklist`, `delete-blocklist`,
`acknowledge-feed-events`, `create-feed-consumer`, `reset-feed-consumer`,
`delete-feed-consumer`, `generate-rss-feed-url` (the old feed address stops
working) and `delete-gnql-file-subscription`. `download-gnql-file` and
`get-gnql-file-metadata` are among them too: the first request for a query
subscribes the workspace to it, and subscriptions are limited.

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

- The downloads whose answer is a binary file: the PCAP of one session or of
  several, the raw payload of a session, the BSI bulk file and the Psychic
  models and snapshots.
- The private RSS feed itself: its address holds the token that opens it.
- The CSV form of `search-gnql` and of the Recall commands: they are read as
  JSON.

## Not verified

This connector was written from GreyNoise's API reference
([docs.greynoise.io/reference](https://docs.greynoise.io/reference)) and is
tested against the examples that reference gives. It was not run against the
service.
