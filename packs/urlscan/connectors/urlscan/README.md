# urlscan.io

urlscan.io loads a web page in a real browser and records what happens: the requests the page makes, the
addresses and domains it talks to, the DOM, a screenshot, and a verdict (malicious or not, the brand a phishing
page imitates). Every scan is kept and can be searched. This connector submits addresses, reads results, searches
the scans that exist and, for an account with urlscan Pro, drives live scanning, saved searches, subscriptions,
channels, incidents, brands, hostname history and data dumps. It has 55 commands.

## The key

An API key of a urlscan.io account, sent in the `API-Key` header. Create one on urlscan.io under
**Settings & API**, then **New API key**, and paste it in the connection.

The key is optional. urlscan's description says that most of its endpoints require authentication, and that the
search answers unauthenticated requests with the quotas of a visitor and a shorter history. An instance without a
key sends no `API-Key` header: the search, and so `get-url-reputation` and `get-domain-reputation`, are the
commands known to answer it. Give a key for everything else.

## Reputation

`get-url-reputation` and `get-domain-reputation` answer the War Room's `!url` and `!domain`. They **submit
nothing**: they search the scans that already exist (`page.url:"…"`, `page.domain:"…"`, the last ten). The
verdict and the summary are the ones Nik's own enrichment gives for urlscan, and the rule is written in the
file:

| What the search answers | Verdict | Summary |
| --- | --- | --- |
| no result (or 404) | unknown | never scanned on urlscan.io |
| results, none judged malicious | unknown | 37 public scans |
| results, some judged malicious | malicious | 37 public scans, 2 judged malicious |

A result is judged malicious when its `verdicts.malicious` is set, which is what the search documents, or its
`verdicts.overall.malicious` is, which is the shape of the result API. A result with both counts once. The
number of scans is the total urlscan counts (exact up to 10 000), or the number of results read when it gives
none; the number judged malicious is among the ten results read. urlscan gives no "clean" verdict, so these
commands never say `harmless`. `link` is the same search on urlscan.io.

## Scanning

`submit-url` asks for a scan and gives its id; `wait-for-result` waits for it (the result answers 404 until the
scan is finished, five minutes at most here) and gives the verdict, the page, the lists of addresses and domains,
and the addresses of the report, the screenshot and the DOM. Between two tries it waits five seconds, or as long
as urlscan asks in a `Retry-After` header when that is longer: nothing has to be set for it. A scan is
**public** unless you say `unlisted` or `private`: do not submit publicly an address that holds personal data
(a mailbox, a token).

## Files

Three commands keep a file as an artifact of Nik, as it came, and give its name, type, size, SHA-256 and
artifact. Nothing opens it.

- `get-screenshot`: the screenshot of a finished scan, a PNG.
- `download-file` (urlscan Pro): a file a scanned page made the browser download, by its SHA-256. urlscan sends
  a ZIP encrypted with the password `urlscan!` (or the one you give) that holds the one file, named after its
  SHA-256. The ZIP is stored as it is.
- `download-data-dump` (urlscan Pro): one data dump file, by the path `list-data-dumps` gives.

A file larger than the limit of an upload in Nik is refused and nothing is kept: a data dump of a whole day can
be larger than that.

## Limits

urlscan publishes no fixed numbers for the free plan. What it states:

- every action (public, unlisted and private scans, search, reading results) has its own quota by the minute,
  the hour and the day, reset at the full minute, hour and day (midnight UTC); `get-quotas` shows the ones of
  your account and what is used;
- only successful requests count; a request over a quota is answered 429, which Nik tries again;
- searches without a key and of free accounts may reach back a limited number of days only (the
  `search_date_limit_days` output of `search`), and a search counts results exactly up to 10 000.

## Commands that need urlscan Pro

Marked *premium* in the library: `set-result-visibility`, `reset-result-visibility`, `get-similar-results`,
`get-phishfeed`, `list-available-brands`, `list-brands`, `get-hostname-history`,
`lookup-malicious-observable`, the live scanning commands (`list-live-scanners`, `start-live-scan`,
`run-live-scan`, `get-live-scan-result`, `get-live-scan-dom`, `get-live-scan-response`, `store-live-scan`,
`purge-live-scan`), saved searches, subscriptions, channels, incidents, `download-file`, `list-data-dumps` and
`download-data-dump`. The `search` command itself is free; its `hostnames`, `incidents`, `notifications` and
`certificates` sources are Pro.

## What is not here

Every endpoint of the API description has its command. What the description does not settle:

- `download-data-dump`: the description says the endpoint "generates a temporary download link" and shows the
  answer as the gzip file itself. If urlscan answers with a redirect to a storage host, the description does not
  name that host and the connector lists none: the first real run is then refused with the name of the host,
  which has to be added to `more_hosts` of the connector. The key of the instance is never sent there.
- Which endpoints beside the search answer without a key is not listed.

## How this was written

From urlscan's published API description (docs.urlscan.io, "urlscan.io APIs" 1.0.0) and the pages beside it.
It was **not run against the service**: the connector is marked not verified until someone tests a connection
with a real key.
