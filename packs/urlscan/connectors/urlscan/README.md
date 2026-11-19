# urlscan.io

urlscan.io loads a web page in a real browser and records what happens: the requests the page makes, the
addresses and domains it talks to, the DOM, a screenshot, and a verdict (malicious or not, the brand a phishing
page imitates). Every scan is kept and can be searched. This connector submits addresses, reads results, searches
the scans that exist and, for an account with urlscan Pro, drives live scanning, saved searches, subscriptions,
channels, incidents, brands, hostname history and data dumps.

## The key

An API key of a urlscan.io account, sent in the `API-Key` header. Create one on urlscan.io under
**Settings & API**, then **New API key**, and paste it in the connection. urlscan answers some calls without a
key, with the small quotas of an unauthenticated visitor, but the connector always sends the header: give it a
key.

## Reputation

`get-url-reputation` and `get-domain-reputation` answer the War Room's `!url` and `!domain`. They **submit
nothing**: they search the scans that already exist (`page.url:"…"`, `page.domain:"…"`, the last ten) and say
`malicious` when one of them was judged malicious, `unknown` otherwise. urlscan gives no "clean" verdict, so
these commands never say `harmless`.

## Scanning

`submit-url` asks for a scan and gives its id; `wait-for-result` waits for it (the result answers 404 until the
scan is finished, five minutes at most here) and gives the verdict, the page, the lists of addresses and domains,
and the addresses of the report, the screenshot and the DOM. A scan is **public** unless you say `unlisted` or
`private`: do not submit publicly an address that holds personal data (a mailbox, a token).

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
`purge-live-scan`), saved searches, subscriptions, channels, incidents and `list-data-dumps`. The `search`
command itself is free; its `hostnames`, `incidents`, `notifications` and `certificates` sources are Pro.

## What is not here

Three endpoints answer a binary file, which a command cannot carry: the screenshot of a scan (its address is the
`screenshot` output of the result), the download of a file by its hash, and the download link of a data dump.

## How this was written

From urlscan's published API description (docs.urlscan.io, "urlscan.io APIs" 1.0.0) and the pages beside it.
It was **not run against the service**: the connector is marked not verified until someone tests a connection
with a real key.
