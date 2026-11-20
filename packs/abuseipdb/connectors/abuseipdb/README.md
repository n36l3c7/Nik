# AbuseIPDB

AbuseIPDB is a database of IP addresses reported for abuse (brute force,
scans, spam, attacks on web applications) by the people who run the servers
those addresses reached. From the reports it works out, for each address, a
confidence of abuse from 0 to 100.

This connector reads that database and writes to it: what is known of an
address or of a network, the reports themselves, the blacklist of the most
reported addresses, reporting an address and taking your own reports back.

## The key

An API key (APIv2) of an AbuseIPDB account: sign up at
[www.abuseipdb.com](https://www.abuseipdb.com/), then create the key in the
account dashboard. A free account is enough for every command. The key
is sent in the `Key` header.

## Commands

| Command | What it does |
| --- | --- |
| `check-ip` | What is known of an address, with a verdict. It is the command `!ip` asks. |
| `list-reports` | The reports made of an address, page by page. |
| `check-block` | The reported addresses of a network. |
| `get-blacklist` | The most reported addresses, with their confidence. |
| `get-blacklist-text` | The same list as plain text, one address a line. |
| `report-ip` | Report an address. Changes something at AbuseIPDB. |
| `bulk-report` | Report many addresses at once, from a CSV file Nik holds. Changes something at AbuseIPDB. |
| `clear-address` | Delete your own reports of an address. Changes something at AbuseIPDB. |

The verdict of `check-ip` is the one Nik's own enrichment gives for
AbuseIPDB: **harmless** when the address is on one of AbuseIPDB's whitelists,
**malicious** from a confidence of 75, **suspicious** from 25, **unknown**
below. Its summary is the same line: `confidence 100 %, 42 reports in 90
days`.

A comment sent with `report-ip` is public: take out of it anything that
names a person. The same holds for the comments of a file sent with
`bulk-report`.

`bulk-report` takes the file as an artifact of Nik (`file-<sha256>`): a CSV
with the headings `IP`, `Categories`, `ReportDate` and `Comment`, in any
order, under 8 MB and 10 000 lines
([www.abuseipdb.com/bulk-report](https://www.abuseipdb.com/bulk-report)
describes it). It asks a person first, and the data guard judges the file
before it leaves. It gives how many reports were saved and the rows that
were refused, each with its reason. `list-reports` also gives `total`, how
many reports AbuseIPDB holds beyond the pages that were read.

## Limits of a free account

Requests a day, as AbuseIPDB states them for each endpoint:

| Endpoint | Free | Webmaster | Supporter | Basic | Premium |
| --- | --- | --- | --- | --- | --- |
| check | 1 000 | 3 000 | 5 000 | 10 000 | 50 000 |
| reports | 100 | 500 | 1 000 | 5 000 | 25 000 |
| blacklist | 5 | 10 | 20 | 100 | 500 |
| report | 1 000 | 3 000 | 1 000 | 10 000 | 50 000 |
| check-block | 100 | 250 | 500 | 1 000 | 5 000 |
| clear-address | 5 | 10 | 20 | 100 | 500 |

Past the limit AbuseIPDB answers 429 until the day ends. Each page that
`list-reports` reads is one request to `reports`. "Test the connection"
sends one `check`.

## What needs a subscription

No command is for subscribers only. A subscription changes these arguments:

- `get-blacklist` and `get-blacklist-text`: `confidence_minimum`,
  `only_countries` and `except_countries` are subscriber features; without a
  subscription AbuseIPDB gives the plain list and no error. `limit` is capped
  at 10 000 addresses for a free account, 100 000 for Basic, 500 000 for
  Premium.
- `check-block`: a free account may ask for a network up to /24 and reports
  up to 30 days old; Basic /20 and 60 days; Premium /16 and 365 days. Asking
  for more is answered 402.

## Not here

Every endpoint of the reference has a command. The reference states no
daily limit for `bulk-report`.

## Not verified

This connector was written from AbuseIPDB's API documentation
([docs.abuseipdb.com](https://docs.abuseipdb.com/)) and is tested against
the answers that documentation shows. It was not run against the service.
