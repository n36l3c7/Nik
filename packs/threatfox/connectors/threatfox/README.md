# ThreatFox

ThreatFox is the project of abuse.ch where indicators of compromise tied to
malware are shared: IP addresses with their ports, domain names, URLs and
file hashes, each with its malware family, a threat type and a confidence
level. It takes confirmed indicators only.

## The key

Every request needs an **Auth-Key**. It is free: sign in at
<https://auth.abuse.ch/> and create one. The same key works for ThreatFox,
URLhaus and MalwareBazaar, so one key serves the three packs. Put it in the
instance as *Auth-Key*.

## Limits

abuse.ch gives the Community API free of charge under its
[fair use principles](https://abuse.ch/terms-of-use/#principles) and
publishes no number of requests for it. Use by companies or for profit may
need the paid, enhanced abuse.ch API, which is a different API and is not
what this connector speaks. Since May 2025 ThreatFox drops indicators older
than 6 months from its API (they stay on its website, marked expired), so
an old indicator is answered as unknown. The list of recent indicators goes
back 7 days at most; a search by tag or by family gives 100 indicators
unless a limit is given, 1000 at most. No command of this connector needs a
paid plan.

## The commands

- `get-ip-report`, `get-domain-report` and `get-url-report` look an exact
  value up: **malicious** when ThreatFox holds an indicator for it,
  **unknown** otherwise. An IP address also finds its `ip:port` entries.
  They are the commands `!ip`, `!domain` and `!url` ask.
- `get-file-report` gives the indicators tied to a file by its MD5 or
  SHA256 hash (the servers a sample talks to): **malicious** when there are
  any. It is the command `!file` asks.
- `search-ioc` searches for a text in any indicator; `get-ioc` reads one
  indicator by its id.
- `list-recent-iocs`, `search-tag` and `search-malware` give lists of
  indicators.
- `get-malware-label`, `list-malware`, `list-types` and `list-tags` give
  the names a submission must use.
- `submit-ioc` shares indicators under your abuse.ch account: it changes
  something at ThreatFox and asks a person first. Read the submission
  policy of ThreatFox before using it: confirmed indicators only.

Each command gives `query_status`, the word the API answers with: a look-up
that finds nothing is not a failure, its `count` is 0.

## What is not here

The data exports (every indicator as one JSON or CSV file) are files on
another host, not part of the API.

## Not run against the service

The connector was written from the documentation at
<https://threatfox.abuse.ch/api/> and is tested against the answers that
page shows, not against ThreatFox itself. Three things the documentation
does not settle and the first real run should confirm:

- it shows no answer for a search that finds nothing, and none for a
  submission: `submit-ioc` gives `query_status` and `data` as they come and
  does not judge them;
- it shows the answer of `get-ioc` as the indicator itself, without the
  `query_status` and `data` the other answers have: the outputs are read
  that way;
- it does not say how `is_compromised` is written: the connector sends
  true or false.
