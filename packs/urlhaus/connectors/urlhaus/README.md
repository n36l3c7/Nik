# URLhaus

URLhaus is the project of abuse.ch that collects the URLs malware is
distributed from: for each, whether it is still online, the host it is on,
its tags and the payloads it served.

## The key

Every request needs an **Auth-Key**. It is free: sign in at
<https://auth.abuse.ch/> and create one. The same key works for URLhaus,
MalwareBazaar and ThreatFox, so one key serves the three packs. Put it in
the instance as *Auth-Key*.

## Limits

abuse.ch gives the API free of charge under its
[fair use principles](https://abuse.ch/terms-of-use/#principles) and
publishes no number of requests for it. Use by companies or for profit may
need the paid, enhanced abuse.ch API, which is a different API and is not
what this connector speaks. The lists of recent URLs and payloads go back 3
days and hold 1000 entries at most; a URL shows 100 payloads at most, a
host 100 URLs, a tag or a signature 1000 URLs. No command of this connector
needs a paid plan.

## The commands

- `get-url-report` looks a URL up: **malicious** when URLhaus tracks it
  (online or not: `url_status` says which), **unknown** otherwise. It is the
  command `!url` asks.
- `get-host-report` looks a domain name, a hostname or an IPv4 address up:
  **suspicious** when URLhaus saw malware URLs on it (the host may be a
  compromised site that also serves honest pages), **unknown** otherwise. It
  is the command `!domain` asks; it takes an IPv4 address too, as a node of
  a playbook.
- `get-file-report` looks an MD5 or SHA256 hash up among the payloads
  URLhaus collected: **malicious** when the payload has a malware family,
  **suspicious** when it has none (URLhaus says itself that not every
  payload it collected is malware: a cleaned-up URL serves anything),
  **unknown** when URLhaus never saw the file. It is the command `!file`
  asks. URLhaus does not take SHA1 hashes.
- `get-url-by-id` reads an entry by its id.
- `list-recent-urls` and `list-recent-payloads` give the additions of the
  last 3 days.
- `search-tag` and `search-signature` give the URLs with a tag, or that
  served a malware family.

Each command gives `query_status`, the word the API answers with (`ok`,
`no_results`, `invalid_url`…): a look-up that finds nothing is not a
failure.

## What is not here

- Submitting a URL: the submission API is on another host
  (`urlhaus.abuse.ch`, not `urlhaus-api.abuse.ch`), and a connector reaches
  one host.
- Downloading a payload: the API answers a ZIP file, which a connector
  cannot carry.
- The feeds and database dumps (CSV, hostfile, RPZ, IDS rules, ClamAV
  signatures, MISP): files whose address holds the Auth-Key, described by
  URLhaus only to a signed-in account.

## Not run against the service

The connector was written from the documentation at
<https://urlhaus-api.abuse.ch/> and is tested against the answers that page
shows, not against URLhaus itself. One thing the documentation does not
settle and the first real run should confirm: `get-url-by-id` sends the
field `urlid` (the example of the documentation; its table says `id`).
