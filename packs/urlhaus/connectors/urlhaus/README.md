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
- `download-payload` downloads a payload by its SHA256 hash and keeps it as
  an artifact of the incident the playbook works on.
- `download-hourly-batch` and `download-daily-batch` download the batch of
  the payloads of an hour or of a day.
- `download-export` downloads one of the database dumps and feeds
  (`recent.csv` unless another name is given).
- `submit-url` reports a URL that is serving malware to URLhaus, under your
  abuse.ch account: it changes something at URLhaus and asks a person
  first. Read the submission policy of URLhaus before using it.

Each look-up gives `query_status`, the word the API answers with (`ok`,
`no_results`, `invalid_url`…): a look-up that finds nothing is not a
failure.

## Files

A payload comes as URLhaus sends it: a ZIP file, which at the time of
writing has no password and may set an antivirus off. Nik keeps that
archive as an artifact and opens nothing. The batches are ZIP files with
the password `infected`, on `datalake.abuse.ch`, which the connector
reaches beside the API and which is never sent the Auth-Key. A batch is
often hundreds of megabytes (a daily one over a gigabyte): one that is
larger than the limit of a sample in Nik (`SAMPLE_MAX_MB`) is refused, and
nothing is kept.

## The second Auth-Key

The key of the instance travels in the `Auth-Key` header, to
`urlhaus-api.abuse.ch` and nowhere else. Two commands need it elsewhere:

- `download-export`: the address of a dump holds the key
  (`/v2/files/exports/<Auth-Key>/recent.csv`);
- `submit-url`: the submission API is on another host, `urlhaus.abuse.ch`,
  which wants the key in its header.

For those an instance is given the key a second time, as *Auth-Key, for
submissions and exports*. Giving it is the permission to send it there; it
is replaced in what a step records. Left empty, these two commands fail and
every other command works. URLhaus names one dump, `recent.csv`; the names
of the others (CSV and JSON dumps, host file, RPZ, IDS rules, ClamAV
signatures, MISP) are shown on <https://urlhaus.abuse.ch/api/> to a
signed-in account, and `download-export` takes any of them.

## What is not here

Every part of the API the documentation describes has a command.

## Not run against the service

The connector was written from the documentation at
<https://urlhaus-api.abuse.ch/> and <https://urlhaus.abuse.ch/api/>, and is
tested against the answers those pages show, not against URLhaus itself.
What the documentation does not settle and the first real run should
confirm:

- `get-url-by-id` sends the field `urlid` (the example of the
  documentation; its table says `id`);
- `download-payload` keeps the answer only when its type says it is an
  archive (`zip` or `octet-stream`): the documentation says a hash URLhaus
  does not hold is answered `not_found`, and does not say with what type
  either comes;
- the documentation shows no answer for a submission: `submit-url` gives
  the answer as it comes and does not judge it;
- the names of the batches (`2026-11-19-23.zip`, `2026-11-18.zip`) are
  those the listings of `datalake.abuse.ch` show; the documentation only
  links to the listings.
