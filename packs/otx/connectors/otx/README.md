# AlienVault OTX

The Open Threat Exchange (OTX, now run by LevelBlue) is a community threat-intelligence exchange. Its members
publish **pulses**: named sets of indicators (IP addresses, domains, hostnames, URLs, file hashes, CVEs…) with
what they are about: an adversary, malware families, targeted countries and industries. For each indicator OTX
also holds what LevelBlue Labs observed: geography, passive DNS, the URLs and malware samples seen with it,
whois, the analysis of a file. This connector reads all of that through the DirectConnect API, publishes,
edits and subscribes to pulses, and submits URLs and files for analysis. It has 47 commands.

## The key

The **OTX Key** of an OTX account, sent in the `X-OTX-API-KEY` header. Accounts are free: sign up on
otx.alienvault.com, then copy the key from **Settings** (it is also shown on the API Integration page) and
paste it in the connection. Every command needs it.

## Reputation

`get-ip-reputation`, `get-domain-reputation`, `get-url-reputation` and `get-file-reputation` answer the War
Room's `!ip`, `!domain`, `!url` and `!file`. They read the `general` section of the indicator. The verdict and
the summary are the ones Nik's own look-up code gave for OTX, and the rule is written in the file:

| What OTX answers | Verdict | Summary |
| --- | --- | --- |
| 404: it does not know the value | unknown | not in OTX |
| at least one pulse names the value | suspicious | in 3 OTX pulses |
| no pulse, and OTX lists it as known good (its `validation`: a whitelisted domain, a well-known address) | harmless | whitelisted by OTX |
| no pulse, no such list | unknown | in no OTX pulse |

OTX does not judge a pulse, so a value in a pulse is never `malicious`. The outputs also give the number of
pulses, their names (`pulses`), the first ten with their id, author, date, tags and TLP (`pulse_details`), the
malware families the listed pulses name, in alphabetical order, eight at most (`families`), what OTX's lists say
(`validation`), a link to the page of the indicator on OTX, and for an address its network and country.

## Limits

OTX is free and the whole API is open to any account: no command needs a paid plan. The reference states no
quota or rate limit; a request answered 429 is tried again by Nik. The feeds are read page after page up to a
ceiling (a thousand subscribed pulses, five thousand indicators of a pulse): narrow them with `modified_since`.

## Commands that change something

Publishing, editing, cloning and deleting a pulse, subscribing to a pulse or a user, following a user, putting
a pulse in a group and submitting URLs or a file for analysis. Several of these are plain GET requests in this
API; they ask a person first all the same, and are never sent in a dry run. A pulse created with `public` set is
visible to everyone on OTX.

`submit-file` sends a file Nik holds (an artifact, or its SHA-256) to OTX, which analyses it statically and
then in its sandbox when that applies. The file leaves Nik and stays with OTX: the data guard judges it before
anything is sent, and the node asks a person first. The reference gives this endpoint no field beside the file,
so the TLP of a submitted file cannot be chosen here. `list-submitted-files` says how far the analysis is.

## What is not here

- Changing the TLP of submitted files and URLs: the reference gives each of the two endpoints the fields of
  the other (the one for files asks for `urls`, the one for URLs for `hashes`), so neither could be written
  with confidence.

## How this was written

From LevelBlue's reference of the API (the page behind otx.alienvault.com/api) and, for the few calls it does
not show (a user by name, cloning a pulse, pulses in groups, YARA indicators), from LevelBlue's own Python
SDK. It was **not run against the service**: the connector is marked not verified until someone tests a
connection with a real key. The reference shows no example answer for the sections of an indicator: those
commands give the answer as it comes.
