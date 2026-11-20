# Shodan

Shodan is a search engine of what is exposed on the Internet: for each IP
address, the open ports, the banners of the services behind them, the
software and its known vulnerabilities, host names and tags. This connector
speaks to its REST API (`https://api.shodan.io`): host look-ups, searches,
on-demand scans, network alerts and their notifiers, the directory of saved
queries, DNS and the account. It also speaks to the services Shodan keeps
beside it, each on a host of its own:

| Service | Host | Key | Commands |
| --- | --- | --- | --- |
| InternetDB | `internetdb.shodan.io` | none | `check-ip` |
| CVEDB | `cvedb.shodan.io` | none | `get-cve`, `get-euvd`, `get-ghsa`, `search-cves`, `count-cves`, `list-cpes`, `count-cpes` |
| EntityDB | `entitydb.shodan.io` | none | `list-entities`, `get-entity`, `get-entity-by-symbol`, `get-entitydb-last-updated`, `check-entitydb-health` |
| GeoNet | `geonet.shodan.io` | none | `ping-host`, `ping-host-worldwide`, `lookup-dns`, `lookup-dns-worldwide` |
| Trends | `trends.shodan.io` | the API key | `search-trends`, `list-trends-filters`, `list-trends-facets` |

A playbook that uses these commands reaches those hosts as well as
`api.shodan.io`.

## The key

Every Shodan account has an API key, shown on <https://account.shodan.io>.
Creating an account is free (<https://account.shodan.io/register>). The key
is sent in the query of a request (`?key=…`), as the API asks, to
`api.shodan.io` and `trends.shodan.io` only: the services that take no key
are never sent it. Nik stores it encrypted and never shows it in what a step
records.

The key is optional. An instance without one can use the commands of the
services that take no key (`check-ip` and those of CVEDB, EntityDB and
GeoNet); every other command is refused by Shodan (401).

## Plans and limits

As Shodan states them (<https://developer.shodan.io/pricing>):

- every account comes with a free API plan;
- every API plan is limited to 1 request a second;
- searching uses **query credits** and scanning uses **scan credits**, both
  renewed each month: 100 and 100 with the Membership, 10,000 and 5,120 with
  Freelancer, 200,000 and 65,536 with Small Business, unlimited queries and
  327,680 scan credits with Corporate;
- network alerts watch 16 IP addresses with the Membership, 5,120 with
  Freelancer, 65,536 with Small Business, 327,680 with Corporate;
- the `vuln` search filter needs the Small Business plan at least, and the
  `tag` filter the Corporate plan;
- using InternetDB commercially is part of the Corporate plan.

`get-api-info` says what the key has left.

What uses credits:

| Command | Uses |
| --- | --- |
| `search-hosts`, `search-all-hosts` | 1 query credit when the query holds a filter, and 1 for each page of 100 results past the first |
| `get-domain` | 1 query credit for each look-up |
| `submit-scan` | 1 scan credit for each IP address |

`count-hosts` gives the total and the facets of a search without using
credits, and `check-ip` uses neither a key nor credits.

## Commands that need a paid plan

They are marked *premium* in the library:

| Command | Needs |
| --- | --- |
| `submit-scan` | a paid API plan (a one-time payment or a subscription) |
| `submit-internet-scan` | to be a security researcher Shodan approved, or a Shodan Enterprise Data license |
| `list-datasets`, `list-dataset-files` | a Shodan Enterprise Data license |
| `get-organization`, `add-organization-member`, `remove-organization-member` | an Enterprise account |
| `search-trends`, `list-trends-filters`, `list-trends-facets` | an Enterprise account |

## The verdict of `check-ip`

`check-ip` answers the War Room's `!ip`. It reads Shodan InternetDB, as Nik's
automatic enrichment does, and gives the same verdict. Shodan says what a
host exposes, not whether it is clean, so the verdict comes from the tags of
the host:

- **malicious** when the host is tagged `malware`, `c2`, `compromised` or `botnet`;
- **suspicious** when the only such tag is `tor`;
- **unknown** otherwise, and when InternetDB has nothing on the address.

The summary is the line the enrichment gives: the first 8 open ports, the
number of known CVEs and the first 5 tags (`ports 22, 443; 1 CVE; tags c2`),
`no open port` for a host that has none, `no open port known to Shodan` when
InternetDB has nothing on the address. `bad_tags` gives the tags the verdict
came from. `get-host` reads the full record of a host from the REST API
(banners, location, organisation), with the key.

`search-all-hosts`, `list-saved-queries` and `search-saved-queries` read a
list page after page and also give `total`, how many results Shodan has
beyond the pages that were read.

## What is not here

- The Exploits API (`exploits.shodan.io`): its reference could not be read
  when this connector was written.
- The Streaming API (`stream.shodan.io`): an endless stream, which a command
  cannot read.
- The `format=markdown` answers of CVEDB: the commands read JSON.

## Not verified

This connector was written from what Shodan publishes
(<https://developer.shodan.io/api>, <https://developer.shodan.io/api/trends>
and the OpenAPI files of InternetDB, CVEDB, EntityDB and GeoNet). The
commands of the REST API and of Trends are tested against the answers the
documentation shows; those of the other four services against answers made
to the shape their OpenAPI files give, which show no example. Nothing was run
against the real services: the connector is marked *not verified* until
someone does.
