# RDAP (registration data)

RDAP, the Registration Data Access Protocol, is the successor of WHOIS: the
registries of domains (Verisign, the country registries…) and of addresses
(ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC) answer over HTTPS, in JSON, who
registered a domain and when, which registrar sold it, who holds an IP
network or an AS number. It is a standard of the IETF (RFC 9082 for the
queries, RFC 9083 for the answers), not a product.

## No key

RDAP needs no account and no key. The only setting is the **RDAP server**:

- `https://rdap.org` (the default) is a bootstrap server: it holds no data,
  finds the registry that holds the object and answers with a redirect to it.
- The address of one registry's own server
  (`https://rdap.verisign.com/com/v1`, `https://rdap.arin.net/registry`,
  `https://rdap.db.ripe.net`…) asks that registry directly, and only for
  what it holds. IANA publishes which server answers for what
  (`https://data.iana.org/rdap/`).

### Which registries are reached out of the box

RDAP.org answers a look-up with a redirect to the registry's own host, and a
redirect is followed only to a host the connector may reach. The connector
lists 38 registry hosts, each taken from IANA's bootstrap files:

- **Addresses and AS numbers**: the five regional internet registries, so
  every look-up of an IP address, a network or an AS number: ARIN, RIPE NCC,
  APNIC, LACNIC, AFRINIC.
- **Generic top-level domains**: .com and .net (Verisign), .org (Public
  Interest Registry), .info and some 450 others (Identity Digital), .xyz and
  some 90 others (CentralNic), .dev, .app and Google's others, .online and
  .site (Radix), .top (ZDNS), .cc and .name (Verisign), and those run by
  Nominet, GMO Registry, registry.click, Mobile Registry and Teleinfo.
- **Country codes**: .uk, .nl, .fr, .br, .au, .ca, .in, .pl, .cz, .no, .fi,
  .ua, .kr, .tw, .sg, .id, .ar, .tv, .is, .si, .th.

Some much used top-level domains have no RDAP server in IANA's files at the
time of writing (.de, .eu, .ch, .io, .co among them): RDAP.org answers 404
for those, and only WHOIS knows them.

For a registry that has RDAP but is not in the list, a look-up is refused
with the name of the host it was redirected to. Then either add that host to
the hosts the playbook may reach, or make an instance of this connector with
that registry's own address as its *RDAP server*: no redirect is involved.

## Limits

RDAP.org, as it states them: at most 10 requests in 10 seconds from one
client (429 beyond that), 403 for a client blocked for abuse, 404 when it
knows no RDAP server for the object. It asks heavy users to read IANA's
bootstrap files and go to the registries directly. Each registry has limits
of its own, which its `help` answer usually states (`get-help`).

Nothing here needs a paid plan.

## Commands

| Command | What it asks |
| --- | --- |
| `get-domain` | The registration of a domain: registrar, dates, status, name servers, DNSSEC. |
| `get-ip`, `get-ip-network` | The network an address or a block belongs to: name, range, holder, country. |
| `get-autnum` | The registration of an AS number. |
| `get-nameserver`, `get-entity` | A name server, or an entity (registrar, contact) by its handle. |
| `search-domains`, `search-nameservers`, `search-entities` | The searches of RFC 9082. RDAP.org refuses them (they belong to a registry's own server), and most registries refuse them too or ask for credentials this connector does not send. |
| `get-help` | What the server says of itself. |

`get-domain` and `get-ip` are the reputation commands for a domain and an
address. They inform; they do not judge, with one exception, the one Nik's
own enrichment makes: a domain registered less than 30 days ago is
*suspicious*. `get-domain` gives the age in whole days (`age_days`) and says
it in its summary: `registered 16 days ago (2026-12-30), Example Registrar`
for a young domain, `registered 1995-08-14, Example Registrar` otherwise.
For every other domain, and for every address, the verdict is *unknown*.
The summary of `get-ip` is the name of the network, its holder and its
country.

A domain or an address the registry has no record of (404) is an answer,
not a failure: the verdict is *unknown* and the summary says so. Any other
refusal fails the step.

`get-domain` takes the registered domain (`example.co.uk`), not a host under
it (`www.example.co.uk`): a registry has no record of a host name. Personal
data of registrants is usually redacted by the registry.

WHOIS on port 43, which the registries without RDAP still speak, is not
HTTP and is not part of this connector.

## Not verified

This connector was written from the RFCs and from what RDAP.org publishes.
It was not run against a real server; registries differ in what they put in
an answer, and an output the answer does not hold comes out empty.
