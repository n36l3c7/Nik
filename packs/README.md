# Content packs

One folder for each product of a vendor: `pack.yml` and a folder for each
kind of item (connectors, mappers, playbooks, incident types, dashboards…).
The format is in the
[pack format](https://n36l3c7.github.io/Nik/reference/connector-format/#the-pack-format).

The workflow *Packs* publishes these folders as the catalogue a Nik reads
(the release `packs`: one `.nikpack` file for each pack, an index and its
signature). A change to a pack raises the `version` of its `pack.yml`: a Nik
offers an update only for a higher version.

`tags` in `pack.yml` (lower case words: what the product is, what it works on)
are what the page of the packs filters by, beside the category.

## Sigma rules

A pack may carry Sigma rules for host evidence (7.0): a folder `sigma/`, in any
depth of subfolders, with **one rule document in each `.yml` file**, as the rule
is written (its `id` is what names it). Nik asks the forensics worker to read
them 200 at a time when the pack is applied; a rule arrives switched on when the
worker can run it, its `status` is `stable` or `test` and its `level` is `medium`
or more, and off otherwise. A rule a person changed keeps their text when the
pack is updated, and Reset gives the text of the pack back.

`notice` in `pack.yml` is the licence or the notice of what the pack carries
(the Detection Rule License of SigmaHQ asks that the authors of the rules be
named): it is shown with the pack, and the report names the author of each rule
that matched.

Every connector here was written from what its vendor publishes about its
API and is tested against recorded exchanges
(`backend/tests/data/connectors/<id>/`), not against a real system: each says
`verified: false`.

## Logos

`connectors/<id>/logo.png` is the mark of the product, shown beside the
connector and on the card of the pack. Each is the vendor's own file, scaled
to 256 px and not otherwise changed. They are trademarks of their owners and
are used only to say which product a pack is for; they are not covered by
the licence of this repository.

| Pack | Taken from |
| --- | --- |
| jira-cloud, jira-datacenter | `atlassian.design/foundations/logos` (jira_app.zip) |
| confluence-cloud, confluence-datacenter | `atlassian.design/foundations/logos` (confluence_app.zip) |
| bitbucket-cloud, bitbucket-datacenter | `atlassian.design/foundations/logos` (bitbucket_app.zip) |
| checkpoint-management, checkpoint-sase | `www.checkpoint.com` (the icon of the site) |
| sentinelone, sentinelone-sdl | `www.sentinelone.com/press` (logo package, the mark) |
| servicenow | `store.servicenow.com` (the icon of the site) |
| zscaler-zia | `www.zscaler.com` (the icon of the site) |
| virustotal | `www.virustotal.com` (the icon of the site) |
| abuseipdb | `www.abuseipdb.com` (its logo file) |
| urlscan | `urlscan.io` (its logo file) |
| otx | `otx.alienvault.com` (the icon of the site: the LevelBlue mark) |
| greynoise | `www.greynoise.io` (the icon of the site) |
| shodan | `www.shodan.io` (the icon of the site) |
| safebrowsing | `safebrowsing.google.com` (its logo file) |

MalwareBazaar, URLhaus, ThreatFox and RDAP have no logo: abuse.ch publishes
only wordmarks, which cannot be read at the size of a card, and RDAP is a
standard, not a product.
