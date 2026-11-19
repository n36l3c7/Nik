# Content packs

One folder for each product of a vendor: `pack.yml` and a folder for each
kind of item (connectors, mappers, playbooks, incident types, dashboards…).
The format is in the
[automation guide](https://n36l3c7.github.io/Nik/automation.html#pack-format).

The workflow *Packs* publishes these folders as the catalogue a Nik reads
(the release `packs`: one `.nikpack` file for each pack, an index and its
signature). A change to a pack raises the `version` of its `pack.yml`: a Nik
offers an update only for a higher version.

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
