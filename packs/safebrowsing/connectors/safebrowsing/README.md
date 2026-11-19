# Google Safe Browsing

Google Safe Browsing keeps lists of unsafe web resources: pages that spread
malware or unwanted software, social engineering (phishing) pages, and
potentially harmful applications. This connector asks whether a URL or a
domain is on those lists, and reads the lists themselves for a client that
keeps a local copy.

## The key

An **API key** of a Google Cloud project:

1. Sign in to the [Google Cloud console](https://console.cloud.google.com/) and create a project (or pick one).
2. Under *APIs & Services*, *Library*, enable **Safe Browsing API**.
3. Under *APIs & Services*, *Credentials*, create an **API key**.

The key is sent as the `key` query parameter of every request. The API does
not answer without one.

*Client id* and *Client version* are what the v4 requests give as the client
(`client.clientId`, `client.clientVersion`); the defaults are fine.

## Limits, as Google states them

- "The Safe Browsing API is for non-commercial use only." For commercial
  use Google points to Web Risk, a different product this connector does not
  speak to.
- There is no cost. A project gets a default quota when the API is enabled;
  the allocation and the usage are shown in the Google Cloud console, where
  more can be asked for.
- A v4 look-up takes up to 500 URLs in one request; a v5 URL search up to
  50; a v5 hash search up to 1000 hash prefixes.
- An answer must not be kept longer than the cache duration it comes with.
- A warning shown to people on the strength of this data must say the page
  is *suspected* to be unsafe, not that it is, and carry the notice
  "Advisory provided by Google".

No command needs a paid plan. `report-threat-hit` is open only to projects
Google made trusted reporters.

## Commands

| Command | What it asks |
| --- | --- |
| `check-url`, `check-domain` | Whether a URL, or the home page of a domain over http and https, is on the lists (v4 `threatMatches.find`). These are the reputation commands: *malicious* when a list has it, *unknown* otherwise. Not being listed does not mean a page is safe. |
| `find-threat-matches` | The same look-up with the threat, platform and entry types of your choice, for up to 500 entries. |
| `find-full-hashes`, `fetch-threat-list-update`, `list-threat-lists` | The v4 Update API, for a client that keeps the lists locally. |
| `get-encoded-full-hashes`, `get-encoded-updates` | The same two, for a request already serialised as a protocol buffer. |
| `report-threat-hit` | Tells Google a client met a listed entry (trusted reporters only). |
| `search-urls`, `search-hashes` | The v5 look-ups. |
| `list-hash-lists`, `get-hash-list`, `batch-get-hash-lists` | The v5 hash lists. |

Hash prefixes, full hashes, states and versions are base64 texts, as the JSON
form of the API has them. The lists come Rice-encoded or raw: the connector
gives them as the API sends them and does not decode them.

## Not verified

This connector was written from Google's documentation and from the
discovery documents of the service. It was not run against the service. The
v5 commands ask for JSON (`alt=json`), which the discovery document gives as
the default form of an answer, while the v5 guide describes answers as
protocol buffers: check them first against your key.
