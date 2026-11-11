# Security policy

Nik handles hostile files for a living, so reports about it mishandling one
are welcome and taken seriously.

## Reporting a vulnerability

Report it **privately**, with a
[GitHub security advisory](https://github.com/n36l3c7/Nik/security/advisories/new).
Please do not open a public issue for a vulnerability.

A useful report says:

- the version (shown at the top of `/api/docs`) and how Nik is deployed (the
  Compose stack, or a manual install);
- what you did, what happened, and what you expected;
- a file, a page or a request that triggers it. If it is malware, share it as
  you would any sample: in a password-protected archive.

A fix is published as a release with a `Security` entry in the changelog,
and the advisory is published with it.

## Supported versions

The latest release is the supported one. Fixes are not back-ported: update
with `git pull` and `compose up -d --build`.

## What is in scope

- A file, an e-mail, a capture, an address or a string from evidence that
  makes the server, a worker or an analyst's browser do something it should
  not: run code, reach the internal network, read another file, write to the
  audit log, open a link.
- A way for an analyst account or an API key to do what its role does not
  allow, or for one user's change to silently destroy another's.
- A secret that ends up in a log, a response or the repository.

How Nik contains hostile content, and its known limits, are described in the
[Security page](https://n36l3c7.github.io/Nik/security.html) of the
documentation. Something listed there under "Known limits" is known; a way
to turn one of them into an actual compromise is still a welcome report.

## What is not

- Attacks that need control of the host, of the container runtime, or an
  administrator account.
- The self-signed certificate of a fresh install, and missing protections
  on a deployment that was not configured as the deployment guide says.
