# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-11-04

### Added

- Safari in Browser Forensics (macOS only): `History.db` (browsing history
  with redirect chains), `Downloads.plist` and `Bookmarks.plist` (Favorites,
  folders and Reading List, with the date each item was added).
- A dependency-free property list parser for the browser, reading both binary
  (`bplist00`) and XML plists.
- Browser registry `platforms` field: the "where to find files" note warns
  when a browser does not exist on the incident's host OS.
- Safari uploads through the REST API (`browser=safari`, `source` =
  `history` / `downloads` / `bookmarks`).

## [1.1.0] - 2026-11-04

### Added

- `GET /api/incidents/{id}` answers `304 Not Modified` to a matching
  `If-None-Match`, checking only the version column (not the document body).
- `PATCH /api/incidents/{id}` accepts `Content-Type: application/merge-patch+json`
  (RFC 7396): nested members are merged and `null` removes one, so a client
  can send only what changed. Plain `application/json` keeps its behaviour.
- `os` in the `view=summary` incident listing, stored in a new `incidents.os`
  column (Alembic migration `0002_incident_os_column` backfills it).
- Frontend unit tests on Node's built-in test runner (`npm test`), run in CI.

### Changed

- Opening Nik downloads only the light incident list. An incident's artifacts
  are fetched when it is opened, behind a non-blocking loading state (the
  sidebar stays usable; switching incident cancels the pending download), and
  stay cached for the session with ETag revalidation on reopen.
- Every edit (flags, notes, uploads, metadata) sends only the changed part of
  the incident as a merge patch instead of the whole `data` blob.
- Exporting an incident that was not opened yet fetches it first.

### Fixed

- The backend test fixture resets the rate limiter between tests, so the
  login limit no longer makes the suite fail as it grows.

## 1.0.0 - 2026-07-11

### Added

- First release of Nik: forensic analysis platform with browser, command
  history and endpoint artifact analysis, a super-timeline, SOC detection
  rules, case management, full backup, authentication and audit, and the
  external REST API.

[Unreleased]: https://github.com/n36l3c7/Nik/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/n36l3c7/Nik/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/n36l3c7/Nik/releases/tag/v1.1.0
