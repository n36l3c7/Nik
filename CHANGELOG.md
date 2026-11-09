# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.3.2] - 2026-11-09

### Added

- Prettier (`npm run format`, `npm run format:check`) for JS/JSX, CSS, JSON,
  HTML and YAML, and `ruff format` for the backend; CI checks both. The whole
  code base was reformatted once in this release, with no behaviour change.

## [2.3.1] - 2026-11-09

### Added

- ESLint (`npm run lint`, React and hooks rules) for the frontend and Ruff
  (`ruff check .`, `backend/ruff.toml`) for the backend; CI runs both.

### Fixed

- The Events, Commands, Artifacts and Timeline tabs no longer recompute their
  memoized rows on every render when an incident has no flags.
- Backend errors re-raised as HTTP or validation errors keep their original
  cause (exception chaining).
- Removed unused parameters, variables, imports and lint suppressions.

## [2.3.0] - 2026-11-06

### Added

- `tail -f` side panel: the latest 60 timestamped events of the open incident
  (browser, commands, endpoint), newest at the bottom, with source, severity
  and flags. Toggled from the tab bar on wide screens, remembered per tab and
  open on Summary by default.

### Changed

- Terminal look, step 2: Summary, Browser Forensics (profiles, upload zones,
  events, bookmarks, shortcuts, widgets), Command History, Endpoint
  Artifacts, Timeline, Network Logs, Settings (rules, business hours,
  accounts, API keys, audit log) and Full backup use the design tokens.
- Analyst flags use the green accent and SOC rows their severity colour, so a
  flag never looks like a detection.
- The Summary counters wrap to two rows of three below very wide screens.

### Removed

- The `dark:` Tailwind variant and the `dark` class on `<html>`: no
  component uses them any more.

## [2.2.0] - 2026-11-06

### Added

- Terminal look, step 1: named colour tokens in `src/index.css` (surfaces,
  text, green accent, HIGH/MED severities…) used by the UI kit and the
  application shell.
- Bundled fonts: Inter and JetBrains Mono (woff2, OFL-1.1), no CDN.
  JetBrains Mono covers the block and box-drawing characters, so the ASCII
  skull and banners render without fallback fonts.
- Sign-in and first-run screens with the NIK banner and a `$ nik status` box
  showing the real API and database status (public health endpoints).

### Changed

- The UI kit (buttons, cards, badges, modals, tables, inputs, stat cards,
  empty states), the sidebar, header, tab bar and OS picker use the terminal
  look: square corners, monospace labels, green accent.
- The header shows the incident as `host / user` with its OS.
- `index.html` is in English (`lang="en"`) and has a terminal favicon.

### Removed

- The light theme and its toggle: Nik is dark only. `ThemeContext` and the
  `nik:theme` local-storage preference are gone.

## [2.1.0] - 2026-11-06

### Added

- ASCII skull loaders: a symmetric skull drawn in text characters, generated
  at any size by `src/utils/asciiSkull.js` and rendered by the new
  `AsciiSkull` / `MicroSkull` UI components (presets block, large, medium,
  small; eyes that look around and blink, closed, or crossed out).
- Opening an incident shows the block skull with the real download progress
  (percentage and megabytes, from the response's Content-Length) and a Cancel
  button that returns to no incident.
- `EmptyState` accepts an `illustration` in place of its icon.

### Changed

- Loading a tab, a failed incident load (eyes crossed out), the "no active
  incident" state (asleep) and file parsing in the upload zones now use the
  skull; connecting, loading the incident list, an unreachable server and
  busy buttons (backup export/restore, API key creation, incident export) use
  the inline micro skull.
- Skulls stay still when the operating system asks to reduce motion.

### Removed

- The `Spinner` UI component, replaced everywhere by the skulls.

## [2.0.0] - 2026-11-04

### Added

- Several profiles per browser (Chrome "Default", "Profile 1", "Work", …):
  add, rename and delete them in Browser Forensics; each profile has its own
  files and data, and the browser badge sums all profiles.
- Timeline and flags name the profile ("Chrome · Work") when a browser has
  more than one; flags on a deleted profile are kept and marked as such.
- `profile` query parameter on `POST /api/incidents/{id}/upload` (profile
  name, case-insensitive, created if missing; default `Default`) and a
  `profile` argument on the Cortex XSOAR `nik-upload-artifact` command.
- Alembic migration `0003_browser_profiles`, moving existing browser data
  into a "Default" profile.

### Changed

- **BREAKING:** an incident's browser data is now
  `data.browser.browsers[<id>] = { activeProfile, profiles: { <profileId>:
  { id, name, createdAt, history, downloads, bookmarks, shortcuts, meta } } }`
  instead of the artifact lists directly under `browsers[<id>]`. API clients
  reading `data.browser` must follow the new shape.
- **BREAKING:** the upload response `target` is now
  `browser/<id>/<profile>/<source>` and includes `profileId`.
- Path hints show `<profile>` in place of the Chromium/Firefox profile folder.
- Incident exports are envelope version 4; versions 3 and older still import.
- Creating, patching, fetching and restoring incidents convert any pre-2.0.0
  browser data, so old exports, backups and clients keep working.

### Upgrade notes

Back up, then run `alembic upgrade head` (automatic in the Docker image): the
migration rewrites every incident once, which can take a while on large
databases.

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

[Unreleased]: https://github.com/n36l3c7/Nik/compare/v2.3.2...HEAD
[2.3.2]: https://github.com/n36l3c7/Nik/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/n36l3c7/Nik/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/n36l3c7/Nik/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/n36l3c7/Nik/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/n36l3c7/Nik/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/n36l3c7/Nik/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/n36l3c7/Nik/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/n36l3c7/Nik/releases/tag/v1.1.0
