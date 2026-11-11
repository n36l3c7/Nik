# Contributing to Nik

Thanks for wanting to help. This is what a change needs to be merged.

## Before you start

- For anything larger than a fix, open an issue first and say what you want
  to change and why: it saves writing something that does not fit.
- A vulnerability is not an issue: see [SECURITY.md](SECURITY.md).

## Setting up

The [developer guide](https://n36l3c7.github.io/Nik/developer.html) has the
details. In short:

```bash
# Backend (Python 3.11 to 3.13)
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
COOKIE_SECURE=false uvicorn app.main:app --reload --port 8000

# Frontend (Node 22.12 or later)
cd frontend
npm ci
npm run dev
```

Never run a sample to see what it does, on your machine or on a server that
runs Nik: nothing in this project executes evidence.

## What a change must pass

```bash
# Backend
cd backend && ruff check . && ruff format --check . && pytest -q

# Frontend
cd frontend && npm run lint && npm run format:check && npm test && npm run build
npm run test:e2e        # the whole app, in a browser (needs the backend's Python environment)
```

CI runs the same, plus the backend suite on PostgreSQL, the workers' tests
inside their images, and the end-to-end suite against the real workers.

## What a change must contain

- **Tests** for the behaviour it adds or fixes. A fix comes with the test
  that failed before it.
- **Documentation in the same change**: the README and the pages under
  `docs/` (plain HTML, no generator) describe the behaviour, so a change of
  behaviour changes them too.
- **A changelog entry** under `[Unreleased]` in `CHANGELOG.md`
  ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/)), and the same
  in short on `docs/changelog.html` when a release is cut.
- **English** everywhere: identifiers, comments, messages, documentation.
- No new dependency without a reason in the pull request: why it is needed,
  whether it is maintained, its licence.

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/):
  `type(scope): summary` in the imperative, at most 72 characters, then a
  body that says what changed and why. Types: `feat`, `fix`, `docs`,
  `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`. A breaking
  change has a `!` and a `BREAKING CHANGE:` footer.
- One pull request does one thing. It is squashed into one commit when
  merged, so its title is that commit's summary.
- The pull request says what it changes, why, and how to test it.
- Versions follow [Semantic Versioning](https://semver.org/).

## Where things are

`backend/` is the FastAPI application, `frontend/` the React app, `workers/`
the analysis containers, `deploy/` the scripts for a server, `docs/` the
site. The
[architecture page](https://n36l3c7.github.io/Nik/architecture.html) has the
map.
