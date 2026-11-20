"""Application configuration.

All settings are read from environment variables (optionally from a local
``.env`` file loaded by ``python-dotenv`` when present). Sensible defaults keep
the app runnable in development without any external services: the database
defaults to a local SQLite file so the backend boots without PostgreSQL.
"""

from __future__ import annotations

import os
from urllib.parse import quote_plus

# Load a local .env file if python-dotenv is installed. This is optional: in
# production the environment is typically populated by systemd / the container
# runtime, so a missing dotenv package is not an error.
try:  # pragma: no cover - trivial import guard
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv is optional
    pass


def _database_url() -> str:
    """Resolve the database connection URL.

    Precedence:

    1. An explicit ``DATABASE_URL`` is used verbatim (dev SQLite, custom DSNs).
    2. Otherwise, when ``DB_PASSWORD`` is set, a PostgreSQL URL is assembled
       from the ``DB_*`` parts with each credential percent-escaped — so the
       password may freely contain ``%``, ``@``, ``:``, ``/`` and friends,
       which would corrupt a URL spliced together by hand.
    3. Otherwise fall back to the local SQLite dev database.
    """
    explicit = os.getenv("DATABASE_URL")
    if explicit:
        return explicit

    password = os.getenv("DB_PASSWORD")
    if password:
        user = quote_plus(os.getenv("DB_USER", "nik"))
        host = os.getenv("DB_HOST", "localhost")
        port = os.getenv("DB_PORT", "5432")
        name = os.getenv("DB_NAME", "nik")
        return f"postgresql+psycopg://{user}:{quote_plus(password)}@{host}:{port}/{name}"

    return "sqlite:///./nik.db"


def _get_bool(name: str, default: bool) -> bool:
    """Parse a boolean environment variable.

    Accepts the usual truthy spellings (1/true/yes/on) case-insensitively.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    """Parse an integer environment variable, falling back on invalid input."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


class Settings:
    """Runtime configuration container.

    Instantiated once as the module-level ``settings`` singleton.
    """

    def __init__(self) -> None:
        # Database connection string. Defaults to a local SQLite file so the
        # backend runs out-of-the-box in development. In production either set
        # a full PostgreSQL URL or the individual DB_* parts (safer: the
        # password gets escaped automatically) — see _database_url().
        self.DATABASE_URL: str = _database_url()

        # Secret key: the provider API keys and TLS key logs stored in the
        # database are encrypted under it (core/vault.py), so it must be kept
        # with the backups. Session tokens are random and do not depend on it.
        # The default is for development only: the container refuses it
        # (app/preflight.py).
        self.SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-insecure-change-me")
        # Old values of SECRET_KEY (comma-separated), set for one start after
        # changing it: what they encrypted is re-encrypted with the new key.
        self.SECRET_KEY_PREVIOUS: list[str] = [
            value.strip() for value in os.getenv("SECRET_KEY_PREVIOUS", "").split(",") if value.strip()
        ]

        # Whether the session cookie carries the Secure attribute (HTTPS only).
        # Default True for safety; set COOKIE_SECURE=false for plain-HTTP local dev.
        self.COOKIE_SECURE: bool = _get_bool("COOKIE_SECURE", True)

        # Session lifetime in hours.
        self.SESSION_TTL_HOURS: int = _get_int("SESSION_TTL_HOURS", 12)

        # Name of the session cookie (per API contract).
        self.SESSION_COOKIE_NAME: str = "nik_session"

        # Observability / ops.
        self.LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
        # When set, /api/metrics answers only to `Authorization: Bearer <token>`.
        self.METRICS_TOKEN: str = os.getenv("METRICS_TOKEN", "")
        # When false, startup does NOT create tables (Alembic owns the schema).
        self.RUN_CREATE_ALL: bool = _get_bool("RUN_CREATE_ALL", True)

        # PostgreSQL connection pool + a safety statement timeout (ignored on
        # SQLite). Tune for the deployment's concurrency.
        self.DB_POOL_SIZE: int = _get_int("DB_POOL_SIZE", 5)
        self.DB_MAX_OVERFLOW: int = _get_int("DB_MAX_OVERFLOW", 10)
        self.DB_POOL_RECYCLE: int = _get_int("DB_POOL_RECYCLE", 1800)
        self.DB_STATEMENT_TIMEOUT_MS: int = _get_int("DB_STATEMENT_TIMEOUT_MS", 30000)

        # Malware samples: raw files live on disk (named by SHA-256, never
        # executed), only metadata and analysis results go to the database.
        # Exclude this directory from the server's antivirus, or it will
        # quarantine the evidence.
        self.SAMPLE_STORE: str = os.getenv("SAMPLE_STORE", "./samples")
        self.SAMPLE_MAX_MB: int = _get_int("SAMPLE_MAX_MB", 100)
        # Largest evidence file (browser database, event log, shell history,
        # tool output) accepted by POST /incidents/{id}/upload.
        self.ARTIFACT_MAX_MB: int = _get_int("ARTIFACT_MAX_MB", 500)
        # A mailbox (mbox, Maildir archive) can be much larger than any other upload;
        # a PST is converted by the document worker, on its work volume, so it has a limit of its own.
        self.MAILBOX_MAX_MB: int = _get_int("MAILBOX_MAX_MB", 2048)
        self.PST_MAX_MB: int = _get_int("PST_MAX_MB", 4096)
        # Directory of the built-in YARA rule files (*.yar); admin rules live in
        # the database and are compiled together with these.
        self.YARA_RULES: str = os.getenv(
            "YARA_RULES", os.path.join(os.path.dirname(os.path.dirname(__file__)), "malware", "yara")
        )
        # Analyzer worker (rizin) for disassembly, functions and graphs; see
        # workers/analyzer/. Empty URL = the Code view reports "not configured".
        self.ANALYZER_URL: str = os.getenv("ANALYZER_URL", "").rstrip("/")
        self.ANALYZER_TOKEN: str = os.getenv("ANALYZER_TOKEN", "")
        self.ANALYZER_TIMEOUT: int = _get_int("ANALYZER_TIMEOUT", 600)
        # capa worker for the Capabilities view; see workers/capa/. Empty URL = the
        # view reports "not configured".
        self.CAPA_URL: str = os.getenv("CAPA_URL", "").rstrip("/")
        self.CAPA_TOKEN: str = os.getenv("CAPA_TOKEN", "")
        self.CAPA_TIMEOUT: int = _get_int("CAPA_TIMEOUT", 1800)
        # Automatic threat-intelligence lookups (Settings -> Threat
        # intelligence turns them on per type). false = no background thread.
        self.ENRICHMENT_WORKER: bool = _get_bool("ENRICHMENT_WORKER", True)
        # What the API process does by itself in threads of its own: the check of the workers
        # (worker_watch.py) and the scans of addresses playbooks ask for (urlscan_queue.py).
        # false = neither starts (the tests, which own the database they run on).
        self.API_BACKGROUND: bool = _get_bool("API_BACKGROUND", True)
        # Content packs. A folder of packs (each a folder with a pack.yml, or a .nikpack file) installed
        # at start when they are not here or are older: for a Nik that cannot reach the catalogue.
        self.PACKS_DIR: str = os.getenv("NIK_PACKS_DIR", "").strip()
        # Where the catalogue of packs is read from until an admin sets another address (Settings).
        self.PACKS_CATALOGUE: str = os.getenv(
            "NIK_PACKS_CATALOGUE", "https://github.com/n36l3c7/Nik/releases/download/packs/index.json"
        ).strip()
        # Automation (app/automation). Where the loop that makes playbooks run lives:
        # `container` (the automation service of the Compose stack, the default),
        # `inline` (a thread of this process: tests, a single-container install)
        # or `off` (no events are recorded and nothing runs).
        worker = os.getenv("AUTOMATION_WORKER", "container").strip().lower()
        self.AUTOMATION_WORKER: str = worker if worker in ("container", "inline", "off") else "container"
        self.AUTOMATION_CONCURRENCY: int = max(1, min(32, _get_int("AUTOMATION_CONCURRENCY", 4)))
        self.AUTOMATION_MAX_ACTIVE_RUNS: int = max(1, _get_int("AUTOMATION_MAX_ACTIVE_RUNS", 200))
        self.AUTOMATION_RUNS_KEPT: int = max(10, _get_int("AUTOMATION_RUNS_KEPT", 500))
        # The script sandbox (workers/sandbox/). Empty URL = scripts say "not configured".
        self.SANDBOX_URL: str = os.getenv("SANDBOX_URL", "").rstrip("/")
        self.SANDBOX_TOKEN: str = os.getenv("SANDBOX_TOKEN", "")
        self.SANDBOX_MAX_TIMEOUT: int = max(1, min(600, _get_int("SANDBOX_MAX_TIMEOUT", 60)))
        self.SANDBOX_TIMEOUT: int = max(1, min(self.SANDBOX_MAX_TIMEOUT, _get_int("SANDBOX_TIMEOUT", 10)))
        # Previews of mail attachments: document viewer and isolated browser
        # (workers/docview/, workers/browser/). Empty URL = the buttons say "not configured".
        self.DOCVIEW_URL: str = os.getenv("DOCVIEW_URL", "").rstrip("/")
        self.DOCVIEW_TOKEN: str = os.getenv("DOCVIEW_TOKEN", "")
        self.BROWSER_URL: str = os.getenv("BROWSER_URL", "").rstrip("/")
        self.BROWSER_TOKEN: str = os.getenv("BROWSER_TOKEN", "")
        # Packet capture worker (workers/pcap/): Wireshark's engine for the Network
        # Analysis tab. Empty URL = captures are stored but not analysed.
        self.PCAP_URL: str = os.getenv("PCAP_URL", "").rstrip("/")
        self.PCAP_TOKEN: str = os.getenv("PCAP_TOKEN", "")
        self.PCAP_MAX_MB: int = _get_int("PCAP_MAX_MB", 500)
        # Backups (app/backups): the directory they are written to. In the Compose stack it is a
        # volume of its own (NIK_BACKUP_DIR chooses a path of the host instead).
        self.BACKUP_DIR: str = os.getenv("BACKUP_DIR", "./backups")
        # Before a release changes the database its migrations are tried on a copy; false skips
        # that rehearsal (never the snapshot) on a database too large to copy at every upgrade.
        self.UPGRADE_REHEARSAL: bool = _get_bool("NIK_UPGRADE_REHEARSAL", True)

    @property
    def is_sqlite(self) -> bool:
        """True when the configured database is SQLite."""
        return self.DATABASE_URL.startswith("sqlite")


# Module-level singleton imported across the app.
settings = Settings()
