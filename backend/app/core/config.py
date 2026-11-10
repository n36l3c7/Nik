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

        # Secret key. Reserved for signing/entropy purposes. Session tokens are
        # random hex, but a stable secret is still good practice in production.
        self.SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-insecure-change-me")

        # Whether the session cookie carries the Secure attribute (HTTPS only).
        # Default True for safety; set COOKIE_SECURE=false for plain-HTTP local dev.
        self.COOKIE_SECURE: bool = _get_bool("COOKIE_SECURE", True)

        # Session lifetime in hours.
        self.SESSION_TTL_HOURS: int = _get_int("SESSION_TTL_HOURS", 12)

        # Name of the session cookie (per API contract).
        self.SESSION_COOKIE_NAME: str = "nik_session"

        # Observability / ops.
        self.LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
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

    @property
    def is_sqlite(self) -> bool:
        """True when the configured database is SQLite."""
        return self.DATABASE_URL.startswith("sqlite")


# Module-level singleton imported across the app.
settings = Settings()
