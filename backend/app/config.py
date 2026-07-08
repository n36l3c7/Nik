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
        user = quote_plus(os.getenv("DB_USER", "csap"))
        host = os.getenv("DB_HOST", "localhost")
        port = os.getenv("DB_PORT", "5432")
        name = os.getenv("DB_NAME", "csap")
        return f"postgresql+psycopg://{user}:{quote_plus(password)}@{host}:{port}/{name}"

    return "sqlite:///./csap.db"


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
        self.SESSION_COOKIE_NAME: str = "csap_session"

    @property
    def is_sqlite(self) -> bool:
        """True when the configured database is SQLite."""
        return self.DATABASE_URL.startswith("sqlite")


# Module-level singleton imported across the app.
settings = Settings()
