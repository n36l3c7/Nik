"""Data migrations on a SQLite copy of an older schema."""

from __future__ import annotations

import json

import pytest
import sqlalchemy as sa
from alembic.config import Config

from alembic import command

CFG_A = {"truncated": False, "blocks": [{"addr": 4096, "size": 2, "jump": None, "fail": None, "ops": []}]}
CODE_A = {"code": "void f(void) {}", "spans": [], "truncated": False}
CODE_B = {"code": "int g(void) { return 0; }", "spans": [], "truncated": False}


def test_migration_0010_moves_cfgs_and_pseudo_c_into_one_row_per_function(tmp_path, monkeypatch):
    url = "sqlite:///" + str(tmp_path / "old.db").replace("\\", "/")
    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "CREATE TABLE sample_code (sha256 VARCHAR(64) PRIMARY KEY, status VARCHAR NOT NULL,"
                " error VARCHAR, requested_at VARCHAR NOT NULL, requested_by VARCHAR NOT NULL DEFAULT '',"
                " finished_at VARCHAR, summary JSON NOT NULL, cfgs JSON NOT NULL, decompiled JSON NOT NULL)"
            )
        )
        conn.execute(
            sa.text("INSERT INTO sample_code VALUES ('a' || :pad, 'done', NULL, 't', 'x', 't', '{}', :cfgs, :code)"),
            {
                "pad": "0" * 63,
                "cfgs": json.dumps({"4096": CFG_A}),
                "code": json.dumps({"4096": CODE_A, "8192": CODE_B}),  # 8192: decompiled on demand, no CFG row
            },
        )

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0009_sample_capa")
    command.upgrade(cfg, "0010_function_rows_capa_rules")

    sha = "a" + "0" * 63
    with engine.connect() as conn:
        rows = conn.execute(sa.text("SELECT sha256, addr, cfg, decompiled FROM sample_functions ORDER BY addr")).all()
        columns = {c["name"] for c in sa.inspect(conn).get_columns("sample_code")}
        tables = set(sa.inspect(conn).get_table_names())
    assert [(r[0], r[1]) for r in rows] == [(sha, 4096), (sha, 8192)]
    assert json.loads(rows[0][2]) == CFG_A and json.loads(rows[0][3]) == CODE_A
    assert rows[1][2] is None and json.loads(rows[1][3]) == CODE_B
    assert "cfgs" not in columns and "decompiled" not in columns and "capa_rules" in tables

    command.downgrade(cfg, "0009_sample_capa")
    with engine.connect() as conn:
        cfgs, code = conn.execute(sa.text("SELECT cfgs, decompiled FROM sample_code")).one()
        tables = set(sa.inspect(conn).get_table_names())
    assert json.loads(cfgs) == {"4096": CFG_A} and json.loads(code) == {"4096": CODE_A, "8192": CODE_B}
    assert "sample_functions" not in tables and "capa_rules" not in tables


def test_migration_0011_creates_the_ioc_index(tmp_path, monkeypatch):
    url = "sqlite:///" + str(tmp_path / "old.db").replace("\\", "/")
    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY)"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0010_function_rows_capa_rules")
    command.upgrade(cfg, "0011_ioc_index")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert "ioc_index" in inspector.get_table_names()
        assert [ix["name"] for ix in inspector.get_indexes("ioc_index")] == ["ix_ioc_index_type_value"]
    command.downgrade(cfg, "0010_function_rows_capa_rules")
    with engine.connect() as conn:
        assert "ioc_index" not in sa.inspect(conn).get_table_names()


def test_migration_0013_mirrors_ticket_and_severity(tmp_path, monkeypatch):
    url = "sqlite:///" + str(tmp_path / "old.db").replace("\\", "/")
    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY, doc JSON NOT NULL)"))
        conn.execute(
            sa.text("INSERT INTO incidents VALUES ('a', :doc), ('b', '{}')"),
            {"doc": json.dumps({"ticketId": "INC-7", "severity": "high"})},
        )

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0012_search_trigram_indexes")
    command.upgrade(cfg, "0013_incident_ticket_severity")
    with engine.connect() as conn:
        rows = conn.execute(sa.text("SELECT id, ticket_id, severity FROM incidents ORDER BY id")).all()
    assert [tuple(r) for r in rows] == [("a", "INC-7", "high"), ("b", "", "")]
    command.downgrade(cfg, "0012_search_trigram_indexes")
    with engine.connect() as conn:
        assert "ticket_id" not in {c["name"] for c in sa.inspect(conn).get_columns("incidents")}


def test_migration_0014_adds_mails_and_has_mail(tmp_path, monkeypatch):
    url = "sqlite:///" + str(tmp_path / "old.db").replace("\\", "/")
    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY, doc JSON NOT NULL)"))
        conn.execute(sa.text("INSERT INTO incidents VALUES ('a', '{}')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0013_incident_ticket_severity")
    command.upgrade(cfg, "0014_mails")
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT has_mail FROM incidents")).scalar() in (0, False)
        assert "mails" in sa.inspect(conn).get_table_names()
    command.downgrade(cfg, "0013_incident_ticket_severity")
    with engine.connect() as conn:
        assert "mails" not in sa.inspect(conn).get_table_names()
        assert "has_mail" not in {c["name"] for c in sa.inspect(conn).get_columns("incidents")}


def test_migration_0015_adds_enrichment_tables(tmp_path, monkeypatch):
    url = "sqlite:///" + str(tmp_path / "old.db").replace("\\", "/")
    engine = sa.create_engine(url)

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY, doc JSON NOT NULL)"))
    command.stamp(cfg, "0014_mails")
    command.upgrade(cfg, "0015_ioc_enrichment")
    with engine.connect() as conn:
        assert {"ioc_enrichment", "integration_keys", "leases"} <= set(sa.inspect(conn).get_table_names())
    command.downgrade(cfg, "0014_mails")
    with engine.connect() as conn:
        assert not {"ioc_enrichment", "integration_keys", "leases"} & set(sa.inspect(conn).get_table_names())


def test_migration_0016_adds_network_captures(tmp_path, monkeypatch):
    url = "sqlite:///" + str(tmp_path / "old.db").replace("\\", "/")
    engine = sa.create_engine(url)

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0015_ioc_enrichment")
    command.upgrade(cfg, "0016_network_captures")
    with engine.connect() as conn:
        assert "network_captures" in sa.inspect(conn).get_table_names()
    command.downgrade(cfg, "0015_ioc_enrichment")
    with engine.connect() as conn:
        assert "network_captures" not in sa.inspect(conn).get_table_names()


def test_migration_0019_mirrors_status_and_assignee(tmp_path, monkeypatch):
    url = "sqlite:///" + str(tmp_path / "old.db").replace("\\", "/")
    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY, doc JSON NOT NULL)"))
        conn.execute(
            sa.text("INSERT INTO incidents VALUES ('a', :a), ('b', '{}'), ('c', :c)"),
            {"a": json.dumps({"status": "closed", "assignee": "anna"}), "c": json.dumps({"status": "archived"})},
        )

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0018_url_scans")
    command.upgrade(cfg, "0019_incident_status_assignee")
    with engine.connect() as conn:
        rows = conn.execute(sa.text("SELECT id, status, assignee FROM incidents ORDER BY id")).all()
    assert [tuple(r) for r in rows] == [("a", "closed", "anna"), ("b", "open", ""), ("c", "open", "")]
    command.downgrade(cfg, "0018_url_scans")
    with engine.connect() as conn:
        assert "status" not in {c["name"] for c in sa.inspect(conn).get_columns("incidents")}


def test_migration_0020_adds_the_revision(tmp_path, monkeypatch):
    url = "sqlite:///" + str(tmp_path / "old.db").replace("\\", "/")
    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY, doc JSON NOT NULL)"))
        conn.execute(sa.text("INSERT INTO incidents VALUES ('a', '{}')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0019_incident_status_assignee")
    command.upgrade(cfg, "0020_incident_rev")
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT rev FROM incidents")).scalar() == 0
    # Running it on a schema that already has the column changes nothing.
    command.stamp(cfg, "0019_incident_status_assignee")
    command.upgrade(cfg, "0020_incident_rev")
    command.downgrade(cfg, "0019_incident_status_assignee")
    with engine.connect() as conn:
        assert "rev" not in {c["name"] for c in sa.inspect(conn).get_columns("incidents")}


def test_migration_0022_keeps_the_stored_keys_and_adds_raw_and_history(tmp_path, monkeypatch):
    url = "sqlite:///" + str(tmp_path / "old.db").replace("\\", "/")
    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "CREATE TABLE integration_keys (provider VARCHAR PRIMARY KEY, secret TEXT NOT NULL,"
                " hint VARCHAR NOT NULL DEFAULT '', updated_at VARCHAR NOT NULL,"
                " updated_by VARCHAR NOT NULL DEFAULT '')"
            )
        )
        conn.execute(
            sa.text(
                "CREATE TABLE ioc_enrichment (type VARCHAR, value VARCHAR, provider VARCHAR, status VARCHAR,"
                " verdict VARCHAR, summary VARCHAR, link VARCHAR, data JSON, error VARCHAR, checked_at VARCHAR,"
                " PRIMARY KEY (type, value, provider))"
            )
        )
        conn.execute(sa.text("INSERT INTO integration_keys VALUES ('virustotal', 'enc-1', '0001', 't1', 'admin')"))
        conn.execute(sa.text("INSERT INTO integration_keys VALUES ('abuseipdb', 'enc-2', '0002', 't2', 'admin')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0021_user_account_state")
    command.upgrade(cfg, "0022_intel_keys_history")
    with engine.connect() as conn:
        rows = conn.execute(
            sa.text("SELECT provider, secret, hint, status, updated_by, id FROM integration_keys ORDER BY provider")
        ).all()
    assert [tuple(r[:5]) for r in rows] == [
        ("abuseipdb", "enc-2", "0002", "ok", "admin"),
        ("virustotal", "enc-1", "0001", "ok", "admin"),
    ]
    assert len({r[5] for r in rows}) == 2 and all(len(r[5]) == 32 for r in rows)
    with engine.connect() as conn:
        assert "raw" in {c["name"] for c in sa.inspect(conn).get_columns("ioc_enrichment")}
        assert "ioc_enrichment_history" in sa.inspect(conn).get_table_names()
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO integration_keys (id, provider, secret, hint, status, updated_at)"
                " VALUES ('z', 'virustotal', 'enc-3', '0003', 'ok', 't3')"
            )
        )
    command.downgrade(cfg, "0021_user_account_state")
    with engine.connect() as conn:
        back = conn.execute(sa.text("SELECT provider, secret FROM integration_keys ORDER BY provider")).all()
    assert [tuple(r) for r in back] == [("abuseipdb", "enc-2"), ("virustotal", "enc-1")]


def test_migration_0023_adds_the_ioc_library_tables(tmp_path, monkeypatch):
    url = "sqlite:///" + str(tmp_path / "old.db").replace("\\", "/")
    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY)"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0022_intel_keys_history")
    command.upgrade(cfg, "0023_ioc_library")
    tables = {"iocs", "ioc_lists", "ioc_list_items", "ioc_checks", "ioc_alerts"}
    with engine.connect() as conn:
        assert tables <= set(sa.inspect(conn).get_table_names())
        assert {c["name"] for c in sa.inspect(conn).get_columns("iocs")} >= {"type", "value", "tlp", "expires_at"}
    command.downgrade(cfg, "0022_intel_keys_history")
    with engine.connect() as conn:
        assert not tables & set(sa.inspect(conn).get_table_names())


def test_migration_0023_leaves_tables_the_baseline_already_made(tmp_path, monkeypatch):
    """On a new database the baseline creates the schema from the models."""
    url = "sqlite:///" + str(tmp_path / "new.db").replace("\\", "/")
    engine = sa.create_engine(url)
    from app.core.db import Base

    Base.metadata.create_all(engine)
    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0022_intel_keys_history")
    command.upgrade(cfg, "0023_ioc_library")
    with engine.connect() as conn:
        assert "ioc_alerts" in sa.inspect(conn).get_table_names()


def test_migration_0024_adds_the_mailbox_tables_and_leaves_existing_ones(tmp_path, monkeypatch):
    url = "sqlite:///" + str(tmp_path / "old.db").replace("\\", "/")
    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY)"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0023_ioc_library")
    command.upgrade(cfg, "0024_mailboxes")
    with engine.connect() as conn:
        assert {"mailboxes", "mailbox_messages"} <= set(sa.inspect(conn).get_table_names())
        assert {c["name"] for c in sa.inspect(conn).get_columns("mailbox_messages")} >= {"seq", "parent", "thread"}
    command.upgrade(cfg, "0024_mailboxes")  # again: nothing to do
    command.downgrade(cfg, "0023_ioc_library")
    with engine.connect() as conn:
        assert "mailboxes" not in sa.inspect(conn).get_table_names()


def _database_before_roles(tmp_path, monkeypatch):
    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "CREATE TABLE users (id VARCHAR PRIMARY KEY, username VARCHAR NOT NULL UNIQUE,"
                " password_hash VARCHAR NOT NULL, role VARCHAR NOT NULL, created_at VARCHAR NOT NULL,"
                " created_by VARCHAR, disabled BOOLEAN NOT NULL DEFAULT 0, failed_logins INTEGER NOT NULL DEFAULT 0,"
                " locked_until VARCHAR)"
            )
        )
        conn.execute(
            sa.text(
                "CREATE TABLE api_keys (id VARCHAR PRIMARY KEY, label VARCHAR NOT NULL, prefix VARCHAR NOT NULL,"
                " key_hash VARCHAR NOT NULL, role VARCHAR NOT NULL, scopes VARCHAR NOT NULL,"
                " created_at VARCHAR NOT NULL, created_by VARCHAR, expires_at VARCHAR, last_used_at VARCHAR,"
                " revoked_at VARCHAR)"
            )
        )
        for name, role in (("root", "admin"), ("anna", "analyst")):
            conn.execute(
                sa.text("INSERT INTO users VALUES (:n, :n, 'h', :r, 't', NULL, 0, 0, NULL)"), {"n": name, "r": role}
            )
        for label, role, scopes in (
            ("adm", "admin", "read,write,admin"),
            ("rw", "analyst", "read,write"),
            ("ro", "analyst", "read"),
        ):
            conn.execute(
                sa.text("INSERT INTO api_keys VALUES (:l, :l, 'nik_', 'h', :r, :s, 't', NULL, NULL, NULL, NULL)"),
                {"l": label, "r": role, "s": scopes},
            )
    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    return engine


def _stored_roles(engine, table: str, key: str) -> dict:
    with engine.connect() as conn:
        rows = conn.execute(sa.text(f"SELECT {key}, roles, role FROM {table}")).all()  # noqa: S608 (fixed names)
    return {row[0]: (json.loads(row[1]) if isinstance(row[1], str) else row[1], row[2]) for row in rows}


def test_migration_0025_gives_accounts_and_keys_their_roles(tmp_path, monkeypatch):
    engine = _database_before_roles(tmp_path, monkeypatch)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0024_mailboxes")
    command.upgrade(cfg, "0025_roles")

    assert _stored_roles(engine, "users", "username") == {
        "root": (["admin"], "admin"),
        "anna": (["analyst"], "analyst"),
    }
    assert _stored_roles(engine, "api_keys", "label") == {
        "adm": (["admin"], "admin"),
        "rw": (["analyst"], "analyst"),
        "ro": (["viewer"], "analyst"),  # the old columns are left as they were
    }
    with engine.connect() as conn:
        assert "session_epoch" in {c["name"] for c in sa.inspect(conn).get_columns("users")}

    # A second run changes nothing, and keeps roles given since.
    with engine.begin() as conn:
        conn.execute(sa.text("UPDATE users SET roles = '[\"viewer\", \"audit\"]' WHERE username = 'anna'"))
    command.stamp(cfg, "0024_mailboxes")
    command.upgrade(cfg, "0025_roles")
    assert _stored_roles(engine, "users", "username")["anna"] == (["viewer", "audit"], "analyst")

    command.downgrade(cfg, "0024_mailboxes")
    with engine.connect() as conn:
        assert {"roles", "session_epoch"}.isdisjoint({c["name"] for c in sa.inspect(conn).get_columns("users")})
        assert "roles" not in {c["name"] for c in sa.inspect(conn).get_columns("api_keys")}
        assert conn.execute(sa.text("SELECT role FROM users WHERE username = 'root'")).scalar() == "admin"


def test_migration_0026_adds_the_automation_tables_and_leaves_existing_ones(tmp_path, monkeypatch):
    from app.core.models import AUTOMATION_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY)"))
        # One of them is there already (a database the baseline created from the models).
        conn.execute(sa.text("CREATE TABLE scripts (id VARCHAR(32) PRIMARY KEY, name VARCHAR(50) NOT NULL)"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0025_roles")
    command.upgrade(cfg, "0026_automation")
    with engine.connect() as conn:
        tables = set(sa.inspect(conn).get_table_names())
        assert set(AUTOMATION_TABLES) <= tables
        assert {c["name"] for c in sa.inspect(conn).get_columns("scripts")} == {"id", "name"}  # left as it was
        assert {c["name"] for c in sa.inspect(conn).get_columns("run_steps")} >= {"claimed_by", "next_at", "waiting"}
    command.stamp(cfg, "0025_roles")
    command.upgrade(cfg, "0026_automation")  # again: nothing to do
    command.downgrade(cfg, "0025_roles")
    with engine.connect() as conn:
        assert not set(AUTOMATION_TABLES) & set(sa.inspect(conn).get_table_names())


def test_migration_0027_adds_the_connector_tables_and_leaves_existing_ones(tmp_path, monkeypatch):
    from app.core.models import CONNECTOR_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY)"))
        # One of them is there already (a database the baseline created from the models).
        conn.execute(sa.text("CREATE TABLE connectors (id VARCHAR(41) PRIMARY KEY, name VARCHAR(80) NOT NULL)"))
        conn.execute(sa.text("CREATE TABLE playbooks (id VARCHAR(32) PRIMARY KEY, name VARCHAR(120) NOT NULL)"))
        conn.execute(sa.text("INSERT INTO playbooks (id, name) VALUES ('p1', 'Kept')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0026_automation")
    command.upgrade(cfg, "0027_connectors")
    with engine.connect() as conn:
        assert set(CONNECTOR_TABLES) <= set(sa.inspect(conn).get_table_names())
        # The address a playbook can be started at from outside: nobody has one yet.
        assert {c["name"] for c in sa.inspect(conn).get_columns("playbooks")} >= {"hook_hash", "hook_created_at"}
        assert conn.execute(sa.text("SELECT name, hook_hash FROM playbooks")).all() == [("Kept", None)]
        assert {c["name"] for c in sa.inspect(conn).get_columns("connectors")} == {"id", "name"}  # left as it was
        assert {c["name"] for c in sa.inspect(conn).get_columns("connections")} >= {"connector_id", "config", "secrets"}
    command.stamp(cfg, "0026_automation")
    command.upgrade(cfg, "0027_connectors")  # again: nothing to do
    command.downgrade(cfg, "0026_automation")
    with engine.connect() as conn:
        assert not set(CONNECTOR_TABLES) & set(sa.inspect(conn).get_table_names())
        assert {c["name"] for c in sa.inspect(conn).get_columns("playbooks")} == {"id", "name"}


def test_migration_0028_adds_fields_and_types_and_leaves_incidents_as_they_are(tmp_path, monkeypatch):
    from app.core.models import FIELD_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "CREATE TABLE incidents (id VARCHAR PRIMARY KEY, name VARCHAR NOT NULL DEFAULT '', "
                "status VARCHAR NOT NULL DEFAULT 'open', doc JSON NOT NULL)"
            )
        )
        conn.execute(
            sa.text("INSERT INTO incidents (id, name, status, doc) VALUES ('i1', 'Kept', 'closed', '{\"a\": 1}')")
        )
        # One of the tables is there already (a database the baseline created from the models).
        conn.execute(sa.text("CREATE TABLE fields (id VARCHAR(32) PRIMARY KEY, name VARCHAR(41) NOT NULL)"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0027_connectors")
    command.upgrade(cfg, "0028_fields_types")
    added = {"type_id", "fields", "fields_rev", "closed_at", "close_reason", "close_notes", "occurred_at",
             "source_connection_id", "source_id", "mirror"}  # fmt: skip
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert set(FIELD_TABLES) <= set(inspector.get_table_names())
        assert {c["name"] for c in inspector.get_columns("fields")} == {"id", "name"}  # left as it was
        assert added <= {c["name"] for c in inspector.get_columns("incidents")}
        assert {"ix_incidents_type_id", "ix_incidents_status", "uq_incidents_source"} <= {
            index["name"] for index in inspector.get_indexes("incidents")
        }
        # An incident that was there keeps what it held, has no type and no custom field.
        row = conn.execute(sa.text("SELECT name, status, doc, type_id, fields, fields_rev FROM incidents")).one()
        assert (row[0], row[1], row[3], row[5]) == ("Kept", "closed", None, 0)
        assert row[2] in ('{"a": 1}', {"a": 1}) and row[4] in ("{}", {})
        # Two incidents may have no source; two cannot share one.
        conn.execute(sa.text("INSERT INTO incidents (id, doc) VALUES ('i2', '{}')"))
        conn.execute(sa.text("UPDATE incidents SET source_connection_id = 'c1', source_id = 'A-1' WHERE id = 'i1'"))
        with pytest.raises(sa.exc.IntegrityError):
            conn.execute(sa.text("UPDATE incidents SET source_connection_id = 'c1', source_id = 'A-1' WHERE id = 'i2'"))
    command.stamp(cfg, "0027_connectors")
    command.upgrade(cfg, "0028_fields_types")  # again: nothing to do
    command.downgrade(cfg, "0027_connectors")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert not set(FIELD_TABLES) & set(inspector.get_table_names())
        assert {c["name"] for c in inspector.get_columns("incidents")} == {"id", "name", "status", "doc"}
        assert conn.execute(sa.text("SELECT name FROM incidents WHERE id = 'i1'")).scalar() == "Kept"


def test_migration_0029_adds_the_context_and_war_room_tables(tmp_path, monkeypatch):
    from app.core.models import CONTEXT_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY, doc JSON)"))
        conn.execute(sa.text('INSERT INTO incidents (id, doc) VALUES (\'i1\', \'{"notes": [{"text": "kept"}]}\')'))
        # One of them is there already (a database the baseline created from the models).
        conn.execute(sa.text("CREATE TABLE incident_context (incident_id VARCHAR PRIMARY KEY)"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0028_fields_types")
    command.upgrade(cfg, "0029_context_war_room")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert set(CONTEXT_TABLES) <= set(inspector.get_table_names())
        assert {c["name"] for c in inspector.get_columns("incident_context")} == {"incident_id"}  # left as it was
        assert {c["name"] for c in inspector.get_columns("war_room_entries")} >= {"incident_id", "kind", "body", "tags"}
        # The notes of an incident stay where they are.
        assert "kept" in str(conn.execute(sa.text("SELECT doc FROM incidents")).scalar())
    command.stamp(cfg, "0028_fields_types")
    command.upgrade(cfg, "0029_context_war_room")  # again: nothing to do
    command.downgrade(cfg, "0028_fields_types")
    with engine.connect() as conn:
        assert not set(CONTEXT_TABLES) & set(sa.inspect(conn).get_table_names())


def test_migration_0030_adds_the_tables_of_tasks_and_notifications(tmp_path, monkeypatch):
    from app.core.models import TASK_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY)"))
        # One of them is there already (a database the baseline created from the models).
        conn.execute(sa.text("CREATE TABLE notifications (id VARCHAR(32) PRIMARY KEY)"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0029_context_war_room")
    command.upgrade(cfg, "0030_tasks_sla")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert set(TASK_TABLES) <= set(inspector.get_table_names())
        assert {c["name"] for c in inspector.get_columns("notifications")} == {"id"}  # left as it was
        assert {c["name"] for c in inspector.get_columns("tasks")} >= {"incident_id", "step_id", "status", "due_at"}
    command.stamp(cfg, "0029_context_war_room")
    command.upgrade(cfg, "0030_tasks_sla")  # again: nothing to do
    command.downgrade(cfg, "0029_context_war_room")
    with engine.connect() as conn:
        assert not set(TASK_TABLES) & set(sa.inspect(conn).get_table_names())


def test_migration_0030_widens_the_port_of_a_step_on_postgresql(client):
    """A question leaves by a port named after a choice: 12 characters were not enough."""
    import importlib.util
    from pathlib import Path

    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    import app.core.db

    engine = app.core.db.engine
    if engine.dialect.name != "postgresql":
        pytest.skip("SQLite holds no length for a text column")
    spec = importlib.util.spec_from_file_location(
        "m0030", Path(__file__).parent.parent / "alembic" / "versions" / "0030_tasks_sla.py"
    )
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    def length(conn) -> int:
        return next(c for c in sa.inspect(conn).get_columns("run_steps") if c["name"] == "port")["type"].length

    with engine.begin() as conn:
        conn.execute(sa.text("ALTER TABLE run_steps ALTER COLUMN port TYPE varchar(12)"))
        for _ in range(2):  # the second time there is nothing to do
            with Operations.context(MigrationContext.configure(conn)):
                migration.upgrade()
            assert length(conn) == 40


def test_migration_0031_adds_the_lists_and_moves_what_the_settings_held(tmp_path, monkeypatch):
    from app import lists
    from app.core.db import Base
    from app.core.models import LIST_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    held = {"iocAllowlist": ["corp.example"], "mail": {"orgDomains": ["corp.example"], "trustedAuthServers": []}}
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE settings (id INTEGER PRIMARY KEY, doc JSON NOT NULL)"))
        conn.execute(sa.text("INSERT INTO settings (id, doc) VALUES (1, :doc)"), {"doc": json.dumps(held)})
        for table in ("playbooks", "playbook_versions", "ioc_lists", "ioc_list_items"):
            Base.metadata.tables[table].create(conn)

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    lists.clear_cache()
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0030_tasks_sla")
    command.upgrade(cfg, "0031_lists")
    lists.clear_cache()
    with engine.connect() as conn:
        assert set(LIST_TABLES) <= set(sa.inspect(conn).get_table_names())
        names = {row[0] for row in conn.execute(sa.text("SELECT name FROM lists"))}
        assert names == set(lists.BUILTIN)
        doc = json.loads(conn.execute(sa.text("SELECT doc FROM settings WHERE id = 1")).scalar())
        assert doc["iocAllowlist"] == {"list": "ioc_allowlist"}
        assert doc["mail"]["orgDomains"] == {"list": "internal_domains"}
        kept = conn.execute(
            sa.text("SELECT i.key FROM list_items i JOIN lists l ON l.id = i.list_id WHERE l.name = 'ioc_allowlist'")
        ).fetchall()
        assert [row[0] for row in kept] == ["corp.example"]
    command.stamp(cfg, "0030_tasks_sla")
    command.upgrade(cfg, "0031_lists")  # again: the lists are there, nothing moves
    lists.clear_cache()
    command.downgrade(cfg, "0030_tasks_sla")
    lists.clear_cache()
    with engine.connect() as conn:
        assert not set(LIST_TABLES) & set(sa.inspect(conn).get_table_names())
        doc = json.loads(conn.execute(sa.text("SELECT doc FROM settings WHERE id = 1")).scalar())
        assert doc["iocAllowlist"] == ["corp.example"] and doc["mail"]["orgDomains"] == ["corp.example"]


def test_migration_0032_adds_the_tables_and_columns_of_fetching(tmp_path, monkeypatch):
    from app.core.models import FETCH_COLUMNS, FETCH_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        # A connection as releases before this one knew it, and one table that is there already.
        conn.execute(sa.text("CREATE TABLE connections (id VARCHAR(32) PRIMARY KEY, name VARCHAR(80) NOT NULL)"))
        conn.execute(sa.text("INSERT INTO connections (id, name) VALUES ('c1', 'SOC')"))
        conn.execute(sa.text("CREATE TABLE mappers (id VARCHAR(32) PRIMARY KEY)"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0031_lists")
    command.upgrade(cfg, "0032_fetch_mappers")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert set(FETCH_TABLES) <= set(inspector.get_table_names())
        assert {c["name"] for c in inspector.get_columns("mappers")} == {"id"}  # left as it was
        assert set(FETCH_COLUMNS["connections"]) <= {c["name"] for c in inspector.get_columns("connections")}
        # The connection that was there fetches nothing.
        assert conn.execute(sa.text("SELECT fetch_enabled, fetch_state FROM connections")).one() in (
            (0, None),
            (False, None),
        )
    command.stamp(cfg, "0031_lists")
    command.upgrade(cfg, "0032_fetch_mappers")  # again: nothing to do
    command.downgrade(cfg, "0031_lists")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert not set(FETCH_TABLES) & set(inspector.get_table_names())
        assert {c["name"] for c in inspector.get_columns("connections")} == {"id", "name"}


def test_migration_0033_adds_the_tables_of_dashboards_and_packs(tmp_path, monkeypatch):
    from app.core.models import DASHBOARD_PACK_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        # A run as releases before this one knew it.
        conn.execute(sa.text("CREATE TABLE runs (id VARCHAR(32) PRIMARY KEY, status VARCHAR(10))"))
        conn.execute(sa.text("INSERT INTO runs (id, status) VALUES ('r1', 'done')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0032_fetch_mappers")
    command.upgrade(cfg, "0033_dashboards_packs")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert set(DASHBOARD_PACK_TABLES) <= set(inspector.get_table_names())
        # The run that was there is not a debug run.
        assert conn.execute(sa.text("SELECT debug FROM runs")).scalar() in (0, False)
        assert {"layout", "shared_with", "builtin"} <= {c["name"] for c in inspector.get_columns("dashboards")}
        assert {"kind", "name", "pack_id"} <= {c["name"] for c in inspector.get_columns("pack_items")}
    command.stamp(cfg, "0032_fetch_mappers")
    command.upgrade(cfg, "0033_dashboards_packs")  # again: nothing to do
    command.downgrade(cfg, "0032_fetch_mappers")
    with engine.connect() as conn:
        assert not set(DASHBOARD_PACK_TABLES) & set(sa.inspect(conn).get_table_names())
        assert {c["name"] for c in sa.inspect(conn).get_columns("runs")} == {"id", "status"}


def test_migration_0034_adds_the_tables_and_columns_of_4_7(tmp_path, monkeypatch):
    from app.core.models import MISC_COLUMNS, MISC_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        # What releases before this one knew of the tables that gain columns.
        conn.execute(sa.text("CREATE TABLE artifacts (id VARCHAR(80) PRIMARY KEY, kind VARCHAR(10))"))
        conn.execute(sa.text("INSERT INTO artifacts (id, kind) VALUES ('file-1', 'file')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0033_dashboards_packs")
    command.upgrade(cfg, "0034_misc")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert set(MISC_TABLES) <= set(inspector.get_table_names())
        for table, columns in MISC_COLUMNS.items():
            if table in inspector.get_table_names():
                assert set(columns) <= {c["name"] for c in inspector.get_columns(table)}
        assert conn.execute(sa.text("SELECT COUNT(*) FROM artifacts")).scalar() == 1
    command.stamp(cfg, "0033_dashboards_packs")
    command.upgrade(cfg, "0034_misc")  # again: nothing to do
    command.downgrade(cfg, "0033_dashboards_packs")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert not set(MISC_TABLES) & set(inspector.get_table_names())
        assert {c["name"] for c in inspector.get_columns("artifacts")} == {"id", "kind"}


def test_migration_0035_numbers_the_incidents_and_rewrites_stored_queries(tmp_path, monkeypatch):
    from app.core.models import NUMBER_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        # What 4.7 knew of the two tables this release touches.
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY, name VARCHAR, created_at VARCHAR)"))
        for incident_id, created in (("c", "2026-03-01"), ("a", "2026-01-01"), ("b", "2026-02-01")):
            conn.execute(
                sa.text("INSERT INTO incidents (id, name, created_at) VALUES (:id, :id, :at)"),
                {"id": incident_id, "at": created},
            )
        conn.execute(sa.text("CREATE TABLE dashboards (id VARCHAR PRIMARY KEY, layout JSON, filter_query VARCHAR)"))
        conn.execute(
            sa.text("INSERT INTO dashboards (id, layout, filter_query) VALUES ('d1', :layout, 'status:!closed')"),
            {
                "layout": json.dumps(
                    [{"id": "w1", "query": "severity:>=high owner:!anna"}, {"id": "w2", "type": "note"}]
                )
            },
        )
        conn.execute(sa.text("INSERT INTO dashboards (id, layout, filter_query) VALUES ('d2', '[]', '')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0034_misc")
    command.upgrade(cfg, "0035_incident_numbers")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert set(NUMBER_TABLES) <= set(inspector.get_table_names())
        # Numbered in the order they were created, and the counter stands at the last.
        numbers = dict(conn.execute(sa.text("SELECT id, number FROM incidents")).all())
        assert numbers == {"a": 1, "b": 2, "c": 3}
        assert conn.execute(sa.text("SELECT value FROM sequences WHERE name = 'incidents'")).scalar() == 3
        assert "uq_incidents_number" in {index["name"] for index in inspector.get_indexes("incidents")}
        layout, filter_query = conn.execute(
            sa.text("SELECT layout, filter_query FROM dashboards WHERE id = 'd1'")
        ).one()
        assert json.loads(layout)[0]["query"] == "severity:>=high !owner:anna"
        assert filter_query == "!status:closed"
    with engine.begin() as conn:
        # An incident made by 4.7 code against the new schema would have no number: the migration,
        # run again, gives it the next one and leaves the others alone.
        conn.execute(sa.text("INSERT INTO incidents (id, name, created_at) VALUES ('d', 'd', '2025-01-01')"))
    command.stamp(cfg, "0034_misc")
    command.upgrade(cfg, "0035_incident_numbers")
    with engine.connect() as conn:
        assert dict(conn.execute(sa.text("SELECT id, number FROM incidents")).all()) == {"a": 1, "b": 2, "c": 3, "d": 4}
        assert conn.execute(sa.text("SELECT value FROM sequences WHERE name = 'incidents'")).scalar() == 4
    command.downgrade(cfg, "0034_misc")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert "sequences" not in inspector.get_table_names()
        assert {c["name"] for c in inspector.get_columns("incidents")} == {"id", "name", "created_at"}
        assert conn.execute(sa.text("SELECT COUNT(*) FROM incidents")).scalar() == 4


def test_migration_0036_leaves_every_connection_on(tmp_path, monkeypatch):
    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE connections (id VARCHAR(32) PRIMARY KEY, name VARCHAR(80))"))
        conn.execute(sa.text("CREATE TABLE connectors (id VARCHAR(41) PRIMARY KEY, name VARCHAR(80))"))
        conn.execute(sa.text("INSERT INTO connectors (id, name) VALUES ('acme', 'Acme')"))
        conn.execute(sa.text("INSERT INTO connections (id, name) VALUES ('c1', 'Desk'), ('c2', 'Desk test')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0035_incident_numbers")
    command.upgrade(cfg, "0036_instances")
    with engine.connect() as conn:
        assert [bool(row[0]) for row in conn.execute(sa.text("SELECT enabled FROM connections"))] == [True, True]
        # A connector there was has no logo and an empty README.
        assert conn.execute(sa.text("SELECT logo, logo_type, readme FROM connectors")).one() == (None, "", "")
    command.stamp(cfg, "0035_incident_numbers")
    command.upgrade(cfg, "0036_instances")  # again: nothing to do
    command.downgrade(cfg, "0035_incident_numbers")
    with engine.connect() as conn:
        assert {c["name"] for c in sa.inspect(conn).get_columns("connections")} == {"id", "name"}
        assert {c["name"] for c in sa.inspect(conn).get_columns("connectors")} == {"id", "name"}
        assert conn.execute(sa.text("SELECT COUNT(*) FROM connections")).scalar() == 2


def test_migration_0037_adds_the_branches_of_playbooks(tmp_path, monkeypatch):
    from app.core.models import BRANCH_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE playbooks (id VARCHAR(32) PRIMARY KEY, name VARCHAR(120))"))
        conn.execute(sa.text("INSERT INTO playbooks (id, name) VALUES ('p1', 'One')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0036_instances")
    command.upgrade(cfg, "0037_branches")
    with engine.connect() as conn:
        assert set(BRANCH_TABLES) <= set(sa.inspect(conn).get_table_names())
        assert conn.execute(sa.text("SELECT COUNT(*) FROM playbook_branches")).scalar() == 0
    command.stamp(cfg, "0036_instances")
    command.upgrade(cfg, "0037_branches")  # again: nothing to do
    command.downgrade(cfg, "0036_instances")
    with engine.connect() as conn:
        assert "playbook_branches" not in sa.inspect(conn).get_table_names()
        assert conn.execute(sa.text("SELECT COUNT(*) FROM playbooks")).scalar() == 1


def test_migration_0038_adds_the_playground(tmp_path, monkeypatch):
    from app.core.models import INCIDENT_PAGE_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY)"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0037_branches")
    command.upgrade(cfg, "0038_incident_page")
    with engine.connect() as conn:
        assert set(INCIDENT_PAGE_TABLES) <= set(sa.inspect(conn).get_table_names())
    command.stamp(cfg, "0037_branches")
    command.upgrade(cfg, "0038_incident_page")  # again: nothing to do
    command.downgrade(cfg, "0037_branches")
    with engine.connect() as conn:
        assert set(sa.inspect(conn).get_table_names()) >= {"incidents"}
        assert "playground_entries" not in sa.inspect(conn).get_table_names()


def test_migration_0039_adds_where_a_pack_came_from(tmp_path, monkeypatch):
    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE packs (id VARCHAR(49) PRIMARY KEY, name VARCHAR(120))"))
        conn.execute(sa.text("CREATE TABLE pack_items (kind VARCHAR(20), name VARCHAR(200), pack_id VARCHAR(49))"))
        conn.execute(sa.text("INSERT INTO packs (id, name) VALUES ('mine', 'Mine')"))
        conn.execute(sa.text("INSERT INTO pack_items (kind, name, pack_id) VALUES ('scripts', 'One', 'mine')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0038_incident_page")
    command.upgrade(cfg, "0039_pack_catalogue")
    with engine.connect() as conn:
        assert {"source", "logo", "logo_type"} <= {c["name"] for c in sa.inspect(conn).get_columns("packs")}
        assert conn.execute(sa.text("SELECT source, logo_type FROM packs")).one() == ("file", "")
        assert conn.execute(sa.text("SELECT digest FROM pack_items")).scalar() == ""
    command.stamp(cfg, "0038_incident_page")
    command.upgrade(cfg, "0039_pack_catalogue")  # again: nothing to do
    command.downgrade(cfg, "0038_incident_page")
    with engine.connect() as conn:
        assert {c["name"] for c in sa.inspect(conn).get_columns("packs")} == {"id", "name"}
        assert "digest" not in {c["name"] for c in sa.inspect(conn).get_columns("pack_items")}


def test_migration_0040_adds_the_keys_of_an_instance(tmp_path, monkeypatch):
    from app.core.models import INSTANCE_KEY_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE connectors (id VARCHAR(41) PRIMARY KEY)"))
        conn.execute(sa.text("CREATE TABLE connections (id VARCHAR(32) PRIMARY KEY, name VARCHAR(80))"))
        conn.execute(sa.text("INSERT INTO connections (id, name) VALUES ('c1', 'Mine')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0039_pack_catalogue")
    command.upgrade(cfg, "0040_instance_keys")
    with engine.connect() as conn:
        assert set(INSTANCE_KEY_TABLES) <= set(sa.inspect(conn).get_table_names())
        assert conn.execute(sa.text("SELECT extra_keys, key_policy FROM connections")).one() == ("", None)
    command.stamp(cfg, "0039_pack_catalogue")
    command.upgrade(cfg, "0040_instance_keys")  # again: nothing to do
    command.downgrade(cfg, "0039_pack_catalogue")
    with engine.connect() as conn:
        assert not set(INSTANCE_KEY_TABLES) & set(sa.inspect(conn).get_table_names())
        assert {c["name"] for c in sa.inspect(conn).get_columns("connections")} == {"id", "name"}


def test_migration_0041_adds_the_saved_filters(tmp_path, monkeypatch):
    from app.core.models import SAVED_FILTER_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY)"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0040_instance_keys")
    command.upgrade(cfg, "0041_saved_filters")
    with engine.begin() as conn:
        assert set(SAVED_FILTER_TABLES) <= set(sa.inspect(conn).get_table_names())
        conn.execute(
            sa.text(
                "INSERT INTO saved_filters (id, owner, name, entity, query, columns, created_at, updated_at) "
                "VALUES ('f1', 'admin', 'Mine', 'incidents', 'status:open', '[]', 'now', 'now')"
            )
        )
        assert conn.execute(sa.text("SELECT shared, sort FROM saved_filters")).one() == (0, None)
    command.stamp(cfg, "0040_instance_keys")
    command.upgrade(cfg, "0041_saved_filters")  # again: nothing to do, and what was saved is still there
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT name FROM saved_filters")).scalar() == "Mine"
    command.downgrade(cfg, "0040_instance_keys")
    with engine.connect() as conn:
        assert not set(SAVED_FILTER_TABLES) & set(sa.inspect(conn).get_table_names())


def test_migration_0043_adds_how_an_instance_fetches(tmp_path, monkeypatch):
    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE connections (id VARCHAR(32) PRIMARY KEY, name VARCHAR(80))"))
        conn.execute(sa.text("INSERT INTO connections (id, name) VALUES ('c1', 'Mine')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0041_saved_filters")
    command.upgrade(cfg, "0043_instance_fetch")
    with engine.begin() as conn:
        # An instance that was there fetches as its connector says: nothing is set for it.
        assert conn.execute(sa.text("SELECT name, fetch_settings FROM connections")).one() == ("Mine", None)
        conn.execute(sa.text("UPDATE connections SET fetch_settings = '{\"lookbackMinutes\": 5}'"))
    command.stamp(cfg, "0041_saved_filters")
    command.upgrade(cfg, "0043_instance_fetch")  # again: nothing to do, and what was set is still there
    with engine.connect() as conn:
        assert "lookbackMinutes" in conn.execute(sa.text("SELECT fetch_settings FROM connections")).scalar()
    command.downgrade(cfg, "0041_saved_filters")
    with engine.connect() as conn:
        assert {c["name"] for c in sa.inspect(conn).get_columns("connections")} == {"id", "name"}


def test_migration_0044_drops_the_single_role_and_the_scopes_once_every_row_has_roles(tmp_path, monkeypatch):
    engine = _database_before_roles(tmp_path, monkeypatch)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0024_mailboxes")
    command.upgrade(cfg, "0025_roles")
    with engine.begin() as conn:
        # Roles given since 4.0 are what counts, whatever the old columns still say.
        conn.execute(sa.text("UPDATE users SET roles = '[\"viewer\", \"audit\"]' WHERE username = 'anna'"))
        # Rows that something wrote without roles: they get what their old columns stand for.
        conn.execute(sa.text("INSERT INTO users VALUES ('late', 'late', 'h', 'admin', 't', NULL, 0, 0, NULL, '[]', 0)"))
        conn.execute(
            sa.text(
                "INSERT INTO api_keys VALUES"
                " ('late', 'late', 'nik_', 'h', 'analyst', 'read', 't', NULL, NULL, NULL, NULL, '[]')"
            )
        )

    def roles(table: str, key: str) -> dict:
        with engine.connect() as conn:
            rows = conn.execute(sa.text(f"SELECT {key}, roles FROM {table}")).all()  # noqa: S608 (fixed names)
        return {row[0]: json.loads(row[1]) if isinstance(row[1], str) else row[1] for row in rows}

    def columns(table: str) -> set:
        with engine.connect() as conn:
            return {c["name"] for c in sa.inspect(conn).get_columns(table)}

    command.stamp(cfg, "0043_instance_fetch")
    command.upgrade(cfg, "0044_no_legacy_roles")
    assert "role" not in columns("users") and {"role", "scopes"}.isdisjoint(columns("api_keys"))
    assert roles("users", "username") == {"root": ["admin"], "anna": ["viewer", "audit"], "late": ["admin"]}
    assert roles("api_keys", "label") == {"adm": ["admin"], "rw": ["analyst"], "ro": ["viewer"], "late": ["viewer"]}

    command.stamp(cfg, "0043_instance_fetch")
    command.upgrade(cfg, "0044_no_legacy_roles")  # again: the columns are gone, nothing to do
    assert roles("users", "username")["anna"] == ["viewer", "audit"]

    # A downgrade puts the old columns back, filled from the roles.
    command.downgrade(cfg, "0043_instance_fetch")
    with engine.connect() as conn:
        assert dict(conn.execute(sa.text("SELECT username, role FROM users")).all()) == {
            "root": "admin",
            "anna": "analyst",
            "late": "admin",
        }
        assert {
            row[0]: (row[1], row[2]) for row in conn.execute(sa.text("SELECT label, role, scopes FROM api_keys"))
        } == {
            "adm": ("admin", "read,write,admin"),
            "rw": ("analyst", "read,write"),
            "ro": ("analyst", "read"),
            "late": ("analyst", "read"),
        }


def test_migration_0025_has_nothing_to_fill_on_a_database_that_never_had_the_single_role(tmp_path, monkeypatch):
    engine = sa.create_engine("sqlite:///" + str(tmp_path / "new.db").replace("\\", "/"))
    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    # The baseline makes the tables as the models are now: with roles, without the old columns.
    command.upgrade(cfg, "0025_roles")
    with engine.connect() as conn:
        names = {c["name"] for c in sa.inspect(conn).get_columns("users")}
    assert "roles" in names and "role" not in names
    command.upgrade(cfg, "0044_no_legacy_roles")


def test_migration_0045_files_the_stored_answers_under_the_connectors(tmp_path, monkeypatch):
    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    answers = [
        ("ip", "198.51.100.7", "internetdb", "malicious", "ports 22; tags c2"),
        ("ip", "198.51.100.7", "virustotal", "malicious", "7/88 engines flag it"),
        ("domain", "evil.example", "registration", "suspicious", "registered 3 days ago"),
        ("sha256", "a" * 64, "abusech", "malicious", "MalwareBazaar: AgentTesla"),
        ("url", "http://evil.example/x", "abusech", "malicious", "URLhaus: malware_download (online)"),
        ("ip", "198.51.100.7", "abusech", "malicious", "ThreatFox: Cobalt Strike (botnet_cc)"),
        ("domain", "evil.example", "abusech", "unknown", "not in ThreatFox or URLhaus"),
    ]
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "CREATE TABLE ioc_enrichment (type VARCHAR, value VARCHAR, provider VARCHAR, verdict VARCHAR,"
                " summary VARCHAR, PRIMARY KEY (type, value, provider))"
            )
        )
        conn.execute(
            sa.text(
                "CREATE TABLE ioc_enrichment_history (id VARCHAR PRIMARY KEY, type VARCHAR, value VARCHAR,"
                " provider VARCHAR, verdict VARCHAR, summary VARCHAR)"
            )
        )
        conn.execute(sa.text("CREATE TABLE integration_keys (id VARCHAR PRIMARY KEY, provider VARCHAR)"))
        conn.execute(sa.text("INSERT INTO integration_keys VALUES ('k1', 'abusech')"))
        for index, row in enumerate(answers):
            values = dict(zip(("type", "value", "provider", "verdict", "summary"), row, strict=True))
            conn.execute(
                sa.text("INSERT INTO ioc_enrichment VALUES (:type, :value, :provider, :verdict, :summary)"), values
            )
            conn.execute(
                sa.text(
                    "INSERT INTO ioc_enrichment_history VALUES (:id, :type, :value, :provider, :verdict, :summary)"
                ),
                {"id": f"h{index}", **values},
            )

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    expected = {
        ("ip", "198.51.100.7", "shodan", "malicious"),
        ("ip", "198.51.100.7", "virustotal", "malicious"),
        ("domain", "evil.example", "rdap", "suspicious"),
        ("sha256", "a" * 64, "malwarebazaar", "malicious"),
        ("url", "http://evil.example/x", "urlhaus", "malicious"),
        ("ip", "198.51.100.7", "threatfox", "malicious"),
    }
    for _again in range(2):  # the second time there is nothing to do
        command.stamp(cfg, "0044_no_legacy_roles")
        command.upgrade(cfg, "0045_lookups_through_connectors")
        with engine.connect() as conn:
            for table in ("ioc_enrichment", "ioc_enrichment_history"):
                found = conn.execute(sa.text(f"SELECT type, value, provider, verdict FROM {table}")).all()
                assert {tuple(row) for row in found} == expected, table
            # The keys are not touched here: the application moves them when it can.
            assert conn.execute(sa.text("SELECT provider FROM integration_keys")).scalar() == "abusech"
    command.downgrade(cfg, "0044_no_legacy_roles")
    with engine.connect() as conn:
        providers = set(conn.execute(sa.text("SELECT provider FROM ioc_enrichment")).scalars())
        assert {"internetdb", "registration", "malwarebazaar"} <= providers and "shodan" not in providers


def test_migration_0046_adds_the_stored_credentials_and_touches_no_instance(tmp_path, monkeypatch):
    from app.core.models import CREDENTIAL_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE connections (id VARCHAR(32) PRIMARY KEY, name VARCHAR(80), secrets TEXT)"))
        conn.execute(sa.text("INSERT INTO connections VALUES ('c1', 'Mine', 'encrypted-as-it-was')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0045_lookups_through_connectors")
    command.upgrade(cfg, "0046_credentials")
    with engine.begin() as conn:
        assert set(CREDENTIAL_TABLES) <= set(sa.inspect(conn).get_table_names())
        conn.execute(
            sa.text(
                "INSERT INTO credentials (id, name, title, kind, username, secret, created_at, created_by,"
                " updated_at, updated_by) VALUES ('k1', 'vt_key', '', 'secret', '', 'x', 'now', '', 'now', '')"
            )
        )
        # What an instance holds is as it was: a typed secret becomes a credential only when someone asks.
        assert conn.execute(sa.text("SELECT secrets FROM connections")).scalar() == "encrypted-as-it-was"
    command.stamp(cfg, "0045_lookups_through_connectors")
    command.upgrade(cfg, "0046_credentials")  # again: nothing to do, and what was stored is still there
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT name FROM credentials")).scalar() == "vt_key"
        with pytest.raises(sa.exc.IntegrityError):  # a name is one credential
            conn.execute(
                sa.text(
                    "INSERT INTO credentials (id, name, title, kind, username, secret, created_at, created_by,"
                    " updated_at, updated_by) VALUES ('k2', 'vt_key', '', 'secret', '', 'x', 'now', '', 'now', '')"
                )
            )
    command.downgrade(cfg, "0045_lookups_through_connectors")
    with engine.connect() as conn:
        assert not set(CREDENTIAL_TABLES) & set(sa.inspect(conn).get_table_names())
        assert conn.execute(sa.text("SELECT secrets FROM connections")).scalar() == "encrypted-as-it-was"


def test_migration_0047_adds_what_a_playbook_asks_about_a_file(tmp_path, monkeypatch):
    from app.core.models import PLAYBOOK_FILE_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE samples (sha256 VARCHAR(64) PRIMARY KEY)"))
        conn.execute(sa.text("INSERT INTO samples (sha256) VALUES ('" + "a" * 64 + "')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0046_credentials")
    command.upgrade(cfg, "0047_playbook_files")
    with engine.connect() as conn:
        assert set(PLAYBOOK_FILE_TABLES) <= set(sa.inspect(conn).get_table_names())
        columns = {column["name"] for column in sa.inspect(conn).get_columns("artifact_jobs")}
        assert {"id", "kind", "status", "params", "result", "error", "run_id", "depth"} <= columns
        parts = {column["name"] for column in sa.inspect(conn).get_columns("artifact_job_parts")}
        assert parts == {"job_id", "seq", "data"}
        assert conn.execute(sa.text("SELECT count(*) FROM samples")).scalar() == 1
    command.stamp(cfg, "0046_credentials")
    command.upgrade(cfg, "0047_playbook_files")  # again: the table is there, nothing to do
    command.downgrade(cfg, "0046_credentials")
    with engine.connect() as conn:
        assert not set(PLAYBOOK_FILE_TABLES) & set(sa.inspect(conn).get_table_names())
        assert conn.execute(sa.text("SELECT count(*) FROM samples")).scalar() == 1


def test_migration_0048_adds_the_table_of_the_backups_and_touches_nothing_else(tmp_path, monkeypatch):
    from app.core.models import BACKUP_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE settings (id INTEGER PRIMARY KEY, doc JSON NOT NULL)"))
        conn.execute(sa.text("INSERT INTO settings (id, doc) VALUES (1, '{}')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0047_playbook_files")
    command.upgrade(cfg, "0048_backups")
    with engine.connect() as conn:
        assert set(BACKUP_TABLES) <= set(sa.inspect(conn).get_table_names())
        columns = {column["name"] for column in sa.inspect(conn).get_columns("backups")}
        assert {"id", "kind", "state", "size", "verify_state", "verify", "local", "offsite_state", "offsite"} <= columns
        assert conn.execute(sa.text("SELECT count(*) FROM settings")).scalar() == 1
    command.stamp(cfg, "0047_playbook_files")
    command.upgrade(cfg, "0048_backups")  # again: the table is there, nothing to do
    command.downgrade(cfg, "0047_playbook_files")
    with engine.connect() as conn:
        assert not set(BACKUP_TABLES) & set(sa.inspect(conn).get_table_names())
        assert conn.execute(sa.text("SELECT count(*) FROM settings")).scalar() == 1


def test_migration_0049_adds_the_second_factor_and_keeps_the_open_sessions(tmp_path, monkeypatch):
    from app.core.models import TWO_FACTOR_COLUMNS, TWO_FACTOR_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "CREATE TABLE users (id VARCHAR PRIMARY KEY, username VARCHAR NOT NULL UNIQUE,"
                " password_hash VARCHAR NOT NULL, roles JSON NOT NULL, session_epoch INTEGER NOT NULL DEFAULT 0,"
                " created_at VARCHAR NOT NULL, created_by VARCHAR, disabled BOOLEAN NOT NULL DEFAULT 0,"
                " failed_logins INTEGER NOT NULL DEFAULT 0, locked_until VARCHAR)"
            )
        )
        conn.execute(
            sa.text(
                "CREATE TABLE sessions (token VARCHAR PRIMARY KEY,"
                " user_id VARCHAR NOT NULL REFERENCES users (id) ON DELETE CASCADE,"
                " created_at VARCHAR NOT NULL, expires_at VARCHAR NOT NULL)"
            )
        )
        conn.execute(
            sa.text("INSERT INTO users VALUES ('u1', 'anna', 'hash', '[\"analyst\"]', 0, 't', NULL, 0, 3, NULL)")
        )
        for token in ("one", "two"):
            conn.execute(
                sa.text("INSERT INTO sessions VALUES (:token, 'u1', '2026-11-20T08:00:00+00:00', :ends)"),
                {"token": token, "ends": "2026-11-20T20:00:00+00:00"},
            )

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0048_backups")
    command.upgrade(cfg, "0049_two_factor")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert set(TWO_FACTOR_TABLES) <= set(inspector.get_table_names())
        for table, added in TWO_FACTOR_COLUMNS.items():
            assert set(added) <= {column["name"] for column in inspector.get_columns(table)}, table
        factor = {column["name"] for column in inspector.get_columns("user_factors")}
        assert factor == {"id", "user_id", "kind", "secret", "data", "created_at", "confirmed_at", "last_step"}
        # The sessions that were open stay open: a name each, and a last use that is the upgrade.
        rows = conn.execute(sa.text("SELECT token, public_id, last_used_at, expires_at FROM sessions")).all()
        assert len(rows) == 2 and len({row[1] for row in rows}) == 2
        assert all(row[1] and row[2] and row[3] == "2026-11-20T20:00:00+00:00" for row in rows)
        named = {row[0]: row[1] for row in rows}
        # The account is as it was: no factor, nothing it is told, nothing asked of it.
        user = conn.execute(sa.text("SELECT username, password_hash, signin_addresses, signin_notice FROM users")).one()
        assert tuple(user) == ("anna", "hash", None, None)
        assert conn.execute(sa.text("SELECT count(*) FROM user_factors")).scalar() == 0
    command.stamp(cfg, "0048_backups")
    command.upgrade(cfg, "0049_two_factor")  # again: everything is there, and the sessions keep their names
    with engine.connect() as conn:
        again = dict(conn.execute(sa.text("SELECT token, public_id FROM sessions")).all())
        assert again == named
    command.downgrade(cfg, "0048_backups")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert not set(TWO_FACTOR_TABLES) & set(inspector.get_table_names())
        assert {column["name"] for column in inspector.get_columns("sessions")} == {
            "token",
            "user_id",
            "created_at",
            "expires_at",
        }
        assert "signin_notice" not in {column["name"] for column in inspector.get_columns("users")}
        assert conn.execute(sa.text("SELECT count(*) FROM sessions")).scalar() == 2
        assert conn.execute(sa.text("SELECT failed_logins FROM users")).scalar() == 3


def test_migration_0051_links_the_entries_that_are_there_as_they_are_and_says_so(tmp_path, monkeypatch):
    from app.auditlog import verifier
    from app.core.models import AUDIT_CHAIN_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    old = [
        ("c", "2026-03-01T10:00:00+00:00", "anna", "incident.create", "Case 1", 'Created "Case 1"', "i1", "Case 1"),
        ("a", "2026-01-05T08:00:00+00:00", "admin", "user.create", None, "Created the account anna", None, None),
        ("b", "2026-01-05T08:00:00+00:00", "admin", "auth.login", None, "", None, None),
        ("d", "not a time", "imported", "odd", None, "from a file of another server é", None, None),
    ]
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "CREATE TABLE audit_log (id VARCHAR PRIMARY KEY, at VARCHAR NOT NULL, actor VARCHAR NOT NULL,"
                " action VARCHAR NOT NULL, target VARCHAR, details VARCHAR NOT NULL DEFAULT '',"
                " incident_id VARCHAR, incident_name VARCHAR)"
            )
        )
        for row in old:
            conn.execute(
                sa.text("INSERT INTO audit_log VALUES (:a, :b, :c, :d, :e, :f, :g, :h)"),
                dict(zip("abcdefgh", row, strict=True)),
            )

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0049_two_factor")
    command.upgrade(cfg, "0051_audit_chain")

    def entries():
        with engine.connect() as conn:
            rows = conn.execute(sa.text("SELECT * FROM audit_log ORDER BY seq")).mappings().all()
        return [dict(row) | {"prev": row["prev_hash"]} for row in rows]

    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert set(AUDIT_CHAIN_TABLES) <= set(inspector.get_table_names())
        assert {"seq", "prev_hash", "hash", "origin", "mac", "key_id"} <= {
            column["name"] for column in inspector.get_columns("audit_log")
        }
        assert any(
            index["name"] == "ux_audit_log_seq" and index["unique"] for index in inspector.get_indexes("audit_log")
        )
    found = entries()
    # In the order of their time (then of their id), each exactly as it was.
    assert [entry["id"] for entry in found[:4]] == ["a", "b", "c", "d"]
    assert sorted(tuple(entry[name] for name in verifier.FIELDS) for entry in found[:4]) == sorted(old)
    assert [entry["seq"] for entry in found] == [1, 2, 3, 4, 5] and found[0]["prev"] == "0" * 64
    # The link the server answers for comes after them and says what it cannot answer for.
    marker = found[4]
    assert (marker["action"], marker["actor"], marker["prev"]) == ("audit.chain", "nik", found[3]["hash"])
    assert marker["details"].startswith("The 4 entries before this one were written before the audit log was chained")
    assert f"sequence 1 to 4, up to hash {found[3]['hash']}" in marker["details"]
    walk = verifier.check(found)
    assert walk.problem is None and walk.count == 5
    # Signed in the same pass, every one, with the key of the server; none is marked.
    from app.auditlog import key as signing

    signed = verifier.check(found, signing.known())
    assert signed.problem is None and signed.signed == 5 and signed.unchecked == {}
    assert {entry["key_id"] for entry in found} == {signing.current()[0]} and {entry["origin"] for entry in found} == {
        None
    }
    with engine.connect() as conn:
        assert tuple(conn.execute(sa.text("SELECT seq, hash FROM audit_chain WHERE id = 1")).one()) == (
            5,
            marker["hash"],
        )
    # Again: nothing is linked twice, and nothing is said twice. An entry that arrived since is linked after.
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "INSERT INTO audit_log (id, at, actor, action, details) VALUES ('e', '2026-12-01', 'x', 'late', '')"
            )
        )
    command.stamp(cfg, "0049_two_factor")
    command.upgrade(cfg, "0051_audit_chain")
    again = entries()
    assert again[:5] == found and [entry["id"] for entry in again] == ["a", "b", "c", "d", marker["id"], "e"]
    assert verifier.check(again).problem is None
    command.downgrade(cfg, "0049_two_factor")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert not set(AUDIT_CHAIN_TABLES) & set(inspector.get_table_names())
        assert not {"seq", "prev_hash", "hash", "origin", "mac", "key_id"} & {
            column["name"] for column in inspector.get_columns("audit_log")
        }
        # The entries are as they were, with the one the upgrade added.
        assert conn.execute(sa.text("SELECT count(*) FROM audit_log")).scalar() == 6


def test_migration_0051_on_a_log_that_is_empty_starts_the_chain_at_nothing(tmp_path, monkeypatch):
    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "CREATE TABLE audit_log (id VARCHAR PRIMARY KEY, at VARCHAR NOT NULL, actor VARCHAR NOT NULL,"
                " action VARCHAR NOT NULL, target VARCHAR, details VARCHAR NOT NULL DEFAULT '',"
                " incident_id VARCHAR, incident_name VARCHAR)"
            )
        )

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0049_two_factor")
    command.upgrade(cfg, "0051_audit_chain")
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT count(*) FROM audit_log")).scalar() == 0
        assert tuple(conn.execute(sa.text("SELECT seq, hash FROM audit_chain")).one()) == (0, "0" * 64)


def test_migration_0052_adds_the_tables_of_the_recovery_and_touches_nothing_else(tmp_path, monkeypatch):
    from app.core.models import RECOVERY_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE settings (id INTEGER PRIMARY KEY, doc JSON NOT NULL)"))
        conn.execute(sa.text("INSERT INTO settings (id, doc) VALUES (1, '{}')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0051_audit_chain")
    command.upgrade(cfg, "0052_recovery")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert set(RECOVERY_TABLES) <= set(inspector.get_table_names())
        bases = {column["name"] for column in inspector.get_columns("recovery_bases")}
        assert {"id", "state", "created_at", "finished_at", "size", "timeline", "start_wal", "facts", "local"} <= bases
        assert {"offsite_state", "offsite", "error", "requested_by"} <= bases
        copies = {column["name"] for column in inspector.get_columns("store_copies")}
        assert copies == {"name", "size", "mtime", "state", "seen_at", "copied_at", "gone_at", "removed_at", "error"}
        assert conn.execute(sa.text("SELECT count(*) FROM settings")).scalar() == 1
    command.stamp(cfg, "0051_audit_chain")
    command.upgrade(cfg, "0052_recovery")  # again: the tables are there, nothing to do
    command.downgrade(cfg, "0051_audit_chain")
    with engine.connect() as conn:
        assert not set(RECOVERY_TABLES) & set(sa.inspect(conn).get_table_names())
        assert conn.execute(sa.text("SELECT count(*) FROM settings")).scalar() == 1


def test_migration_0053_adds_what_holds_work_across_a_restart_and_marks_the_steps_in_flight(tmp_path, monkeypatch):
    from app.core.models import JOB_COLUMNS, JOB_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        # What releases before this one knew of the tables that gain columns.
        conn.execute(sa.text("CREATE TABLE runs (id VARCHAR(32) PRIMARY KEY, status VARCHAR(10) NOT NULL)"))
        conn.execute(
            sa.text(
                "CREATE TABLE run_steps (id VARCHAR(32) PRIMARY KEY, run_id VARCHAR(32) NOT NULL,"
                " kind VARCHAR(12) NOT NULL, status VARCHAR(10) NOT NULL, claimed_at FLOAT, error VARCHAR)"
            )
        )
        conn.execute(sa.text("CREATE TABLE mirror_queue (id VARCHAR(32) PRIMARY KEY, status VARCHAR(8) NOT NULL)"))
        conn.execute(sa.text("INSERT INTO runs VALUES ('r1', 'running'), ('r2', 'done')"))
        conn.execute(
            sa.text(
                "INSERT INTO run_steps VALUES ('calling', 'r1', 'action', 'running', 1700.5, NULL),"
                " ('scripting', 'r1', 'script', 'running', 1701.0, NULL),"
                " ('due', 'r1', 'action', 'pending', NULL, NULL), ('over', 'r2', 'action', 'done', 1600.0, NULL)"
            )
        )
        conn.execute(sa.text("INSERT INTO mirror_queue VALUES ('m1', 'pending')"))
        # Work the version before was doing in its threads when it was stopped.
        conn.execute(sa.text("CREATE TABLE sample_code (sha256 VARCHAR(64) PRIMARY KEY, status VARCHAR NOT NULL)"))
        conn.execute(sa.text("CREATE TABLE mailboxes (id VARCHAR(32) PRIMARY KEY, status VARCHAR(16) NOT NULL)"))
        conn.execute(sa.text("CREATE TABLE jobs (id VARCHAR PRIMARY KEY, status VARCHAR NOT NULL)"))
        conn.execute(sa.text("INSERT INTO sample_code VALUES ('aa', 'running'), ('bb', 'done'), ('cc', 'queued')"))
        conn.execute(
            sa.text("INSERT INTO mailboxes VALUES ('m-read', 'indexing'), ('m-import', 'importing'), ('m-ok', 'ready')")
        )
        conn.execute(sa.text("INSERT INTO jobs VALUES ('j1', 'running'), ('j2', 'done')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0052_recovery")
    command.upgrade(cfg, "0053_jobs")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert set(JOB_TABLES) <= set(inspector.get_table_names())
        for table, added in JOB_COLUMNS.items():
            assert set(added) <= {column["name"] for column in inspector.get_columns(table)}, table
        claims = {column["name"] for column in inspector.get_columns("work_claims")}
        assert {"kind", "ref", "state", "holder", "beat_at", "attempts", "interrupted_at", "resumed_at"} <= claims
        unique = {index["name"]: index["unique"] for index in inspector.get_indexes("runs")}
        assert unique["ux_runs_event_key"]
        # An action that was running under the version before may have made its call: it carries the
        # mark, from the moment it was claimed. Nothing else does.
        marks = dict(conn.execute(sa.text("SELECT id, calling_at FROM run_steps")).all())
        assert marks == {"calling": 1700.5, "scripting": None, "due": None, "over": None}
        assert conn.execute(sa.text("SELECT status, holder FROM mirror_queue")).one() == ("pending", None)
        assert conn.execute(sa.text("SELECT count(*) FROM runs WHERE event_key IS NOT NULL")).scalar() == 0
        # What was in progress is wanted, due at once: the server of this version starts it again
        # (or, for an upload whose bytes are gone, says so). What had ended is left alone.
        wanted = conn.execute(sa.text("SELECT kind, ref, state, beat_at, attempts, note FROM work_claims")).all()
        assert sorted((row[0], row[1]) for row in wanted) == [
            ("code", "aa"),
            ("code", "cc"),
            ("import", "m-import"),
            ("mailbox", "m-read"),
            ("upload", "j1"),
        ]
        assert {tuple(row[2:]) for row in wanted} == {
            ("wanted", 0.0, 0, "In progress when the server was upgraded to 6.9")
        }
    with engine.begin() as conn:
        conn.execute(sa.text("UPDATE run_steps SET calling_at = NULL, status = 'interrupted' WHERE id = 'calling'"))
    command.stamp(cfg, "0052_recovery")
    command.upgrade(cfg, "0053_jobs")  # again: everything is there, and no step is marked a second time
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT calling_at FROM run_steps WHERE id = 'calling'")).scalar() is None
        assert conn.execute(sa.text("SELECT count(*) FROM work_claims")).scalar() == 5
    command.downgrade(cfg, "0052_recovery")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert not set(JOB_TABLES) & set(inspector.get_table_names())
        assert {column["name"] for column in inspector.get_columns("run_steps")} == {
            "id",
            "run_id",
            "kind",
            "status",
            "claimed_at",
            "error",
        }
        assert "event_key" not in {column["name"] for column in inspector.get_columns("runs")}
        # The version before knows no step that waits for a word: it fails with what was known of it.
        step = conn.execute(sa.text("SELECT status, error FROM run_steps WHERE id = 'calling'")).one()
        assert tuple(step) == ("failed", "The worker stopped while this ran: outcome unknown")


def test_migration_0054_adds_the_tables_of_the_indicators_found_and_reads_no_incident(tmp_path, monkeypatch):
    from app.core.models import FOUND_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY, doc JSON NOT NULL)"))
        conn.execute(sa.text("INSERT INTO incidents (id, doc) VALUES ('i1', '{\"name\": \"evil-site.com\"}')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0053_jobs")
    command.upgrade(cfg, "0054_indicators_found")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert set(FOUND_TABLES) <= set(inspector.get_table_names())
        found = {column["name"] for column in inspector.get_columns("found_indicators")}
        assert found == {"incident_id", "type", "value", "path", "door", "found_at", "removed_at", "removed_by"}
        assert {column["name"] for column in inspector.get_columns("found_scans")} == {
            "incident_id",
            "at",
            "door",
            "summary",
        }
        # The incidents there are were never read, and the migration reads none.
        assert conn.execute(sa.text("SELECT count(*) FROM found_indicators")).scalar() == 0
        assert conn.execute(sa.text("SELECT count(*) FROM found_scans")).scalar() == 0
    command.stamp(cfg, "0053_jobs")
    command.upgrade(cfg, "0054_indicators_found")  # again: the tables are there, nothing to do
    command.downgrade(cfg, "0053_jobs")
    with engine.connect() as conn:
        assert not set(FOUND_TABLES) & set(sa.inspect(conn).get_table_names())
        assert conn.execute(sa.text("SELECT count(*) FROM incidents")).scalar() == 1


def test_migration_0055_adds_the_tables_of_the_bulk_jobs(tmp_path, monkeypatch):
    from app.core.models import BULK_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY, doc JSON NOT NULL)"))
        conn.execute(sa.text("INSERT INTO incidents (id, doc) VALUES ('i1', '{}')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0054_indicators_found")
    command.upgrade(cfg, "0055_bulk")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert set(BULK_TABLES) <= set(inspector.get_table_names())
        assert {column["name"] for column in inspector.get_columns("bulk_items")} == {
            "job_id",
            "seq",
            "ref",
            "name",
            "state",
            "note",
        }
        jobs = {column["name"] for column in inspector.get_columns("bulk_jobs")}
        assert {"id", "list", "action", "params", "actor", "state", "cancel", "total", "done", "retry_of"} <= jobs
        assert conn.execute(sa.text("SELECT count(*) FROM bulk_jobs")).scalar() == 0
    command.stamp(cfg, "0054_indicators_found")
    command.upgrade(cfg, "0055_bulk")  # again: the tables are there, nothing to do
    command.downgrade(cfg, "0054_indicators_found")
    with engine.connect() as conn:
        assert not set(BULK_TABLES) & set(sa.inspect(conn).get_table_names())
        assert conn.execute(sa.text("SELECT count(*) FROM incidents")).scalar() == 1


def test_migration_0056_adds_the_tables_of_host_evidence_and_the_time_zone(tmp_path, monkeypatch):
    from app.core.models import EVIDENCE_TABLES

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY, doc JSON NOT NULL)"))
        conn.execute(sa.text("INSERT INTO incidents (id, doc) VALUES ('i1', '{}')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0055_bulk")
    command.upgrade(cfg, "0056_evidence")
    with engine.begin() as conn:
        inspector = sa.inspect(conn)
        assert set(EVIDENCE_TABLES) <= set(inspector.get_table_names())
        assert {"tz", "archived_at", "archived_by"} <= {column["name"] for column in inspector.get_columns("incidents")}
        assert {index["name"] for index in inspector.get_indexes("evidence_records")} >= {
            "uq_evidence_records_key",
            "ix_evidence_records_time",
        }
        conn.execute(
            sa.text(
                "INSERT INTO evidence_sources (id, incident_id, kind, source, sha256, file_name, file_path, size,"
                " host, username, profile, parser, parser_version, state, legacy, read, read_count, kept, duplicates,"
                " skipped, notes, truncated, indicators, report, seen_note, created_at, created_by)"
                " VALUES ('s1', 'i1', 'eventlog', 'evtx', '', 'Security.evtx', '', 0, '', '', '', 'evtx', '1',"
                " 'done', 0, 'complete', 1, 1, 0, 0, 0, 0, 0, '{}', '', 'now', '')"
            )
        )
        conn.execute(
            sa.text(
                "INSERT INTO evidence_records (incident_id, source_id, kind, type, key, seq, host, username, channel,"
                " summary, data, truncated, locator) VALUES ('i1', 's1', 'eventlog', 'event',"
                " 'evtx:WS1:Security:1', 0, '', '', 'Security', '', '{}', 0, '{}')"
            )
        )
        # The database numbers the records itself, on SQLite as on PostgreSQL.
        assert conn.execute(sa.text("SELECT id FROM evidence_records")).scalar() == 1
        with pytest.raises(sa.exc.IntegrityError):
            with conn.begin_nested():
                conn.execute(
                    sa.text(
                        "INSERT INTO evidence_records (incident_id, source_id, kind, type, key, seq, host, username,"
                        " channel, summary, data, truncated, locator) VALUES ('i1', 's1', 'eventlog', 'event',"
                        " 'evtx:WS1:Security:1', 1, '', '', 'Security', '', '{}', 0, '{}')"
                    )
                )
        conn.execute(sa.text("DELETE FROM evidence_records"))
        conn.execute(sa.text("DELETE FROM evidence_sources"))
    command.stamp(cfg, "0055_bulk")
    command.upgrade(cfg, "0056_evidence")  # again: the tables and the column are there, nothing to do
    command.downgrade(cfg, "0055_bulk")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert not set(EVIDENCE_TABLES) & set(inspector.get_table_names())
        assert "tz" not in {column["name"] for column in inspector.get_columns("incidents")}
        assert conn.execute(sa.text("SELECT count(*) FROM incidents")).scalar() == 1


def _server_before_0057(tmp_path, monkeypatch):
    """A database as 0056 left it: every table, without what 0057 adds."""
    from app.core.db import Base

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(sa.text("DROP INDEX uq_evidence_detections_record_rule"))
        conn.execute(sa.text("DROP INDEX ix_sigma_rules_pack"))
        for column in ("name", "engine", "original"):
            conn.execute(sa.text(f"ALTER TABLE sigma_rules DROP COLUMN {column}"))
    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0056_evidence")
    return engine, cfg


def test_migration_0057_adds_what_sigma_needs_and_moves_the_keywords_a_person_wrote(tmp_path, monkeypatch):
    import yaml

    from app.defaults import DEFAULT_SUSPICIOUS_KEYWORDS

    engine, cfg = _server_before_0057(tmp_path, monkeypatch)
    shipped = [dict(item) for item in DEFAULT_SUSPICIOUS_KEYWORDS]
    own = {
        "id": "my-site",
        "label": "Our wiki",
        "pattern": r"wiki\.corp",
        "severity": "high",
        "description": "Internal",
    }
    changed = {**shipped[0], "severity": "critical"}  # a shipped one a person raised
    odd = {"id": "odd", "label": "", "pattern": "", "severity": "low"}  # no pattern: nothing to look for
    with engine.begin() as conn:
        conn.execute(
            sa.text("INSERT INTO settings (id, doc) VALUES (1, :doc)"),
            {"doc": json.dumps({"keywords": [changed, *shipped[1:], own, odd], "businessHours": {"startHour": 9}})},
        )
        # Two rows of the same rule on the same record: what a file read twice could have left.
        for _number in (1, 2):
            conn.execute(
                sa.text(
                    "INSERT INTO evidence_detections (incident_id, record_id, rule_id, rule_title, rule_author, level,"
                    " tags, records, created_at) VALUES ('i1', 7, 'r1', 'x', '', 4, '[]', '[]', 'now')"
                )
            )
    command.upgrade(cfg, "0057_sigma")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert {"name", "engine", "original"} <= {column["name"] for column in inspector.get_columns("sigma_rules")}
        assert "ix_sigma_rules_pack" in {index["name"] for index in inspector.get_indexes("sigma_rules")}
        unique = [
            i for i in inspector.get_indexes("evidence_detections") if i["name"] == "uq_evidence_detections_record_rule"
        ]
        assert unique and unique[0]["unique"] and unique[0]["column_names"] == ["record_id", "rule_id"]
        assert conn.execute(sa.text("SELECT count(*) FROM evidence_detections")).scalar() == 1
        rows = conn.execute(
            sa.text(
                "SELECT title, level, product, service, enabled, supported, engine, pack, source, reason"
                " FROM sigma_rules ORDER BY title"
            )
        ).all()
        doc = json.loads(conn.execute(sa.text("SELECT doc FROM settings WHERE id = 1")).scalar())
    # The two the person made became rules; the ones Nik shipped did not.
    assert [(r[0], r[1]) for r in rows] == [("Our wiki", 4), (changed["label"], 5)]
    wiki = rows[0]
    assert (wiki[2], wiki[3], wiki[4], wiki[5], wiki[6], wiki[7]) == ("nik", "browser", 1, 0, "", "")
    assert wiki[9] == "Not checked yet: the forensics worker was not reached"
    text = yaml.safe_load(wiki[8])
    assert (
        text["title"] == "Our wiki"
        and text["level"] == "high"
        and text["logsource"] == {"product": "nik", "service": "browser"}
    )
    assert (
        text["detection"]["url"] == {"url|re": r"(?i)wiki\.corp"} and text["detection"]["condition"] == "url or title"
    )
    assert text["id"] and len(text["id"]) == 36
    assert doc == {"businessHours": {"startHour": 9}}  # the keywords are not a setting any more

    # Again: nothing to move, nothing twice. Down, then up.
    command.downgrade(cfg, "0056_evidence")
    with engine.connect() as conn:
        assert "engine" not in {c["name"] for c in sa.inspect(conn).get_columns("sigma_rules")}
        assert "uq_evidence_detections_record_rule" not in {
            i["name"] for i in sa.inspect(conn).get_indexes("evidence_detections")
        }
    command.upgrade(cfg, "0057_sigma")
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT count(*) FROM sigma_rules")).scalar() == 2


def test_migration_0057_reads_the_keywords_from_their_list_and_removes_the_list(tmp_path, monkeypatch):
    from app.core.models import NamedList, NamedListItem
    from app.defaults import DEFAULT_SUSPICIOUS_KEYWORDS

    engine, cfg = _server_before_0057(tmp_path, monkeypatch)
    first = DEFAULT_SUSPICIOUS_KEYWORDS[0]
    items = [
        (item["id"], {key: item[key] for key in ("label", "pattern", "severity", "description")})
        for item in DEFAULT_SUSPICIOUS_KEYWORDS
    ]
    items.append(("mine", {"label": "Mine", "pattern": r"mine\.example", "severity": "medium", "description": ""}))
    with engine.begin() as conn:
        conn.execute(
            NamedList.__table__.insert(),
            {"id": "l1", "name": "suspicious_keywords", "label": "x", "description": "", "kind": "key_value",
             "item_type": "keyword", "columns": [], "builtin": True, "writable_by_automation": False,
             "updated_at": "now", "updated_by": "nik"},
        )  # fmt: skip
        for position, (key, value) in enumerate(items):
            conn.execute(
                NamedListItem.__table__.insert(),
                {"list_id": "l1", "key": key, "value": value, "note": "", "position": position,
                 "added_at": "now", "added_by": "nik"},
            )  # fmt: skip
        conn.execute(
            sa.text("INSERT INTO settings (id, doc) VALUES (1, :doc)"),
            {
                "doc": json.dumps(
                    {"keywords": {"list": "suspicious_keywords"}, "iocAllowlist": {"list": "ioc_allowlist"}}
                )
            },
        )
    assert first["id"] == items[0][0]
    command.upgrade(cfg, "0057_sigma")
    with engine.connect() as conn:
        assert [r[0] for r in conn.execute(sa.text("SELECT title FROM sigma_rules")).all()] == ["Mine"]
        assert conn.execute(sa.text("SELECT count(*) FROM lists")).scalar() == 0
        assert conn.execute(sa.text("SELECT count(*) FROM list_items")).scalar() == 0
        assert json.loads(conn.execute(sa.text("SELECT doc FROM settings WHERE id = 1")).scalar()) == {
            "iocAllowlist": {"list": "ioc_allowlist"}
        }


def test_migration_0057_on_a_server_that_never_had_keywords_changes_nothing_else(tmp_path, monkeypatch):
    engine, cfg = _server_before_0057(tmp_path, monkeypatch)
    command.upgrade(cfg, "0057_sigma")  # no settings row at all
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT count(*) FROM sigma_rules")).scalar() == 0


def test_migration_0058_adds_the_members_of_a_collection_and_the_source_of_a_record(tmp_path, monkeypatch):
    from app.core.db import Base

    engine = sa.create_engine("sqlite:///" + str(tmp_path / "old.db").replace("\\", "/"))
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(sa.text("DROP TABLE evidence_members"))
        conn.execute(sa.text("ALTER TABLE evidence_records DROP COLUMN source"))
    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0057_sigma")
    command.upgrade(cfg, "0058_collections")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert "evidence_members" in inspector.get_table_names()
        assert {"collection_id", "n", "path", "sha256", "kind", "source", "executable", "skip", "source_id"} <= {
            column["name"] for column in inspector.get_columns("evidence_members")
        }
        assert "source" in {column["name"] for column in inspector.get_columns("evidence_records")}
    command.stamp(cfg, "0057_sigma")
    command.upgrade(cfg, "0058_collections")  # again: both are there, nothing to do
    command.downgrade(cfg, "0057_sigma")
    with engine.connect() as conn:
        inspector = sa.inspect(conn)
        assert "evidence_members" not in inspector.get_table_names()
        assert "source" not in {column["name"] for column in inspector.get_columns("evidence_records")}
