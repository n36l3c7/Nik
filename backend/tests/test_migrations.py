"""Data migrations on a SQLite copy of an older schema."""

from __future__ import annotations

import json

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
