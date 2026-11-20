"""Where the secrets of the server come from (core/keys.py), what the container refuses to start
with (preflight.py), and the server that stays up to say why it did not start (stopped.py)."""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request

import pytest

from app import preflight, stopped
from app.core import keys
from app.core.config import Settings

SECRET = "s3cret-value-that-must-never-be-in-a-message-0123456789"
OTHER = "another-value-that-must-never-be-in-a-message-9876543210"


def _file(tmp_path, name: str, content: bytes | str):
    path = tmp_path / name
    path.write_bytes(content if isinstance(content, bytes) else content.encode())
    return str(path)


# --------------------------------------------------------------------------- #
# The providers                                                               #
# --------------------------------------------------------------------------- #
def test_a_secret_is_taken_from_its_file_or_from_the_environment(tmp_path):
    in_file = {"SECRET_KEY_FILE": _file(tmp_path, "k", SECRET + "\n")}
    assert keys.find("SECRET_KEY", in_file) == keys.Found(SECRET, keys.FILE)
    assert keys.value("SECRET_KEY", "", in_file) == SECRET and keys.source("SECRET_KEY", in_file) == "file"
    # The line end an editor leaves is not part of it; what is inside the value is.
    assert keys.value("K", "", {"K_FILE": _file(tmp_path, "crlf", "a b\tc \r\n")}) == "a b\tc "
    in_env = {"SECRET_KEY": SECRET}
    assert keys.find("SECRET_KEY", in_env) == keys.Found(SECRET, keys.ENVIRONMENT)
    assert keys.source("SECRET_KEY", in_env) == "environment"
    assert keys.find("SECRET_KEY", {}) is None
    assert keys.value("SECRET_KEY", "the default", {}) == "the default" and keys.source("SECRET_KEY", {}) == "default"
    assert keys.value("SECRET_KEY", "the default", {"SECRET_KEY": ""}) == "the default"


def test_an_empty_file_counts_as_none_and_the_environment_is_then_read(tmp_path):
    """The Compose file mounts an empty file in the place of each secret a server keeps in .env."""
    empty = _file(tmp_path, "empty", "")
    assert keys.find("SECRET_KEY", {"SECRET_KEY_FILE": empty}) is None
    assert keys.find("SECRET_KEY", {"SECRET_KEY_FILE": _file(tmp_path, "nl", "\n")}) is None
    assert keys.find("SECRET_KEY", {"SECRET_KEY_FILE": empty, "SECRET_KEY": SECRET}) == keys.Found(
        SECRET, "environment"
    )
    # A variable that names no file is no file.
    assert keys.find("SECRET_KEY", {"SECRET_KEY_FILE": "  ", "SECRET_KEY": SECRET}).source == "environment"


def test_a_secret_given_in_both_places_is_refused_and_no_value_is_said(tmp_path):
    env = {"SECRET_KEY_FILE": _file(tmp_path, "k", SECRET), "SECRET_KEY": OTHER}
    with pytest.raises(keys.Conflict) as refused:
        keys.find("SECRET_KEY", env)
    assert refused.value.name == "SECRET_KEY" and "given twice" in refused.value.message
    assert SECRET not in refused.value.message and OTHER not in refused.value.message
    assert SECRET not in str(refused.value) and OTHER not in repr(refused.value)
    # The same value in both is refused too: one of the two is stale tomorrow.
    with pytest.raises(keys.Conflict):
        keys.find("SECRET_KEY", {"SECRET_KEY_FILE": _file(tmp_path, "same", SECRET), "SECRET_KEY": SECRET})
    assert keys.source("SECRET_KEY", env) == "default"  # asked for a word, it never raises


def test_a_file_that_cannot_be_read_is_never_taken_for_a_missing_one(tmp_path):
    for path in (str(tmp_path / "not-there"), str(tmp_path)):  # missing, and a folder
        with pytest.raises(keys.Unreadable) as refused:
            keys.find("STORE_KEY", {"STORE_KEY_FILE": path, "STORE_KEY": ""})
        assert "STORE_KEY_FILE names" in refused.value.message and "cannot be read" in refused.value.message
    with pytest.raises(keys.Unreadable, match="not text"):
        keys.find("STORE_KEY", {"STORE_KEY_FILE": _file(tmp_path, "bin", b"\xff\xfe\x00\x81")})
    with pytest.raises(keys.Unreadable, match="too large"):
        keys.find("STORE_KEY", {"STORE_KEY_FILE": _file(tmp_path, "big", "k" * (keys.MAX_BYTES + 1))})


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs a file its reader may not open")
def test_a_file_the_user_may_not_read_is_refused(tmp_path):
    path = _file(tmp_path, "closed", SECRET)
    os.chmod(path, 0)
    with pytest.raises(keys.Unreadable, match="the user of the container may read it"):
        keys.find("SECRET_KEY", {"SECRET_KEY_FILE": path})


def test_several_values_are_separated_by_commas_or_lines(tmp_path):
    assert keys.several("SECRET_KEY_PREVIOUS", {}) == []
    assert keys.several("SECRET_KEY_PREVIOUS", {"SECRET_KEY_PREVIOUS": " a , b,,c "}) == ["a", "b", "c"]
    assert keys.several("P", {"P_FILE": _file(tmp_path, "p", "one\ntwo\r\n\nthree,four\n")}) == [
        "one",
        "two",
        "three",
        "four",
    ]


def test_another_provider_is_one_more_class():
    class Manager:
        name = "manager"

        def read(self, secret, env):
            return "from-the-manager" if secret == "STORE_KEY" else None

    before = keys.PROVIDERS
    keys.PROVIDERS = (Manager(), *before)
    try:
        assert keys.find("STORE_KEY", {}) == keys.Found("from-the-manager", "manager")
        assert keys.find("SECRET_KEY", {"SECRET_KEY": SECRET}).source == "environment"
        with pytest.raises(keys.Conflict):
            keys.find("STORE_KEY", {"STORE_KEY": SECRET})
    finally:
        keys.PROVIDERS = before


# --------------------------------------------------------------------------- #
# The settings of a process                                                   #
# --------------------------------------------------------------------------- #
FILE_NAMES = ("SECRET_KEY", "STORE_KEY", "DB_PASSWORD", "ANALYZER_TOKEN", "SANDBOX_TOKEN", "METRICS_TOKEN")


def test_keys_from_files_reach_the_settings_and_never_the_environment(tmp_path, monkeypatch):
    values = {name: f"{name.lower()}-{SECRET}" for name in FILE_NAMES}
    for name, value in values.items():
        monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv(f"{name}_FILE", _file(tmp_path, name.lower(), value + "\n"))
    monkeypatch.setenv("SECRET_KEY_PREVIOUS_FILE", _file(tmp_path, "previous", "old-one\nolder-one\n"))
    monkeypatch.delenv("SECRET_KEY_PREVIOUS", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DB_HOST", "db")
    made = Settings()
    assert made.SECRET_KEY == values["SECRET_KEY"] and made.STORE_KEY == values["STORE_KEY"]
    assert made.SECRET_KEY_PREVIOUS == ["old-one", "older-one"] and made.STORE_KEY_PREVIOUS == []
    assert made.ANALYZER_TOKEN == values["ANALYZER_TOKEN"] and made.SANDBOX_TOKEN == values["SANDBOX_TOKEN"]
    assert made.METRICS_TOKEN == values["METRICS_TOKEN"]
    assert values["DB_PASSWORD"] in made.DATABASE_URL and made.DATABASE_URL.startswith("postgresql+psycopg://nik:")
    # Reading them did not put any of them where a child process, or /proc/<pid>/environ, finds it.
    for name, value in values.items():
        assert name not in os.environ
        assert not any(value in held for held in os.environ.values())
    assert not any("old-one" in held for held in os.environ.values())


def test_a_process_told_it_holds_no_store_key_holds_none(monkeypatch):
    monkeypatch.delenv("STORE_KEY", raising=False)
    monkeypatch.delenv("STORE_KEY_FILE", raising=False)
    monkeypatch.setenv("NIK_NO_STORE_KEY", "1")
    monkeypatch.setenv("NIK_STORE_API_URL", "http://api:8000/")
    made = Settings()
    assert made.STORE_KEY == "" and made.STORE_API_URL == "http://api:8000"
    monkeypatch.delenv("NIK_NO_STORE_KEY")
    assert Settings().STORE_KEY  # development: a key of its own, which the container refuses


# --------------------------------------------------------------------------- #
# What the container refuses to start with                                    #
# --------------------------------------------------------------------------- #
GOOD = {"SECRET_KEY": "k" * 40, "STORE_KEY": "s" * 40}


def test_preflight_takes_the_keys_from_files(tmp_path):
    env = {
        "SECRET_KEY_FILE": _file(tmp_path, "secret", "k" * 40 + "\n"),
        "STORE_KEY_FILE": _file(tmp_path, "store", "s" * 40 + "\n"),
        # As the Compose file passes them when the values are in files: named, and empty.
        "SECRET_KEY": "",
        "STORE_KEY": "",
        "SECRET_KEY_PREVIOUS_FILE": _file(tmp_path, "previous", ""),
        "ANALYZER_URL": "http://analyzer:8700",
        "ANALYZER_TOKEN_FILE": _file(tmp_path, "token", "t" * 64),
    }
    assert preflight.problems(env) == []
    # The empty files of a server that keeps its secrets in .env, with the values in the environment.
    empty = _file(tmp_path, "empty", "")
    assert preflight.problems({**GOOD, "SECRET_KEY_FILE": empty, "STORE_KEY_FILE": empty}) == []


@pytest.mark.parametrize(
    ("store_key", "reason", "said"),
    [
        ("", preflight.MISSING, "STORE_KEY is not set."),
        ("change-this-store-key", preflight.EXAMPLE, "example file"),
        ("dev-insecure-store-key-change-me", preflight.EXAMPLE, "example file"),
        ("short-store-key", preflight.SHORT, "shorter than 32 characters"),
    ],
)
def test_preflight_refuses_a_store_key_that_is_missing_public_or_short(store_key, reason, said):
    found = preflight.problems({**GOOD, "STORE_KEY": store_key})
    assert found == [("STORE_KEY", reason)]
    line = preflight.describe(*found[0])
    assert said in line and (not store_key or store_key not in line)
    if reason == preflight.MISSING:
        # Said exactly: what it is, where it comes from, and that a copy must be kept.
        assert "new in 6.8" in line and "deploy/init-env.sh" in line and "keep a copy" in line


def test_a_process_without_the_store_needs_no_store_key():
    assert preflight.problems({"SECRET_KEY": "k" * 40, "NIK_NO_STORE_KEY": "1"}) == []
    assert preflight.problems({"SECRET_KEY": "k" * 40, "NIK_NO_STORE_KEY": "0"}) == [("STORE_KEY", preflight.MISSING)]


def test_preflight_says_which_secret_is_given_twice_or_cannot_be_read(tmp_path):
    twice = {**GOOD, "STORE_KEY_FILE": _file(tmp_path, "store", SECRET)}
    found = preflight.problems(twice)
    assert [name for name, _ in found] == ["STORE_KEY"]
    line = preflight.describe(*found[0])
    assert "STORE_KEY is given twice" in line and SECRET not in line and "s" * 40 not in line
    gone = {**GOOD, "SECRET_KEY": "", "SECRET_KEY_FILE": str(tmp_path / "nowhere")}
    line = preflight.describe(*preflight.problems(gone)[0])
    assert line.startswith("SECRET_KEY_FILE names") and "cannot be read" in line
    # A key that is not required is still never taken for an empty one when its file cannot be read.
    for name in ("SECRET_KEY_PREVIOUS", "STORE_KEY_PREVIOUS", "DB_PASSWORD"):
        found = preflight.problems({**GOOD, f"{name}_FILE": str(tmp_path / "nowhere")})
        assert [problem for problem, _ in found] == [name]
    token = {
        **GOOD,
        "PCAP_URL": "http://pcap:8740",
        "PCAP_TOKEN": "t" * 64,
        "PCAP_TOKEN_FILE": _file(tmp_path, "t", "u" * 64),
    }
    assert "PCAP_TOKEN is given twice" in preflight.describe(*preflight.problems(token)[0])


def test_preflight_serves_what_is_wrong_instead_of_exiting_when_asked_to(monkeypatch, capsys):
    monkeypatch.setenv("SECRET_KEY", "k" * 40)
    monkeypatch.delenv("STORE_KEY", raising=False)
    monkeypatch.delenv("STORE_KEY_FILE", raising=False)
    monkeypatch.delenv("NIK_NO_STORE_KEY", raising=False)
    for name in preflight.WORKERS:
        monkeypatch.delenv(f"{name}_URL", raising=False)
    served = []
    monkeypatch.setattr(stopped, "serve", served.append)
    preflight.main(["--serve"])
    assert len(served) == 1 and served[0][0].startswith("STORE_KEY is not set.")
    # Without the word, as the automation container runs it: the list, and an exit.
    with pytest.raises(SystemExit) as stop:
        preflight.main([])
    assert stop.value.code == 1 and "STORE_KEY is not set" in capsys.readouterr().err
    monkeypatch.setenv("STORE_KEY", "s" * 40)
    preflight.main(["--serve"])
    assert len(served) == 1


def _get(port: int, path: str, method: str = "GET"):
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method)
    try:
        with urllib.request.urlopen(request, timeout=5) as answer:
            return answer.status, answer.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def test_a_server_that_did_not_start_answers_every_request_with_why():
    sentences = ["STORE_KEY is not set. Run deploy/init-env.sh.", "PCAP_TOKEN is given twice."]
    httpd = stopped.server(sentences, port=0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        # The health check passes, so that the web container comes up and shows the sentence.
        assert _get(port, "/api/health") == (200, b'{"status":"stopped"}')
        for method, path in (
            ("GET", "/api/incidents"),
            ("POST", "/api/auth/login"),
            ("GET", "/api/ready"),
            ("DELETE", "/x"),
        ):
            status, body = _get(port, path, method)
            answer = json.loads(body)
            assert status == 503 and answer["stopped"] == {"reason": "keys"}
            assert answer["detail"].startswith("Nik did not start: STORE_KEY is not set.")
            assert "PCAP_TOKEN is given twice." in answer["detail"] and "deployment guide" in answer["detail"]
        assert _get(port, "/api/ready", "HEAD")[0] == 503
    finally:
        httpd.shutdown()
    said = stopped.explain(sentences)
    assert "NIK DID NOT START" in said and "  - STORE_KEY is not set." in said and "Nothing was changed" in said
