"""What in a text is an indicator, and of which type: the rules of ``app/recognise.py``, one case each."""

from __future__ import annotations

import time

import pytest

from app import recognise
from app.iocs import TYPES, Allowlist, normalize

MD5 = "44d88612fea8a8f36de82e1278abb02f"
SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
SHA512 = SHA256 + SHA256

P = ("private",)
B = ("benign",)

# (the text, what is found in it): each found thing is (type, value) or (type, value, marks).
FOUND = [
    # --- defanged forms are read as meant ---------------------------------------------------- #
    ("hxxp://evil-site.com/a", [("url", "http://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("hxxps://evil-site.com/a", [("url", "https://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("hXXp://evil-site.com/a", [("url", "http://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("h**p://evil-site.com/a", [("url", "http://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("http[://]evil-site.com/a", [("url", "http://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("http[:]//evil-site.com/a", [("url", "http://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("hxxps[:]//evil-site[.]com[/]a", [("url", "https://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("fxp://files.evil-site.com/x", [("url", "ftp://files.evil-site.com/x"), ("domain", "files.evil-site.com")]),
    ("evil-site[.]com", [("domain", "evil-site.com")]),
    ("evil-site(.)com", [("domain", "evil-site.com")]),
    ("evil-site{.}com", [("domain", "evil-site.com")]),
    ("evil-site[dot]com", [("domain", "evil-site.com")]),
    ("evil-site(dot)com", [("domain", "evil-site.com")]),
    ("185[.]220[.]101[.]47", [("ip", "185.220.101.47")]),
    ("185(.)220(.)101(.)47", [("ip", "185.220.101.47")]),
    ("bob[at]evil-site[.]com", [("email", "bob@evil-site.com")]),
    ("bob[@]evil-site.com", [("email", "bob@evil-site.com")]),
    ("bob(at)evil-site(.)com", [("email", "bob@evil-site.com")]),
    ("bob{at}evil-site.com", [("email", "bob@evil-site.com")]),
    ("185.220.101.47[:]8080", [("ip", "185.220.101.47")]),
    # --- a URL: what follows it is not part of it -------------------------------------------- #
    ("See http://evil-site.com/a.", [("url", "http://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("See http://evil-site.com/a, then", [("url", "http://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("(http://evil-site.com/a)", [("url", "http://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("[http://evil-site.com/a]", [("url", "http://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("<http://evil-site.com/a>", [("url", "http://evil-site.com/a"), ("domain", "evil-site.com")]),
    ('"http://evil-site.com/a"', [("url", "http://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("[the page](http://evil-site.com/a).", [("url", "http://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("http://evil-site.com/a?x=1&y=2!", [("url", "http://evil-site.com/a?x=1&y=2"), ("domain", "evil-site.com")]),
    ("http://evil-site.com/a;", [("url", "http://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("{http://evil-site.com/a}", [("url", "http://evil-site.com/a"), ("domain", "evil-site.com")]),
    (
        "http://evil-site.com/a(b)c and more",
        [("url", "http://evil-site.com/a(b)c"), ("domain", "evil-site.com")],
    ),
    ("http://evil-site.com/a#frag", [("url", "http://evil-site.com/a#frag"), ("domain", "evil-site.com")]),
    # --- a URL: its scheme and host lower-case, its own port dropped, two indicators ---------- #
    ("HTTP://Evil-Site.COM/Path", [("url", "http://evil-site.com/Path"), ("domain", "evil-site.com")]),
    ("http://evil-site.com:80/a", [("url", "http://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("https://evil-site.com:443/a", [("url", "https://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("ftp://evil-site.com:21/a", [("url", "ftp://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("https://evil-site.com:8443/a", [("url", "https://evil-site.com:8443/a"), ("domain", "evil-site.com")]),
    ("http://evil-site.com./a", [("url", "http://evil-site.com/a"), ("domain", "evil-site.com")]),
    ("http://evil-site.com", [("url", "http://evil-site.com"), ("domain", "evil-site.com")]),
    # User names and ports are not part of the host.
    (
        "http://user:secret@evil-site.com:8080/a",
        [("url", "http://user:secret@evil-site.com:8080/a"), ("domain", "evil-site.com")],
    ),
    (
        "http://paypal.com@evil-site.com/login",
        [("url", "http://paypal.com@evil-site.com/login"), ("domain", "evil-site.com")],
    ),
    # The host is an address: the second indicator is an address.
    ("http://185.220.101.47/gate.php", [("url", "http://185.220.101.47/gate.php"), ("ip", "185.220.101.47")]),
    ("http://185.220.101.47:8080/", [("url", "http://185.220.101.47:8080/"), ("ip", "185.220.101.47")]),
    (
        "http://[2001:4860:4860::8888]:8080/x",
        [("url", "http://[2001:4860:4860::8888]:8080/x"), ("ip", "2001:4860:4860::8888")],
    ),
    # Private, internal: recognised, and marked.
    ("http://10.1.2.3/admin", [("url", "http://10.1.2.3/admin", P), ("ip", "10.1.2.3", P)]),
    ("http://intranet/wiki", [("url", "http://intranet/wiki", P)]),
    ("http://files.corp/share", [("url", "http://files.corp/share", P)]),
    ("http://localhost:8000/x", [("url", "http://localhost:8000/x", P)]),
    # Names with letters outside ASCII become their xn-- form.
    ("https://münchen.de/", [("url", "https://xn--mnchen-3ya.de/"), ("domain", "xn--mnchen-3ya.de")]),
    ("https://xn--mnchen-3ya.de/", [("url", "https://xn--mnchen-3ya.de/"), ("domain", "xn--mnchen-3ya.de")]),
    ("bücher.de", [("domain", "xn--bcher-kva.de")]),
    ("XN--BCHER-KVA.de", [("domain", "xn--bcher-kva.de")]),
    # Other schemes are not URLs of the library; the name in them still is one.
    ("wss://evil-site.com/socket", [("domain", "evil-site.com")]),
    ("//cdn.evil-site.com/x.js", [("domain", "cdn.evil-site.com")]),
    # --- e-mail addresses: the address, and nothing of its domain ------------------------------ #
    ("Bob.Smith@Evil-Site.COM", [("email", "bob.smith@evil-site.com")]),
    ("mailto:bob@evil-site.com", [("email", "bob@evil-site.com")]),
    ("<bob+tag@mail.evil-site.co.uk>", [("email", "bob+tag@mail.evil-site.co.uk")]),
    ("From: bob@evil-site.com.", [("email", "bob@evil-site.com")]),
    ("bob@example.com", [("email", "bob@example.com", B)]),
    ("root@localhost", []),
    ("bob@host.local", []),
    ("user@", []),
    # --- domains ----------------------------------------------------------------------------- #
    ("evil-site.com", [("domain", "evil-site.com")]),
    ("Evil-Site.COM.", [("domain", "evil-site.com")]),
    ("sub.evil-site.co.uk", [("domain", "sub.evil-site.co.uk")]),
    ("evil-site.com:8443", [("domain", "evil-site.com")]),
    ("host=evil-site.com;", [("domain", "evil-site.com")]),
    ("evil-site.com/login.php", [("domain", "evil-site.com")]),
    ("a.github.io", [("domain", "a.github.io")]),
    ("hidden3xample.onion", [("domain", "hidden3xample.onion")]),
    ("\\\\files.evil-site.com\\share", [("domain", "files.evil-site.com")]),
    ("example.com", [("domain", "example.com", B)]),
    ("www.example.org", [("domain", "www.example.org", B)]),
    ("evil.example", [("domain", "evil.example", B)]),
    ("thing.test", [("domain", "thing.test", B)]),
    ("www.w3.org", [("domain", "www.w3.org", B)]),
    (
        'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"',
        [
            ("url", "http://schemas.microsoft.com/win/2004/08/events/event", B),
            ("domain", "schemas.microsoft.com", B),
        ],
    ),
    (
        "http://www.w3.org/2001/XMLSchema-instance",
        [("url", "http://www.w3.org/2001/XMLSchema-instance", B), ("domain", "www.w3.org", B)],
    ),
    (
        "https://json-schema.org/draft/2020-12/schema",
        [("url", "https://json-schema.org/draft/2020-12/schema", B), ("domain", "json-schema.org", B)],
    ),
    # Not a domain: a file, a version, a word of code, a package, a path, an unknown top-level domain.
    ("kernel32.dll", []),
    ("report.final.docx", []),
    ("invoice.pdf.exe", []),
    ("install.sh", []),
    ("README.md", []),
    ("setup.py", []),
    ("archive.zip", []),
    ("movie.mov", []),
    ("update.pl", []),
    ("main.rs", []),
    ("Safari.app", []),
    ("www.archive.zip", [("domain", "www.archive.zip")]),
    ("sklep.allegro.pl", [("domain", "sklep.allegro.pl")]),
    ("host.corp", []),
    ("printer.local", []),
    ("server.internal", []),
    ("co.uk", []),
    ("com", []),
    ("this.name", []),
    ("window.open('x')", []),
    ("e.target", []),
    ("document.location", []),
    ("com.google.chrome", []),
    ("org.apache.commons.io", []),
    ("System.IO.File", []),
    ("[System.Net.WebClient]::new()", []),
    ("C:\\tools\\evil.com", []),
    ("C:\\Users\\bob\\AppData\\update.pl", []),
    ("/tmp/update.pl", []),
    ("/var/www/evil-site.com/index.php", []),
    ("$env.name", []),
    ("_dmarc.evil-site.com", []),
    ("-evil-.com", []),
    # --- addresses --------------------------------------------------------------------------- #
    ("185.220.101.47", [("ip", "185.220.101.47")]),
    ("src=185.220.101.47 dst=8.8.8.8", [("ip", "185.220.101.47"), ("ip", "8.8.8.8")]),
    ("185.220.101.47:443", [("ip", "185.220.101.47")]),
    ("185.220.101.47/32", [("ip", "185.220.101.47")]),
    ("(185.220.101.47)", [("ip", "185.220.101.47")]),
    ("185.220.101.1-185.220.101.9", [("ip", "185.220.101.1"), ("ip", "185.220.101.9")]),
    ("\\\\185.220.101.47\\share", [("ip", "185.220.101.47")]),
    ("10.1.2.3", [("ip", "10.1.2.3", P)]),
    ("172.16.5.4", [("ip", "172.16.5.4", P)]),
    ("192.168.1.1", [("ip", "192.168.1.1", P)]),
    ("127.0.0.1", [("ip", "127.0.0.1", P)]),
    ("169.254.10.10", [("ip", "169.254.10.10", P)]),
    ("100.64.1.1", [("ip", "100.64.1.1", P)]),
    ("0.0.0.0", [("ip", "0.0.0.0", P)]),
    ("255.255.255.255", [("ip", "255.255.255.255", P)]),
    ("224.0.0.251", [("ip", "224.0.0.251", P)]),
    ("192.0.2.10", [("ip", "192.0.2.10", P)]),
    # Not an address: a version, too many parts, too few, a number over 255, leading zeros.
    ("1.2.3", []),
    ("1.2.3.4.5", []),
    ("v1.2.3.4", []),
    ("version 1.2.3.4", []),
    ("Version: 1.2.3.4", []),
    ("build 10.0.19.41", []),
    ("Chrome/120.0.60.71", []),
    ("pkg-1.2.3.4", []),
    ("1.2.3.4-beta", []),
    ("10.0.19041.1", []),
    ("999.1.1.1", []),
    ("010.001.001.001", []),
    ("1.3.6.1.4.1.311.2.1.4", []),
    # IPv6, in its forms.
    ("2001:4860:4860::8888", [("ip", "2001:4860:4860::8888")]),
    ("2001:4860:4860:0:0:0:0:8888", [("ip", "2001:4860:4860::8888")]),
    ("2001:4860:4860:0000:0000:0000:0000:8888", [("ip", "2001:4860:4860::8888")]),
    ("2A00:1450:4001:0810::200E", [("ip", "2a00:1450:4001:810::200e")]),
    ("[2a00:1450:4001:810::200e]:443", [("ip", "2a00:1450:4001:810::200e")]),
    ("::ffff:185.220.101.47", [("ip", "185.220.101.47")]),
    ("::ffff:10.1.2.3", [("ip", "10.1.2.3", P)]),
    ("::1", [("ip", "::1", P)]),
    ("fe80::1%eth0", [("ip", "fe80::1", P)]),
    ("fd12:3456:789a::1", [("ip", "fd12:3456:789a::1", P)]),
    ("2001:db8::1", [("ip", "2001:db8::1", P)]),
    # Not IPv6: a time, a hardware address, code.
    ("12:34:56", []),
    ("aa:bb:cc:dd:ee:ff", []),
    ("Cafe::Add(1)", []),
    ("[Convert]::FromBase64String($a)", []),
    ("std::dec", []),
    # --- hashes: a whole token, of a type Nik keeps ------------------------------------------ #
    (MD5, [("md5", MD5)]),
    (MD5.upper(), [("md5", MD5)]),
    (SHA1, [("sha1", SHA1)]),
    (SHA256, [("sha256", SHA256)]),
    (f"sha256:{SHA256}", [("sha256", SHA256)]),
    (f"MD5={MD5}, SHA1={SHA1}", [("md5", MD5), ("sha1", SHA1)]),
    (f"{SHA256}.exe", [("sha256", SHA256)]),
    (f"({MD5})", [("md5", MD5)]),
    ("d41d8cd98f00b204e9800998ecf8427e", [("md5", "d41d8cd98f00b204e9800998ecf8427e", B)]),
    (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        [("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", B)],
    ),
    # Not a hash: inside a longer run of hex, a SHA-512, digits alone, glued to a name, too short.
    (SHA512, []),
    (MD5 + "ab", []),
    ("ab" + SHA1, []),
    (SHA256 + MD5, []),
    (f"key_{MD5}x", []),
    ("12345678901234567890123456789012", []),
    ("0" * 64, []),
    (MD5[:31], []),
    ("3f2504e0-4f89-41d3-9a0c-0305e82c3301", []),
    # --- a text holds several, each once, in the order met ------------------------------------ #
    (
        f"The C2 was evil-site.com (185.220.101.47) and hxxp://bad-domain[.]net/gate.php, hash {MD5}. "
        "Again: evil-site.com.",
        [
            ("domain", "evil-site.com"),
            ("ip", "185.220.101.47"),
            ("url", "http://bad-domain.net/gate.php"),
            ("domain", "bad-domain.net"),
            ("md5", MD5),
        ],
    ),
    ("", []),
    ("nothing to see here", []),
    ("12:00 on 2026-11-21, 3.5 GB, 99.9%", []),
]


def shown(items) -> list[tuple]:
    return [(item.type, item.value, *([item.marks] if item.marks else [])) for item in items]


def test_the_table_holds_a_hundred_cases_and_more():
    assert len(FOUND) >= 100
    assert len({text for text, _ in FOUND}) == len(FOUND)


@pytest.mark.parametrize(("text", "expected"), FOUND, ids=[str(index) for index in range(len(FOUND))])
def test_what_is_found_in_a_text(text, expected):
    found = recognise.find(text)
    assert shown(found) == [tuple(item) for item in expected], text
    for item in found:
        # Only the types Nik keeps, each in the spelling the library stores: the same thing is one indicator.
        assert item.type in TYPES
        assert normalize(item.type, item.value) == item.value


# (the string, what it is, the reason when it is nothing).
IDENTIFIED = [
    ("hxxps://evil-site[.]com/a", [("url", "https://evil-site.com/a"), ("domain", "evil-site.com")], ""),
    ("  <evil-site.com>  ", [("domain", "evil-site.com")], ""),
    ('"185.220.101.47"', [("ip", "185.220.101.47")], ""),
    ("185.220.101.47:8080", [("ip", "185.220.101.47")], ""),
    ("[2a00:1450:4001:810::200e]:443", [("ip", "2a00:1450:4001:810::200e")], ""),
    ("bob@evil-site.com", [("email", "bob@evil-site.com")], ""),
    (MD5, [("md5", MD5)], ""),
    (f"{SHA256}.exe", [("sha256", SHA256)], ""),
    ("evil-site.com and bad-domain.net", [("domain", "evil-site.com"), ("domain", "bad-domain.net")], ""),
    ("185.220.101.1-185.220.101.9", [("ip", "185.220.101.1"), ("ip", "185.220.101.9")], ""),
    ("", [], "it is empty"),
    ("1.2.3", [], "it reads as a version number, not as an address"),
    ("999.1.1.1", [], "it is not an IP address"),
    ("install.sh", [], "it reads as a file name: write it as a URL, or say it is a domain"),
    ("kernel32.dll", [], '".dll" is not a top-level domain'),
    ("this.name", [], "it reads as code, not as a name"),
    ("com.google.chrome", [], "it reads as the name of a package, written backwards"),
    ("co.uk", [], "it is a public suffix, not a name under one"),
    (
        SHA512,
        [],
        "it is as long as a SHA-512 digest, which Nik does not keep: MD5, SHA-1 and SHA-256 are",
    ),
    ("12345678901234567890123456789012", [], "it is a number, not a hash"),
    ("bob@host.local", [], 'it is not an e-mail address: ".local" is not a top-level domain'),
    ("gopher://evil-site.com/", [("domain", "evil-site.com")], ""),
    ("Cafe::Add", [], "no indicator was recognised in it"),
    ("hello", [], "no indicator was recognised in it"),
]


@pytest.mark.parametrize(("text", "expected", "why"), IDENTIFIED, ids=[str(index) for index in range(len(IDENTIFIED))])
def test_what_one_string_is(text, expected, why):
    found, reason = recognise.identify(text)
    assert (shown(found), reason) == ([tuple(item) for item in expected], why), text


def test_a_type_can_be_forced_and_then_the_string_is_that_or_nothing():
    # A person says it is a domain: the rules that tell a name from a file are not applied.
    assert shown(recognise.identify("update.pl", force="domain")[0]) == [("domain", "update.pl")]
    assert shown(recognise.identify("evil-site.com:8443/x", force="domain")[0]) == [("domain", "evil-site.com")]
    assert recognise.identify("host.corp", force="domain") == ([], '".corp" is not a top-level domain')
    assert shown(recognise.identify("185.220.101.47:80", force="ip")[0]) == [("ip", "185.220.101.47")]
    assert recognise.identify("evil-site.com", force="ip") == ([], "it is not an IP address")
    assert recognise.identify("evil-site.com", force="url") == ([], "a URL starts with http://, https:// or ftp://")
    assert recognise.identify(MD5, force="sha256") == ([], "it is not a SHA256 digest")
    assert shown(recognise.identify(MD5, force="md5")[0]) == [("md5", MD5)]
    assert shown(recognise.identify("bob[at]evil-site.com", force="email")[0]) == [("email", "bob@evil-site.com")]
    assert recognise.identify("x", force="registry") == ([], '"registry" is not a type of indicator')


def test_what_the_organisation_says_of_itself_is_marked():
    known = recognise.Known(
        own_domains=frozenset({"corp-bank.com"}),
        allowlisted=Allowlist(["microsoft.com", "8.8.8.0/24", MD5]).matches,
    )
    text = (
        "anna@corp-bank.com wrote to bob@evil-site.com from mail.corp-bank.com; "
        f"https://login.microsoft.com/x and 8.8.8.8; {MD5}; https://portal.corp-bank.com/a"
    )
    assert shown(recognise.find(text, known)) == [
        ("email", "anna@corp-bank.com", ("own",)),
        ("email", "bob@evil-site.com"),
        ("domain", "mail.corp-bank.com", ("own",)),
        ("url", "https://login.microsoft.com/x", ("allowlisted",)),
        ("domain", "login.microsoft.com", ("allowlisted",)),
        ("ip", "8.8.8.8", ("allowlisted",)),
        ("md5", MD5, ("allowlisted",)),
        ("url", "https://portal.corp-bank.com/a", ("own",)),
        ("domain", "portal.corp-bank.com", ("own",)),
    ]


def test_the_host_of_a_url_says_which_url_it_came_from():
    url, host = recognise.find("see https://evil-site.com/a")
    assert (url.host_of, host.host_of) == ("", "https://evil-site.com/a")


def test_a_long_text_is_read_in_a_time_that_grows_with_its_length():
    # What a careless pattern would take minutes on: long runs with no end in sight.
    hard = [
        "a" * 200_000,
        "a." * 100_000,
        "a@" * 100_000,
        ":" * 200_000,
        "http://" * 30_000,
        "1." * 100_000,
        ("a" * 60 + ".") * 3000 + "com",
        "(" * 100_000 + "http://evil-site.com/" + ")" * 100_000,
    ]
    started = time.perf_counter()
    for text in hard:
        recognise.find(text)
        recognise.identify(text)
    assert time.perf_counter() - started < 20
    # No more than a text's first 200 000 characters are read, and no more than 2000 indicators kept.
    many = " ".join(f"host{index}.evil-site.com" for index in range(5000))
    assert len(recognise.find(many)) == recognise.FOUND_MAX


def test_the_pasted_lists_of_the_indicators_page_read_the_same_defanged_forms():
    from app import ioc_library

    assert ioc_library.refang is recognise.refang
    assert ioc_library.refang("hxxps://evil[.]example/a b(.)c user[at]d") == "https://evil.example/a b.c user@d"
