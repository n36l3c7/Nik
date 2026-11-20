"""The hosts the downloads of an instance may come from.

A product often hands a file over as a link: the console answers with an
address on a storage host, signed and good for a few minutes. A connector
reaches its own instance and the hosts its file lists by name
(``more_hosts``), and the vendor's reference seldom names the storage: it is
another one for each region, each tenant, each cloud. So a connector may say
that the instance knows (``download_hosts_from``, which names a configuration
entry of type ``hosts``), and an administrator writes the hosts in the
instance.

What is written there is a short list of names, checked when the instance is
saved:

    files.vendor.example.com        that host
    *.storage.vendor.example.com    every host under that name

Nothing else: no ``*`` alone, no address, no range, no scheme, no port, no
path, no internal name. What it opens is narrow too (connector_runtime.py,
egress.py): only a request whose answer is a file follows a link or a
redirect there, over https, without the credentials of the instance and
without any header of the connector, under the size limit of a file and the
rules every request of a playbook obeys. An address inside the network is
refused whatever the list says.
"""

from __future__ import annotations

import re

HOSTS_MAX = 40
_NAME = re.compile(r"^(?=.{4,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
_UNDER = "*.storage.example.com"


def _problem(item: str) -> str | None:
    """Why one entry is refused (None when it is a host name or a pattern)."""
    from ..enrichment.service import internal_host

    if "://" in item:
        return "is an address: write the name of the host alone, without https://"
    if "/" in item:
        return "has a path or is a range: write the name of the host alone"
    name = item[2:] if item.startswith("*.") else item
    if "*" in name:
        return f"is not a host: a * stands only at the start, for the hosts under a name ({_UNDER})"
    if ":" in name or "[" in name:
        return "has a port or is an address: write the name of the host alone (a download is https)"
    if name.replace(".", "").isdigit():
        return "is an address: a host is written by its name"
    if not _NAME.match(name):
        return "is not the name of a host"
    if internal_host(name) is not None:
        return "is an internal name: a download comes from a host outside the network"
    return None


def patterns(text: object) -> list[str]:
    """The hosts written in an instance, one for each line or separated by commas: lower case, each
    once, in the order they were written. Raises ``ValueError`` with a sentence for the first that is
    not a host name or a ``*.`` pattern."""
    found: list[str] = []
    for raw in re.split(r"[\s,;]+", str(text or "")):
        item = raw.strip().lower().rstrip(".")
        if not item:
            continue
        why = _problem(item)
        if why:
            raise ValueError(f'"{raw[:80]}" {why}')
        if item not in found:
            found.append(item)
    if len(found) > HOSTS_MAX:
        raise ValueError(f"{HOSTS_MAX} hosts at most")
    return found


def tolerant(text: object) -> tuple[str, ...]:
    """The same list where it is read to send a request: what was saved was checked, and a value that
    is not a list any more (a database edited by hand) opens nothing."""
    try:
        return tuple(patterns(text))
    except ValueError:
        return ()


def matches(hosts: tuple[str, ...] | frozenset, host: str) -> bool:
    """Whether a host is one of the list: by its exact name, or under a ``*.`` pattern."""
    host = (host or "").lower().rstrip(".")
    return any(host == pattern or (pattern.startswith("*.") and host.endswith(pattern[1:])) for pattern in hosts or ())
