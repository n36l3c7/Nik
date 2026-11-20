"""The address a request really comes from.

In the Compose stack the browser talks to the ``web`` container (nginx),
which passes the request on and writes the address it saw in
``X-Forwarded-For``. That header is believed **only when the connection
itself comes from a trusted proxy** (``TRUSTED_PROXIES``: host names,
addresses or networks, ``web`` by default). From anybody else it is ignored:
a client that reaches the API some other way and writes the header itself is
known by the address of its connection.

The server must therefore be started without a proxy layer of its own in
front of the application: with ``FORWARDED_ALLOW_IPS=*`` (as the Compose file
had it before 6.7) gunicorn rewrites the address of every connection from
the header, whoever sends it, and nothing here can tell. ``overtrusting``
says so, and the screen of the sign-in policy repeats it.

What the limits on sign-in attempts and the administrators' networks are
worth depends on the address being the person's own. Some set-ups hide it:
rootless podman, and Docker Desktop, hand every connection to the web
container from an address of the container network itself. ``describe``
recognises that case (an address that came through the proxy and belongs to
a network this very container is on, or is a loopback address) and says the
address cannot be known, instead of pretending. It says the same of a
connection that comes straight from such a network without being a trusted
proxy: a proxy nobody named, behind which everybody looks like one client.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import threading
import time
from typing import Any

from fastapi import Request

from .config import settings

# A proxy named by its host name is looked up by a thread of its own, never by a request: a name
# that does not answer (the web container starts after the backend) takes the resolver seconds, and
# a request, the health check among them, must not wait for that. The thread asks every
# RESOLVE_SECONDS, and RETRY_SECONDS after a name had no address or a connection came from somebody
# who is not a proxy (a container that was recreated has a new address). What a name last had is
# dropped when it has had no address for KEEP_SECONDS: an address of a container that is gone may be
# given to another.
RESOLVE_SECONDS = 30
RETRY_SECONDS = 3
KEEP_SECONDS = 60
_resolved: dict[str, tuple[float, list[Any]]] = {}
_wake = threading.Event()
_thread: threading.Thread | None = None
_thread_lock = threading.Lock()

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Address = ipaddress.IPv4Address | ipaddress.IPv6Address


def parse(value: object) -> Address | None:
    """An address as written in a header or a connection; None for anything else.
    An IPv4 address carried inside an IPv6 one (``::ffff:10.0.0.1``) is that IPv4 address."""
    try:
        address = ipaddress.ip_address(str(value or "").strip().strip("[]").split("%")[0])
    except ValueError:
        return None
    mapped = getattr(address, "ipv4_mapped", None)
    return mapped or address


def parse_network(value: object) -> Network | None:
    """A network (``10.1.0.0/16``, ``2001:db8::/32``) or a single address; None for anything else."""
    try:
        return ipaddress.ip_network(str(value or "").strip(), strict=False)
    except ValueError:
        return None


def inside(address: object, networks: list[Network]) -> bool:
    found = address if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else parse(address)
    if found is None:
        return False
    return any(found.version == network.version and found in network for network in networks)


def _lookup(name: str) -> list[Network]:
    """The addresses a host name has now (none when it has none: nothing is trusted then)."""
    try:
        found = {info[4][0] for info in socket.getaddrinfo(name, None)}
    except OSError:
        return []
    return [network for network in (parse_network(address) for address in found) if network is not None]


def _names() -> list[str]:
    return [entry for entry in settings.TRUSTED_PROXIES if parse_network(entry) is None]


def refresh(now: float | None = None) -> bool:
    """Ask every name of ``TRUSTED_PROXIES`` for its addresses now. True when each had some."""
    now = time.monotonic() if now is None else now
    complete = True
    for name in _names():
        found = _lookup(name)
        if found:
            _resolved[name] = (now, found)
            continue
        complete = False
        kept = _resolved.get(name)
        if kept is not None and now - kept[0] > KEEP_SECONDS:
            del _resolved[name]
    for name in set(_resolved) - set(_names()):
        del _resolved[name]
    return complete


def _resolver() -> None:
    while True:
        try:
            complete = refresh()
        except Exception:  # noqa: BLE001 - the thread must outlive a bad answer of the resolver
            complete = False
        time.sleep(RETRY_SECONDS)
        _wake.wait(RESOLVE_SECONDS - RETRY_SECONDS if complete else 0)
        _wake.clear()


def _start() -> None:
    """Start the thread that looks the names up, once, when there is a name to look up."""
    global _thread
    if _thread is not None or not _names():
        return
    with _thread_lock:
        if _thread is None:
            _thread = threading.Thread(target=_resolver, name="nik-trusted-proxies", daemon=True)
            _thread.start()


def trusted_proxies() -> list[Network]:
    """The networks ``X-Forwarded-For`` is believed from, as they are known now (nothing is looked up here)."""
    _start()
    networks: list[Network] = []
    for entry in settings.TRUSTED_PROXIES:
        network = parse_network(entry)
        if network is not None:
            networks.append(network)
            continue
        kept = _resolved.get(entry)
        if kept is not None:
            networks.extend(kept[1])
    return networks


def _is_proxy(address: str) -> tuple[bool, list[Network]]:
    """Whether a connection comes from a trusted proxy. When it does not, the names are asked again
    soon, in case the proxy has a new address; this request is answered with what is known."""
    proxies = trusted_proxies()
    if proxies and inside(address, proxies):
        return True, proxies
    if _names():
        _wake.set()
    return False, proxies


def forget() -> None:
    """Forget what the names had (the tests)."""
    _resolved.clear()


def peer(request: Request) -> str:
    """The address of the connection itself."""
    host = request.client.host if request.client else ""
    found = parse(host)
    return str(found) if found is not None else host


def _forwarded(request: Request, proxies: list[Network]) -> str | None:
    """The client a trusted proxy names: the last address of the header that is not a proxy itself."""
    entries = [entry.strip() for entry in request.headers.get("x-forwarded-for", "").split(",") if entry.strip()]
    for entry in reversed(entries):
        address = parse(entry)
        if address is None:
            return None  # a header nobody can read is not believed in part
        if not inside(address, proxies):
            return str(address)
    return None


def client_address(request: Request) -> str:
    """The address of whoever sent the request, as far as the server can know it."""
    cached = getattr(request.state, "nik_client_address", None)
    if cached is not None:
        return cached
    direct = peer(request)
    address = direct
    through_proxy, proxies = _is_proxy(direct)
    if through_proxy:
        address = _forwarded(request, proxies) or direct
    request.state.nik_client_address = address
    request.state.nik_through_proxy = through_proxy
    return address


def limiter_key(request: Request) -> str:
    """What the rate limiter counts by."""
    return client_address(request) or "unknown"


# --------------------------------------------------------------------------- #
# Whether that address is the person's                                        #
# --------------------------------------------------------------------------- #
def own_networks() -> list[Network]:
    """The networks this container (or machine) is directly on, read from the kernel's routes.
    Nothing on a system that has no ``/proc/net/route``."""
    networks: list[Network] = []
    try:
        with open("/proc/net/route", encoding="ascii") as handle:
            lines = handle.read().splitlines()[1:]
    except OSError:
        return networks
    for line in lines:
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            destination, gateway, mask = (int(parts[index], 16) for index in (1, 2, 7))
        except ValueError:
            continue
        if gateway != 0 or mask == 0:
            continue  # a route through a gateway, or the default route: not a network it is on
        address = ipaddress.IPv4Address(socket.ntohl(destination))
        prefix = bin(socket.ntohl(mask)).count("1")
        networks.append(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
    return networks + _own_networks_v6()


def _own_networks_v6() -> list[Network]:
    """The same for IPv6: the routes without a next hop, link-local and multicast left out."""
    networks: list[Network] = []
    try:
        with open("/proc/net/ipv6_route", encoding="ascii") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return networks
    for line in lines:
        parts = line.split()
        if len(parts) < 10 or len(parts[0]) != 32:
            continue
        try:
            prefix = int(parts[1], 16)
            network = ipaddress.ip_network((int(parts[0], 16), prefix), strict=False)
            direct = int(parts[4], 16) == 0
        except ValueError:
            continue
        if not direct or prefix in (0, 128) or network.is_link_local or network.is_multicast or network.is_loopback:
            continue
        networks.append(network)
    return networks


def overtrusting() -> bool:
    """Whether the server in front of the application rewrites addresses from a header for everybody."""
    return "*" in [part.strip() for part in os.getenv("FORWARDED_ALLOW_IPS", "").split(",")]


def describe(request: Request) -> dict[str, Any]:
    """What the server sees of the caller, for the screen where the policy is set.

    ``knowable`` is False when the address is not the person's own: the
    restriction of administrators to networks cannot work then, and the
    limits per address count everybody as one.
    """
    address = client_address(request)
    through_proxy = bool(getattr(request.state, "nik_through_proxy", False))
    found = parse(address)
    reason = ""
    if found is None:
        reason = "The connection has no address the server can read."
    elif through_proxy and (found.is_loopback or inside(found, own_networks())):
        reason = (
            f"The web container hands over every request as coming from {address}, an address of the "
            "server's own container network. Either you are using Nik from the server itself, or the "
            "container runtime hides the addresses of its clients (rootless podman and Docker Desktop do)."
        )
    elif not through_proxy and not found.is_loopback and inside(found, own_networks()):
        reason = (
            f"The connection comes from {address}, an address of the server's own container network that is "
            "not one of the trusted proxies. If a proxy stands there, name it in TRUSTED_PROXIES: until "
            "then everybody who comes through it looks like one client."
        )
    return {
        "address": address,
        "connection": peer(request),
        "throughProxy": through_proxy,
        "forwardedFor": request.headers.get("x-forwarded-for", "") if through_proxy else "",
        "knowable": not reason,
        "reason": reason,
        "trustedProxies": list(settings.TRUSTED_PROXIES),
        "overtrusting": overtrusting(),
    }


def knowable(request: Request) -> bool:
    return bool(describe(request)["knowable"])
