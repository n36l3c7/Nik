"""The egress proxy on its own (no Chromium): what it lets out and what it refuses."""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import egress  # noqa: E402


async def _upstream(body: bytes = b"hello"):
    """A tiny HTTP server on loopback; returns (server, port, the request heads it saw)."""
    seen: list[bytes] = []

    async def handle(reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        seen.append(head)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1], seen


async def _ask(port: int, request: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(request)
    await writer.drain()
    answer = await asyncio.wait_for(reader.read(), 10)
    writer.close()
    return answer


def test_public_and_internal_names():
    assert egress.is_public("185.220.101.47") and egress.is_public("2606:4700:4700::1111")
    for address in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "::1", "fe80::1", "0.0.0.0", "nope"):
        assert not egress.is_public(address), address
    for name in ("intranet", "fileserver.corp", "nas.local", "printer.home.arpa", ""):
        assert egress.internal_name(name), name
    assert not egress.internal_name("evil.top") and not egress.internal_name("10.0.0.1")


def test_private_addresses_are_refused_whatever_names_them():
    async def scenario():
        proxy = egress.EgressProxy()
        port = await proxy.start()
        upstream, private_port, seen = await _upstream()
        try:
            # Loopback, a cloud metadata address, an internal name: all refused, none contacted.
            for target in (f"127.0.0.1:{private_port}", "169.254.169.254:80", "db:5432", "localhost:80"):
                answer = await _ask(port, f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                assert answer.startswith(b"HTTP/1.1 403"), target
            answer = await _ask(port, f"GET http://127.0.0.1:{private_port}/x HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            assert answer.startswith(b"HTTP/1.1 403") and b"Blocked by Nik" in answer
            assert seen == [] and proxy.refused == 5
            # Not something a browser sends through a proxy: refused too.
            assert (await _ask(port, b"GET /relative HTTP/1.1\r\nHost: x\r\n\r\n")).startswith(b"HTTP/1.1 400")
            assert (await _ask(port, b"GET ftp://example.org/ HTTP/1.1\r\n\r\n")).startswith(b"HTTP/1.1 400")
            assert (await _ask(port, b"garbage\r\n\r\n")).startswith(b"HTTP/1.1 400")
        finally:
            upstream.close()
            await proxy.stop()

    asyncio.run(scenario())


def test_an_allowed_request_is_forwarded_in_origin_form_and_remembered():
    async def scenario():
        proxy = egress.EgressProxy(allow=lambda address: address == "127.0.0.1")
        port = await proxy.start()
        upstream, site_port, seen = await _upstream(b"the page")
        try:
            request = (
                f"GET http://127.0.0.1:{site_port}/a/b?c=1 HTTP/1.1\r\nHost: 127.0.0.1:{site_port}\r\n"
                "Proxy-Connection: keep-alive\r\nUser-Agent: test\r\n\r\n"
            )
            answer = await _ask(port, request.encode())
            assert answer.endswith(b"the page")
            head = seen[0]
            assert head.startswith(b"GET /a/b?c=1 HTTP/1.1\r\n")
            assert b"proxy-connection" not in head.lower() and b"Connection: close" in head
            assert b"User-Agent: test" in head
            assert proxy.address_of("127.0.0.1", site_port) == "127.0.0.1"

            # A tunnel: bytes flow both ways untouched.
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(f"CONNECT 127.0.0.1:{site_port} HTTP/1.1\r\n\r\n".encode())
            assert (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
            writer.write(b"GET /tunnelled HTTP/1.1\r\nHost: x\r\n\r\n")
            await writer.drain()
            assert (await asyncio.wait_for(reader.read(), 10)).endswith(b"the page")
            writer.close()
            assert seen[1].startswith(b"GET /tunnelled")
        finally:
            upstream.close()
            await proxy.stop()

    asyncio.run(scenario())


def test_a_name_with_one_private_address_is_refused():
    """A name that answers a public and a private address cannot be used to reach the private one."""

    async def scenario():
        proxy = egress.EgressProxy()
        loop = asyncio.get_running_loop()

        async def both(host, port, **kwargs):
            return [(2, 1, 6, "", ("185.220.101.47", 0)), (2, 1, 6, "", ("10.0.0.5", 0))]

        loop.getaddrinfo = both
        assert await proxy.vetted("rebind.evil.top") is None

        async def public(host, port, **kwargs):
            return [(10, 1, 6, "", ("2606:4700:4700::1111", 0, 0, 0)), (2, 1, 6, "", ("185.220.101.47", 0))]

        loop.getaddrinfo = public
        # IPv4 first: the container may have no IPv6 route.
        assert await proxy.vetted("Evil.Top.") == "185.220.101.47"

    asyncio.run(scenario())
