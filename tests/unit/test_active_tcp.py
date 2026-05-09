import asyncio
import pytest
from mcpmap.discover.active import tcp_open, tcp_sweep


async def _serve_once(port_holder):
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port_holder.append(server.sockets[0].getsockname()[1])
    return server


@pytest.mark.asyncio
async def test_tcp_open_true_for_listening():
    ports = []
    server = await _serve_once(ports)
    try:
        assert await tcp_open("127.0.0.1", ports[0], timeout=1.0)
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_tcp_open_false_for_unbound():
    # 1 is reserved/unbound on most systems
    assert not await tcp_open("127.0.0.1", 1, timeout=0.3)


@pytest.mark.asyncio
async def test_tcp_sweep_returns_open_ports_only():
    ports = []
    server = await _serve_once(ports)
    try:
        result = await tcp_sweep("127.0.0.1", [1, ports[0], 2], timeout=0.5, concurrency=8)
        assert result == [ports[0]]
    finally:
        server.close()
        await server.wait_closed()
