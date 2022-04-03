import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Tuple


class DrainableDatagramProtocol(asyncio.DatagramProtocol):
    """
    A thin wrapper on top of asyncio.DatagramProtocol that makes it possible to await until writes are resumed.
    This is useful to create backpressure so that the write buffer doesn't grow infinitely.
    """

    def __init__(self):
        self.can_write = asyncio.Event()
        self.can_write.set()

    def pause_writing(self) -> None:
        self.can_write.clear()

    def resume_writing(self) -> None:
        self.can_write.set()

    async def drain(self):
        await self.can_write.wait()


@dataclass
class UdpDatagramWriter:
    transport: asyncio.DatagramTransport
    addr: tuple[str, int]

    def write(self, data: bytes):
        self.transport.sendto(data, self.addr)

    def get_extra_info(self, name, default=None):
        if name == "peername":
            return self.addr
        else:
            return self.transport.get_extra_info(name, default)

    def close(self):
        return self.transport.close()

    async def drain(self):
        proto: DrainableDatagramProtocol
        proto = self.transport.get_protocol()  # type: ignore
        await proto.drain()


class UdpDatagramReader:
    def __init__(self):
        # With Python's datagram protocol we have no way to limit the speed by which we receive packets.
        # To make sure that we aren't overwhelmed, we keep another buffer here and just discard additional packets.
        self.packet_queue = asyncio.Queue(42)  # ~2.75MB
        super().__init__()

    async def read(self, n):
        data = await self.packet_queue.get()
        assert len(data) <= n
        return data


DatagramCallback = Callable[[bytes, tuple[str, int], asyncio.DatagramTransport], None]


class UdpServer(DrainableDatagramProtocol):
    transport: asyncio.DatagramTransport
    datagram_callback: DatagramCallback

    def __init__(self, datagram_callback: DatagramCallback):
        super().__init__()
        self.datagram_callback = datagram_callback

    def close(self):
        self.transport.close()

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.datagram_callback(data, addr, self.transport)


class UdpClient(UdpDatagramReader, DrainableDatagramProtocol):
    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.packet_queue.put_nowait(data)


async def open_connection(host: str, port: int) -> Tuple[UdpDatagramReader, UdpDatagramWriter]:
    """UDP variant of asyncio.open_connection."""
    loop = asyncio.get_running_loop()
    transport: asyncio.DatagramTransport
    reader: UdpClient
    transport, reader = await loop.create_datagram_endpoint(
        lambda: UdpClient(), remote_addr=(host, port)
    )
    writer = UdpDatagramWriter(transport, (host, port))

    return reader, writer


async def start_server(
    datagram_handler: DatagramCallback,
    host: str,
    port: int,
) -> UdpServer:
    loop = asyncio.get_running_loop()
    server: UdpServer
    transport, server = await loop.create_datagram_endpoint(
        lambda: UdpServer(datagram_handler),
        local_addr=(host, port)
    )
    return server
