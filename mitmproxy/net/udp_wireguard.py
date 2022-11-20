"""
This module contains a mock DatagramTransport for use with mitmproxy-wireguard.
"""
from __future__ import annotations
import asyncio
from typing import Any

import mitmproxy_rs

from mitmproxy.connection import Address


class WireGuardDatagramTransport(asyncio.DatagramTransport):
    def __init__(self, server: mitmproxy_rs.WireGuardServer | mitmproxy_rs.WindowsProxy, local_addr: Address, remote_addr: Address):
        self._server: mitmproxy_rs.WireGuardServer | mitmproxy_rs.WindowsProxy = server
        self._local_addr: Address = local_addr
        self._remote_addr: Address = remote_addr
        super().__init__()

    def sendto(self, data, addr=None):
        self._server.send_datagram(data, self._local_addr, addr or self._remote_addr)

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        if name == "sockname":
            if isinstance(self._server, mitmproxy_rs.WireGuardServer):
                return self._server.getsockname()
            else:
                return ("0.0.0.0", 0)
        else:
            raise NotImplementedError

    def get_protocol(self):
        return self

    async def drain(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass
