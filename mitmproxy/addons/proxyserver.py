import asyncio
import re
from typing import Dict, Optional, Tuple, Union

from wsproto.frame_protocol import Opcode

from mitmproxy import command, ctx, dns, exceptions, flow, http, log, master, options, platform, tcp, websocket
from mitmproxy.connection import ConnectionProtocol
from mitmproxy.flow import Flow
from mitmproxy.proxy import commands, events, layers, server_hooks, udp_server
from mitmproxy.proxy import server
from mitmproxy.proxy.layers.tcp import TcpMessageInjected
from mitmproxy.proxy.layers.websocket import WebSocketMessageInjected
from mitmproxy.proxy.udp_server import UdpDatagramReader, UdpDatagramWriter, UdpServer
from mitmproxy.utils import asyncio_utils, human


class ProxyConnectionHandler(server.LiveConnectionHandler):
    master: master.Master

    def __init__(self, master, r, w, options):
        self.master = master
        super().__init__(r, w, options)
        self.log_prefix = f"{human.format_address(self.client.peername)}: "

    async def handle_hook(self, hook: commands.StartHook) -> None:
        with self.timeout_watchdog.disarm():
            # We currently only support single-argument hooks.
            data, = hook.args()
            await self.master.addons.handle_lifecycle(hook)
            if isinstance(data, flow.Flow):
                await data.wait_for_resume()

    def log(self, message: str, level: str = "info") -> None:
        x = log.LogEntry(self.log_prefix + message, level)
        asyncio_utils.create_task(
            self.master.addons.handle_lifecycle(log.AddLogHook(x)),
            name="ProxyConnectionHandler.log"
        )


class Proxyserver:
    """
    This addon runs the actual proxy server.
    """
    tcp_server: Optional[asyncio.AbstractServer] = None
    dns_server: Optional[UdpServer] = None
    listen_port: int
    master: master.Master
    options: options.Options
    is_running: bool = False
    _connections: Dict[Tuple, ProxyConnectionHandler]

    def __init__(self):
        self._lock = asyncio.Lock()
        self._connections = {}

    def __repr__(self):
        return f"ProxyServer({'running' if self.tcp_server else 'stopped'}, {len(self._connections)} active conns)"

    def load(self, loader):
        loader.add_option(
            "connection_strategy", str, "eager",
            "Determine when server connections should be established. When set to lazy, mitmproxy "
            "tries to defer establishing an upstream connection as long as possible. This makes it possible to "
            "use server replay while being offline. When set to eager, mitmproxy can detect protocols with "
            "server-side greetings, as well as accurately mirror TLS ALPN negotiation.",
            choices=("eager", "lazy")
        )
        loader.add_option(
            "stream_large_bodies", Optional[str], None,
            """
            Stream data to the client if response body exceeds the given
            threshold. If streamed, the body will not be stored in any way.
            Understands k/m/g suffixes, i.e. 3m for 3 megabytes.
            """
        )
        loader.add_option(
            "body_size_limit", Optional[str], None,
            """
            Byte size limit of HTTP request and response bodies. Understands
            k/m/g suffixes, i.e. 3m for 3 megabytes.
            """
        )
        loader.add_option(
            "keep_host_header", bool, False,
            """
            Reverse Proxy: Keep the original host header instead of rewriting it
            to the reverse proxy target.
            """
        )
        loader.add_option(
            "proxy_debug", bool, False,
            "Enable debug logs in the proxy core.",
        )
        loader.add_option(
            "normalize_outbound_headers", bool, True,
            """
            Normalize outgoing HTTP/2 header names, but emit a warning when doing so.
            HTTP/2 does not allow uppercase header names. This option makes sure that HTTP/2 headers set
            in custom scripts are lowercased before they are sent.
            """,
        )
        loader.add_option(
            "validate_inbound_headers", bool, True,
            """
            Make sure that incoming HTTP requests are not malformed.
            Disabling this option makes mitmproxy vulnerable to HTTP smuggling attacks.
            """,
        )

        loader.add_option(
            "dns_server", bool, False,
            """Start a DNS server. Disabled by default."""
        )
        loader.add_option(
            "dns_listen_host", str, "127.0.0.1",
            """Address to bind DNS server to."""
        )
        loader.add_option(
            "dns_listen_port", int, 53,
            """DNS server service port."""
        )
        loader.add_option(
            "dns_mode", str, "simple",
            """DNS mode can be "simple", "reverse:<ip>[:<port>]" or "transparent".""",
        )

    async def running(self):
        self.master = ctx.master
        self.options = ctx.options
        self.is_running = True
        await self.refresh_server()

    def configure(self, updated):
        if "stream_large_bodies" in updated:
            try:
                human.parse_size(ctx.options.stream_large_bodies)
            except ValueError:
                raise exceptions.OptionsError(f"Invalid stream_large_bodies specification: "
                                              f"{ctx.options.stream_large_bodies}")
        if "body_size_limit" in updated:
            try:
                human.parse_size(ctx.options.body_size_limit)
            except ValueError:
                raise exceptions.OptionsError(f"Invalid body_size_limit specification: "
                                              f"{ctx.options.body_size_limit}")
        if "mode" in updated and ctx.options.mode == "transparent":  # pragma: no cover
            platform.init_transparent_mode()
        if "dns_mode" in updated:
            # TODO: try to integrate that with server_spec.parse.
            if not re.match(r"regular|transparent|reverse:[^:]+(:\d+)?", ctx.options.dns_mode):
                raise exceptions.OptionsError(f"Invalid DNS mode {ctx.options.dns_mode!r}.")
        if self.is_running and any(x in updated for x in [
            "server", "listen_host", "listen_port",
            "dns_server", "dns_listen_host", "dns_listen_port",
        ]):
            asyncio.create_task(self.refresh_server())

    async def refresh_server(self):
        async with self._lock:
            if self.tcp_server:
                ctx.log.info("Stopping TCP server...")
                self.tcp_server.close()
                await self.tcp_server.wait_closed()
                self.tcp_server = None
            if ctx.options.server:
                if not ctx.master.addons.get("nextlayer"):
                    ctx.log.warn("Warning: Running proxyserver without nextlayer addon!")
                try:
                    self.tcp_server = await asyncio.start_server(
                        self.handle_tcp_connection,
                        self.options.listen_host,
                        self.options.listen_port,
                    )
                except OSError as e:
                    ctx.log.error(str(e))
                else:
                    # TODO: This is a bit confusing currently for `-p 0`.
                    addrs = {f"http://{human.format_address(s.getsockname())}" for s in self.tcp_server.sockets}
                    ctx.log.info(f"Proxy server listening at {' and '.join(addrs)}")

            if self.dns_server:
                ctx.log.info("Stopping UDP server...")
                self.dns_server.close()
                # FIXME await self.dns_server.wait_closed()
                self.dns_server = None
            if ctx.options.dns_server:
                try:
                    self.dns_server = await udp_server.start_server(
                        self.handle_udp_datagram,
                        self.options.dns_listen_host,
                        self.options.dns_listen_port,
                    )
                except OSError as e:
                    ctx.log.error(str(e))
                else:
                    addr = human.format_address((self.options.dns_listen_host, self.options.dns_listen_port))
                    ctx.log.info(f"DNS server listening at {addr}")

    async def shutdown_server(self):
        ctx.log.info("Stopping server...")
        self.tcp_server.close()
        await self.tcp_server.wait_closed()
        self.tcp_server = None

    async def handle_tcp_connection(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        sockname = w.get_extra_info('sockname')
        peername = w.get_extra_info('peername')
        conn_id = ("tcp", sockname, peername)
        await self.handle_connection(r, w, conn_id)

    def handle_udp_datagram(self, data: bytes, peername: Tuple[str, int], transport: asyncio.DatagramTransport) -> None:
        sockname = transport.get_extra_info("sockname")
        conn_id = ("udp", sockname, peername)  # do more fancy stuff here depending on the protocol.
        if conn_id not in self._connections:
            reader = UdpDatagramReader()
            writer = UdpDatagramWriter(transport, peername)
            # XXX: This might be racy, we should set ._connections here.
            asyncio.create_task(
                self.handle_connection(reader, writer, conn_id),
            )
        else:
            handler = self._connections[conn_id]
            reader = handler.transports[handler.client].reader

        try:
            reader.packet_queue.put_nowait(data)
        except asyncio.QueueFull:
            ctx.log.debug("Discarded UDP packet due to overload.")

    async def handle_connection(
        self,
        r: Union[asyncio.StreamReader, UdpDatagramReader],
        w: Union[asyncio.StreamWriter, UdpDatagramWriter],
        connection_id: Tuple
    ) -> None:
        asyncio_utils.set_task_debug_info(
            asyncio.current_task(),
            name=f"Proxyserver.handle_connection",
            client=w.get_extra_info('peername'),
        )
        handler = ProxyConnectionHandler(
            self.master,
            r,
            w,
            self.options
        )
        self._connections[connection_id] = handler

        # hacky: For DNS, hardcode layer and destination here.
        if connection_id[0] == "udp":
            handler.layer = layers.DNSLayer(handler.layer.context)
            if m := re.match(r"reverse:(?P<host>[^:]+)(:(?P<port>\d+))?", self.options.dns_mode):
                handler.layer.context.server.address = (m["host"], int(m["port"] or 53))
                handler.layer.context.server.protocol = ConnectionProtocol.UDP
            elif self.options.dns_mode == "transparent":
                raise NotImplementedError
            else:
                assert self.options.dns_mode == "simple"
        try:
            await handler.handle_client()
        finally:
            del self._connections[connection_id]

    def inject_event(self, event: events.MessageInjected):
        conn_id = ("tcp", event.flow.client_conn.sockname, event.flow.client_conn.peername)
        if conn_id not in self._connections:
            raise ValueError("Flow is not from a live connection.")
        self._connections[conn_id].server_event(event)

    @command.command("inject.websocket")
    def inject_websocket(self, flow: Flow, to_client: bool, message: bytes, is_text: bool = True):
        if not isinstance(flow, http.HTTPFlow) or not flow.websocket:
            ctx.log.warn("Cannot inject WebSocket messages into non-WebSocket flows.")

        msg = websocket.WebSocketMessage(
            Opcode.TEXT if is_text else Opcode.BINARY,
            not to_client,
            message
        )
        event = WebSocketMessageInjected(flow, msg)
        try:
            self.inject_event(event)
        except ValueError as e:
            ctx.log.warn(str(e))

    @command.command("inject.tcp")
    def inject_tcp(self, flow: Flow, to_client: bool, message: bytes):
        if not isinstance(flow, tcp.TCPFlow):
            ctx.log.warn("Cannot inject TCP messages into non-TCP flows.")

        event = TcpMessageInjected(flow, tcp.TCPMessage(not to_client, message))
        try:
            self.inject_event(event)
        except ValueError as e:
            ctx.log.warn(str(e))

    def server_connect(self, ctx: server_hooks.ServerConnectionHookData):
        assert ctx.server.address
        self_connect = (
            ctx.server.address[1] in (self.options.dns_listen_port, self.options.listen_port)
            and
            ctx.server.address[0] in ("localhost", "127.0.0.1", "::1", self.options.listen_host)
        )
        if self_connect:
            ctx.server.error = (
                "Request destination unknown. "
                "Unable to figure out where this request should be forwarded to."
            )

    async def dns_request(self, flow: dns.DNSFlow) -> None:
        if self.options.dns_mode == "simple":
            flow.response = await flow.request.resolve()
