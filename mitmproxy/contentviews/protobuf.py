import io
from collections import Callable
from dataclasses import dataclass
from typing import Optional

from kaitaistruct import KaitaiStream
from . import base
from mitmproxy.contrib.kaitaistruct import google_protobuf
from mitmproxy import flowfilter, http, flow


def write_buf(out, field_tag, body, indent_level):
    if body is not None:
        out.write("{: <{level}}{}: {}\n".format('', field_tag, body if isinstance(body, int) else str(body, 'utf-8'),
                                                level=indent_level))
    elif field_tag is not None:
        out.write(' ' * indent_level + str(field_tag) + " {\n")
    else:
        out.write(' ' * indent_level + "}\n")


def format_pbuf(raw):
    out = io.StringIO()
    stack = []

    try:
        buf = google_protobuf.GoogleProtobuf(KaitaiStream(io.BytesIO(raw)))
    except:
        return False
    stack.extend([(pair, 0) for pair in buf.pairs[::-1]])

    while len(stack):
        pair, indent_level = stack.pop()

        if pair.wire_type == pair.WireTypes.group_start:
            body = None
        elif pair.wire_type == pair.WireTypes.group_end:
            body = None
            pair._m_field_tag = None
        elif pair.wire_type == pair.WireTypes.len_delimited:
            body = pair.value.body
        elif pair.wire_type == pair.WireTypes.varint:
            body = pair.value.value
        else:
            body = pair.value

        try:
            next_buf = google_protobuf.GoogleProtobuf(KaitaiStream(io.BytesIO(body)))
            stack.extend([(pair, indent_level + 2) for pair in next_buf.pairs[::-1]])
            write_buf(out, pair.field_tag, None, indent_level)
        except:
            write_buf(out, pair.field_tag, body, indent_level)

        if stack:
            prev_level = stack[-1][1]
        else:
            prev_level = 0

        if prev_level < indent_level:
            levels = int((indent_level - prev_level) / 2)
            for i in range(1, levels + 1):
                write_buf(out, None, None, indent_level - i * 2)

    return out.getvalue()


@dataclass
class ProtobufDef:
    name: Optional[str] = None
    decode_as: Optional[Callable[[bytes], str]] = None


class _ViewProtobuf(base.View):
    """Human friendly view of protocol buffers
    The view uses the protoc compiler to decode the binary
    """
    definitions: dict[str, ProtobufDef]

    def __init__(self, definitions: dict[str, ProtobufDef]):
        self.definitions = definitions

    def __call__(self, data, **metadata):
        decoded = format_pbuf(data)
        if not decoded:
            raise ValueError("Failed to parse input.")

        return "Protobuf", base.format_text(decoded)


class ViewProtobuf(_ViewProtobuf):
    """Default rendering of protobufs (with no additional information available)"""
    name = "Protocol Buffer"

    def __init__(self):
        super().__init__({})

    __content_types = [
        "application/x-protobuf",
        "application/x-protobuffer",
    ]

    def render_priority(self, data: bytes, *, content_type: Optional[str] = None, **metadata) -> float:
        return float(bool(data) and content_type in self.__content_types)


class CustomProtobuf(_ViewProtobuf):
    """Customized protobuf rendering (with additional metadata specified manually)"""
    # TODO: Ideally we'd have something that consumes .proto files as well

    def __init__(self, filt: str, definitions: dict[str, ProtobufDef]):
        self.filter = flowfilter.parse(filt)
        super().__init__(definitions)

    @property
    def name(self):
        return f"Protobuf ({self.filter.pattern})"

    def render_priority(
        self,
        data: bytes,
        *,
        content_type: Optional[str] = None,
        flow: Optional[flow.Flow] = None,
        http_message: Optional[http.Message] = None,
        **metadata
    ) -> float:
        return 2 * float(self.filter(flow))
