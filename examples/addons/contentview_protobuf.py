from mitmproxy import contentviews
from mitmproxy.contentviews import protobuf

from mitmproxy.contentviews.protobuf import CustomProtobuf, ProtobufDef

get_info = CustomProtobuf(
    "example.com/foo ~s",
    {
        "3": ProtobufDef(name="GPS Position"),
        "3.1": ProtobufDef(name="latitude", decode_as=protobuf.decode_double)
    }
)


def load(l):
    contentviews.add(get_info)


def done():
    contentviews.remove(get_info)
