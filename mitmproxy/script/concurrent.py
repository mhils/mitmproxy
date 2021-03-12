"""
This module provides a @concurrent decorator primitive to
offload computations from mitmproxy's main master thread.
"""
import asyncio

from mitmproxy import hooks
from mitmproxy.coretypes import basethread


def concurrent(fn):
    if fn.__name__ not in set(hooks.all_hooks.keys()) - {"load", "configure"}:
        raise NotImplementedError(
            "Concurrent decorator not supported for '%s' method." % fn.__name__
        )

    async def _concurrent(*args, **kwargs):
        done = asyncio.Event()

        def run():
            fn(*args, **kwargs)
            done.set()

        basethread.BaseThread(f"script.concurrent {fn.__name__}", target=run).start()

        await done.wait()

    return _concurrent
