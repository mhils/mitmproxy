from __future__ import annotations
from contextvars import ContextVar

import mitmproxy.log
import mitmproxy.master
import mitmproxy.options

log: mitmproxy.log.Log
master: mitmproxy.master.Master
options: mitmproxy.options.Options

_log: ContextVar[mitmproxy.log.Log] = ContextVar('log')
_master: ContextVar[mitmproxy.master.Master] = ContextVar('master')
_options: ContextVar[mitmproxy.options.Options] = ContextVar('options')


def __getattr__(name):
    if name in ("log", "master", "options"):
        return globals()["_" + name].get()
    if name in ("_log", "_master", "_options"):
        return globals()[name]

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
