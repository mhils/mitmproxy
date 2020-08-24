import asyncio
import os
import importlib.util
import importlib.machinery
import sys
import types
import typing
import traceback
from pathlib import Path

from mitmproxy import addonmanager
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import command
from mitmproxy import eventsequence
from mitmproxy import ctx
import mitmproxy.types as mtypes


def load_script_module(path: Path) -> typing.Optional[types.ModuleType]:
    """
    Load a Python module from a file path.

    Returns:
        The loaded Python module.

    Raises:
        Anything that is raised while loading the module.
    """
    module_name = "__mitmproxy_script__"
    # if there already is an existing script in sys.modules, remove it.
    sys.modules.pop(module_name, None)

    oldpath = sys.path
    sys.path.insert(0, os.path.dirname(path))
    try:
        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore
        if not getattr(module, "name", None):
            module.name = path.name  # type: ignore
        return module
    except ModuleNotFoundError as e:
        raise ModuleNotFoundError(
            f"No module named {e.name!r}. "
            f"If your mitmproxy addons require the installation of "
            f"additional Python packages, you may need to install mitmproxy from PyPI.\n"
            f"https://docs.mitmproxy.org/stable/overview-installation/"
        )
    finally:
        sys.path[:] = oldpath


ReloadInterval = 1


class Script:
    """
    An addon that manages a single script.
    """
    id: str
    path: Path
    module: typing.Optional[types.ModuleType]
    reload_task: typing.Optional[asyncio.Future] = None

    def __init__(self, id: str, path: Path, reload: bool) -> None:
        self.id = id
        self.path = path
        self.module = None
        if reload:
            self.reload_task = asyncio.ensure_future(self.watcher())

    @property
    def name(self):
        return f"scriptmanager:{self.id}"

    def done(self):
        if self.reload_task:
            self.reload_task.cancel()

    @property
    def addons(self):
        return [self.module] if self.module else []

    def load(self):
        if self.module:
            ctx.master.addons.remove(self.module)
            self.module = None

        self.module = load_script_module(self.path)
        ctx.master.addons.register(self.module)

    def async_reload(self) -> None:
        ctx.log.info(f"Reloading script {self.id}")
        try:
            self.load()
        except Exception:
            etype, exc, tb = sys.exc_info()
            tb = addonmanager.cut_traceback(tb, "source_to_code")
            log_msg = "".join(traceback.format_exception(etype, exc, tb))
            ctx.log.error(log_msg)

    async def watcher(self):
        last_mtime = None
        while True:
            try:
                mtime = self.path.stat().st_mtime
            except FileNotFoundError:
                mtime = -1
            if mtime != last_mtime:
                if last_mtime is not None:
                    self.async_reload()
                last_mtime = mtime
            await asyncio.sleep(ReloadInterval)


class ScriptLoader:
    """
        An addon that manages loading scripts from options.
    """

    def __init__(self):
        self.is_running = False
        self.addons = []

    def load(self, loader):
        loader.add_option(
            "scripts", typing.Sequence[str], [],
            "Execute a script."
        )

    addons: typing.List[Script]

    def running(self):
        self.is_running = True

    @command.command("script.run")
    def script_run(self, flows: typing.Sequence[flow.Flow], path: mtypes.Path) -> None:
        """
            Run a script on the specified flows. The script is configured with
            the current options and all lifecycle events for each flow are
            simulated. Note that the load event is not invoked.
        """
        p = Path(path)
        if not p.is_file():
            ctx.log.error(f'No such script: {p}')
            return
        mod = load_script_module(p)
        if mod:
            ctx.master.addons.invoke_addon(mod, "running")
            ctx.master.addons.invoke_addon(
                mod,
                "configure",
                ctx.options.keys()
            )
            for f in flows:
                for evt, arg in eventsequence.iterate(f):
                    ctx.master.addons.invoke_addon(mod, evt, arg)

    def configure(self, updated):
        if "scripts" in updated:
            script_files: typing.Dict[str, Path] = {}
            for s in ctx.options.scripts:
                if s in script_files:
                    raise exceptions.OptionsError(f"Duplicate script: {s}")
                p = Path(s).expanduser()
                if not p.is_file():
                    raise exceptions.OptionsError(f"No such script: {p}")
                script_files[s] = p

            for a in self.addons[:]:
                if a.id not in script_files:
                    ctx.log.info(f"Un-loading script: {a.id}")
                    ctx.master.addons.remove(a)
                    self.addons.remove(a)

            # The machinations below are to ensure that:
            #   - Scripts remain in the same order
            #   - Scripts are not initialized un-necessarily. If only a
            #   script's order in the script list has changed, it is just
            #   moved.

            current = {}
            for a in self.addons:
                current[a.id] = a

            ordered = []
            new_scripts = []
            for name, path in script_files.items():
                if name in current:
                    ordered.append(current[name])
                else:
                    sc = Script(name, path, True)
                    ordered.append(sc)
                    new_scripts.append(sc)

            self.addons = ordered

            for s in new_scripts:
                ctx.log.info(f"Loading script {s.id}")
                try:
                    s.load()
                except Exception as e:
                    raise exceptions.OptionsError(f"Error loading {s.id}: {str(e)}") from e
                if self.is_running:
                    # We're already running, so we have to explicitly register and
                    # configure the addon
                    ctx.master.addons.invoke_addon(s, "running")
                    ctx.master.addons.invoke_addon(s, "configure", ctx.options.keys())
