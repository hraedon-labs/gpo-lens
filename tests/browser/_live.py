"""Start and stop a real ``gpo-lens serve`` process for browser tests."""

from __future__ import annotations

import atexit
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
GOLDEN = _ROOT / "tests" / "golden_estate"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# Live server processes started by this run; the atexit hook kills any whose
# fixture teardown never ran (Ctrl-C during setup, a wedged teardown).
_LIVE: set[subprocess.Popen[bytes]] = set()


def _die_with_parent() -> None:  # pragma: no cover - runs in the child
    """Linux: deliver SIGTERM to the server if pytest itself dies (even SIGKILL)."""
    if sys.platform.startswith("linux"):
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the server's whole process group, escalating to SIGKILL."""
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
    _LIVE.discard(process)


@atexit.register
def _reap_all() -> None:
    for process in list(_LIVE):
        _kill_group(process)


_INTERRUPT_GRACE_SECONDS = 15
_handlers_installed = False


def _install_interrupt_handlers() -> None:
    """Reap servers the moment SIGINT/SIGTERM arrives, then bound the shutdown.

    pytest-playwright's sync API can spin after a KeyboardInterrupt instead of
    unwinding (reviewer repro: pytest stuck in state R for minutes), so fixture
    teardown and atexit never run. The handler kills every live server group
    first, then lets the previous handler raise as usual; a daemon watchdog
    hard-exits the run if it has not finished within the grace period.
    Installed only once a browser test actually starts a server.
    """
    global _handlers_installed
    if _handlers_installed or threading.current_thread() is not threading.main_thread():
        return
    _handlers_installed = True
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous = signal.getsignal(signum)

        def _handler(sig: int, frame: object, previous: object = previous) -> None:
            _reap_all()
            watchdog = threading.Timer(_INTERRUPT_GRACE_SECONDS, os._exit, args=(128 + sig,))
            watchdog.daemon = True
            watchdog.start()
            if callable(previous):
                previous(sig, frame)
            elif previous == signal.SIG_DFL:
                signal.signal(sig, signal.SIG_DFL)
                os.kill(os.getpid(), sig)

        signal.signal(signum, _handler)


def _child_env(tmp: Path) -> dict[str, str]:
    # Start from a clean gpo-lens configuration: no token, no narration key,
    # default (loopback-only) Host allow-list. Temporary files stay under tmp.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GPO_LENS_")}
    env["TMPDIR"] = str(tmp)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


@dataclass
class LiveServer:
    url: str
    db: Path
    workdir: Path
    process: subprocess.Popen[bytes]
    log: Path
    snapshots_at_start: int = field(default=0)

    def query(self, sql: str, *params: object) -> list[tuple[object, ...]]:
        conn = sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()


def start(tmp: Path, *, seed: bool = True) -> LiveServer:
    estate = tmp / "estate"
    shutil.copytree(GOLDEN, estate)
    db = tmp / "browser.sqlite3"
    env = _child_env(tmp)
    if seed:
        subprocess.run(
            [sys.executable, "-m", "gpo_lens", "--db", str(db), "ingest", str(estate)],
            check=True,
            env=env,
            capture_output=True,
            timeout=120,
        )
    else:
        from gpo_lens.store import init_db

        conn = sqlite3.connect(db)
        try:
            init_db(conn)
        finally:
            conn.close()
    # Port TOCTOU: the port is free when chosen but another process may take it
    # before uvicorn binds. Health is only trusted when THIS process is alive and
    # its own log reports the bind on this port; a bind failure retries on a new
    # port instead of silently attaching to a foreign server.
    last_log = ""
    for _attempt in range(3):
        port = _free_port()
        url = f"http://127.0.0.1:{port}"
        log = tmp / f"server-{port}.log"
        process = _spawn(db, port, env, tmp, log)
        try:
            if _wait_healthy(process, url, port, log):
                break
            last_log = log.read_text(errors="replace")
            _kill_group(process)
        except BaseException:
            _kill_group(process)
            raise
    else:
        raise RuntimeError(f"server could not bind a free port in 3 attempts:\n{last_log}")
    server = LiveServer(url=url, db=db, workdir=tmp, process=process, log=log)
    server.snapshots_at_start = len(server.query("SELECT id FROM snapshot"))
    return server


def _spawn(
    db: Path, port: int, env: dict[str, str], tmp: Path, log: Path
) -> subprocess.Popen[bytes]:
    with log.open("wb") as handle:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "gpo_lens",
                "--db",
                str(db),
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            env=env,
            cwd=tmp,
            stdout=handle,
            stderr=subprocess.STDOUT,
            # Own process group: stop() signals the group, and terminal Ctrl-C
            # cannot leave a half-dead server behind the pytest process.
            start_new_session=True,
            preexec_fn=_die_with_parent,  # noqa: PLW1509 - single-threaded spawn
        )
    _LIVE.add(process)
    _install_interrupt_handlers()
    return process


def _wait_healthy(process: subprocess.Popen[bytes], url: str, port: int, log: Path) -> bool:
    """True once our own process is serving ``url``; False if it failed to bind."""
    bound = f"Uvicorn running on http://127.0.0.1:{port}"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            text = log.read_text(errors="replace")
            if "address already in use" in text.lower():
                return False
            raise RuntimeError(f"server exited early:\n{text}")
        if bound in log.read_text(errors="replace"):
            try:
                with urllib.request.urlopen(f"{url}/healthz", timeout=1) as resp:
                    # Re-check liveness after the response: a foreign server
                    # could answer while ours was dying on a bind error.
                    if resp.status == 200 and process.poll() is None:
                        return True
            except OSError:
                pass
        time.sleep(0.2)
    raise RuntimeError(f"server did not become healthy:\n{log.read_text(errors='replace')}")


def stop(server: LiveServer) -> None:
    _kill_group(server.process)
