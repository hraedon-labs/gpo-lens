"""Start and stop a real ``gpo-lens serve`` process for browser tests."""

from __future__ import annotations

import os
import shutil
import socket
import sqlite3
import subprocess
import sys
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


def start(tmp: Path) -> LiveServer:
    estate = tmp / "estate"
    shutil.copytree(GOLDEN, estate)
    db = tmp / "browser.sqlite3"
    env = _child_env(tmp)
    subprocess.run(
        [sys.executable, "-m", "gpo_lens", "--db", str(db), "ingest", str(estate)],
        check=True,
        env=env,
        capture_output=True,
        timeout=120,
    )
    port = _free_port()
    log = tmp / "server.log"
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
        )
    url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 30
    while True:
        if process.poll() is not None:
            raise RuntimeError(f"server exited early:\n{log.read_text(errors='replace')}")
        try:
            with urllib.request.urlopen(f"{url}/healthz", timeout=1) as resp:
                if resp.status == 200:
                    break
        except OSError:
            pass
        if time.monotonic() > deadline:
            process.kill()
            raise RuntimeError(f"server did not become healthy:\n{log.read_text(errors='replace')}")
        time.sleep(0.2)
    server = LiveServer(url=url, db=db, workdir=tmp, process=process, log=log)
    server.snapshots_at_start = len(server.query("SELECT id FROM snapshot"))
    return server


def stop(server: LiveServer) -> None:
    server.process.terminate()
    try:
        server.process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.process.kill()
        server.process.wait(timeout=10)
