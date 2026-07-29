"""Run an FS-UAE oracle stage until its completion sentinel appears."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fs_uae", type=Path)
    parser.add_argument("config", type=Path)
    parser.add_argument("sentinel", type=Path)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--headless", action="store_true")
    arguments = parser.parse_args()
    arguments.sentinel.unlink(missing_ok=True)
    command = [str(arguments.fs_uae), str(arguments.config)]
    environment = None
    if arguments.headless:
        xvfb_run = shutil.which("xvfb-run")
        if xvfb_run is None:
            raise SystemExit("--headless requires xvfb-run")
        command = [
            xvfb_run,
            "-a",
            "-s",
            "-screen 0 1024x768x24 +extension GLX",
            *command,
        ]
        environment = os.environ | {
            "LIBGL_ALWAYS_SOFTWARE": "1",
            "SDL_AUDIODRIVER": "dummy",
        }
    process = subprocess.Popen(command, env=environment)
    deadline = time.monotonic() + arguments.timeout
    try:
        while time.monotonic() < deadline:
            result = process.poll()
            if arguments.sentinel.is_file():
                return 0
            if result is not None:
                raise SystemExit(f"FS-UAE exited before the sentinel (status {result})")
            time.sleep(0.25)
        raise SystemExit(f"FS-UAE timed out after {arguments.timeout:g} seconds")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
