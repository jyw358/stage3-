"""LocalRunner: compile & run synthetic tasks with gcc + ASAN, no Docker needed.

Executor abstraction:
  - NativeExecutor: linux/macOS with gcc in PATH
  - WslExecutor:    Windows + WSL (paths translated to /mnt/<drive>/...)
Auto-detection order: native gcc -> WSL gcc -> None (caller reports guidance).
"""
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

from plugins.env_manager import RunOutcome

ASAN_ENV = {"ASAN_OPTIONS": "detect_leaks=0"}


def win_to_wsl(p) -> str:
    s = str(p).replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", s)
    return f"/mnt/{m.group(1).lower()}/{m.group(2)}" if m else s


class NativeExecutor:
    name = "native"

    def gcc_available(self) -> bool:
        return shutil.which("gcc") is not None

    def build_cmd(self, args: List, env: Optional[dict] = None) -> List:
        cmd = [str(a) for a in args]
        if env:
            cmd = ["env"] + [f"{k}={v}" for k, v in env.items()] + cmd
        return cmd

    def run(self, cmd: List, timeout_s: float):
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)


class WslExecutor(NativeExecutor):
    name = "wsl"

    def gcc_available(self) -> bool:
        try:
            r = subprocess.run(["wsl", "-e", "gcc", "--version"],
                               capture_output=True, text=True, timeout=20)
            return r.returncode == 0
        except Exception:
            return False

    def build_cmd(self, args: List, env: Optional[dict] = None) -> List:
        out = ["wsl", "-e"]
        if env:
            out += ["env"] + [f"{k}={v}" for k, v in env.items()]
        for a in args:
            s = str(a)
            if re.match(r"^[A-Za-z]:[\\/]", s):
                out.append(win_to_wsl(s))
            elif "\\" in s:  # relative windows path: fix separators, keep it relative to cwd
                out.append(s.replace("\\", "/"))
            else:
                out.append(s)
        return out


def detect_executor():
    # on Windows prefer WSL: MinGW gcc has poor/no ASAN support
    if sys.platform == "win32":
        w = WslExecutor()
        if w.gcc_available():
            return w
        if NativeExecutor().gcc_available():
            return NativeExecutor()
        return None
    if NativeExecutor().gcc_available():
        return NativeExecutor()
    return None


class LocalRunner:
    """Same .run(binary, poc_path) contract as DockerRunner, against local gcc builds."""

    def __init__(self, executor=None, timeout_s: float = 10):
        self.executor = executor or detect_executor()
        self.timeout_s = timeout_s
        if self.executor is None:
            raise RuntimeError("no gcc found: install gcc natively or enable WSL")

    # ---- build step (env preparation, not the PoC) ----
    def compile_target(self, src, out) -> bool:
        # -O0 on purpose: synthetic tasks must be optimization-independent
        # (at -O1 gcc DSE removes dead copies and the OOB access never happens)
        cmd = self.executor.build_cmd([
            "gcc", "-fsanitize=address", "-g", "-O0", "-fno-omit-frame-pointer",
            str(src), "-o", str(out),
        ])
        try:
            r = self.executor.run(cmd, timeout_s=120)
        except subprocess.TimeoutExpired:
            return False
        return r.returncode == 0

    # ---- exec step ----
    def run(self, binary, poc_path, timeout_s: Optional[float] = None) -> RunOutcome:
        cmd = self.executor.build_cmd([str(binary), str(poc_path)], env=ASAN_ENV)
        t0 = time.monotonic()
        try:
            r = self.executor.run(cmd, timeout_s or self.timeout_s)
        except subprocess.TimeoutExpired:
            return RunOutcome(ok=False, timed_out=True, duration_s=time.monotonic() - t0)
        except FileNotFoundError as e:
            return RunOutcome(ok=False, returncode=None, stderr=str(e),
                              duration_s=time.monotonic() - t0)
        return RunOutcome(
            ok=True, returncode=r.returncode,
            stdout=r.stdout[-20000:], stderr=r.stderr[-20000:],
            duration_s=time.monotonic() - t0,
        )
