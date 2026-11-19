#!/usr/bin/env python3
"""Run release/offline Go tests package by package with bounded liveness."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, TextIO


Runner = Callable[..., subprocess.CompletedProcess[str]]


def release_env(base_env: dict[str, str], cache_dir: str, appdata_dir: str) -> dict[str, str]:
    env = dict(base_env)
    env["GOTOOLCHAIN"] = "local"
    env["GOFLAGS"] = "-mod=vendor"
    env["GOTELEMETRY"] = "off"
    env["GOCACHE"] = cache_dir
    env["APPDATA"] = appdata_dir
    return env


def sorted_go_packages(output: str) -> list[str]:
    return sorted({line.strip() for line in output.splitlines() if line.strip()})


def run_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    popen_kwargs: dict[str, object] = {}
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True

    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
        **popen_kwargs,
    )
    windows_job = _create_windows_kill_job(process) if os.name == "nt" else None

    def collect(stream: TextIO | None, chunks: list[str]) -> None:
        if stream is None:
            return
        try:
            for piece in iter(stream.readline, ""):
                chunks.append(piece)
        finally:
            try:
                stream.close()
            except OSError:
                pass

    stdout_thread = threading.Thread(target=collect, args=(process.stdout, stdout_chunks), daemon=True)
    stderr_thread = threading.Thread(target=collect, args=(process.stderr, stderr_chunks), daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    deadline = time.monotonic() + timeout
    while process.poll() is None:
        if time.monotonic() >= deadline:
            _terminate_process_tree(process, windows_job=windows_job, force=True)
            windows_job = None
            _close_process_streams(process)
            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)
            raise subprocess.TimeoutExpired(
                command,
                timeout,
                output="".join(stdout_chunks),
                stderr="".join(stderr_chunks),
            )
        time.sleep(min(0.1, max(0.01, deadline - time.monotonic())))

    _terminate_process_tree(process, windows_job=windows_job, force=True)
    windows_job = None
    _close_process_streams(process)
    stdout_thread.join(timeout=1)
    stderr_thread.join(timeout=1)
    return subprocess.CompletedProcess(
        command,
        process.returncode,
        "".join(stdout_chunks),
        "".join(stderr_chunks),
    )


def _close_process_streams(process: subprocess.Popen[str]) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is None:
            continue
        try:
            stream.close()
        except OSError:
            pass


def _terminate_process_tree(process: subprocess.Popen[str], *, windows_job: int | None, force: bool = False) -> None:
    if os.name == "nt":
        if windows_job is not None:
            # Closing a kill-on-close job is the only reliable way to remove
            # descendants that inherited stdout/stderr after the root process
            # already exited.
            _close_windows_handle(windows_job)
        elif process.poll() is None:
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
        if process.poll() is not None:
            return
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        return
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            if process.poll() is None:
                process.terminate()
    if process.poll() is None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    elif not force:
        return

    if not force and process.poll() is not None:
        return
    if os.name == "nt":
        if process.poll() is None:
            process.kill()
    else:
        time.sleep(0.2)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            if process.poll() is None:
                process.kill()
    try:
        process.wait(timeout=5)
    except (subprocess.TimeoutExpired, ChildProcessError):
        pass


def _create_windows_kill_job(process: subprocess.Popen[str]) -> int | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return None

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", ctypes.c_uint32),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", ctypes.c_uint32),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", ctypes.c_uint32),
            ("SchedulingClass", ctypes.c_uint32),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JobObjectExtendedLimitInformation = 9
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel32.SetInformationJobObject(
        job,
        JobObjectExtendedLimitInformation,
        ctypes.byref(info),
        ctypes.sizeof(info),
    ):
        _close_windows_handle(job)
        return None
    if not kernel32.AssignProcessToJobObject(job, int(process._handle)):
        _close_windows_handle(job)
        return None
    return job


def _close_windows_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle(handle)


def enumerate_go_packages(
    repo_root: Path,
    go: str,
    runner: Runner = run_command,
    *,
    cache_dir: str | None = None,
    appdata_dir: str | None = None,
) -> list[str]:
    with contextlib.ExitStack() as stack:
        resolved_cache = cache_dir or stack.enter_context(tempfile.TemporaryDirectory(prefix="sentinel-aml-golist-cache."))
        resolved_appdata = appdata_dir or stack.enter_context(tempfile.TemporaryDirectory(prefix="sentinel-aml-golist-appdata."))
        completed = runner(
            [go, "list", "./..."],
            cwd=repo_root,
            env=release_env(os.environ, resolved_cache, resolved_appdata),
            timeout=60,
        )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout or "go list ./... failed").strip())
    packages = sorted_go_packages(completed.stdout)
    if not packages:
        raise RuntimeError("go list ./... returned no packages")
    return packages


def run_release_tests(
    repo_root: Path,
    *,
    go: str,
    package_timeout: int,
    runner: Runner = run_command,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    cache_dir: str | None = None,
    appdata_dir: str | None = None,
) -> int:
    try:
        packages = enumerate_go_packages(repo_root, go, runner, cache_dir=cache_dir, appdata_dir=appdata_dir)
    except RuntimeError as exc:
        print(f"go package enumeration failed: {exc}", file=stderr, flush=True)
        return 1

    with contextlib.ExitStack() as stack:
        resolved_cache = cache_dir or stack.enter_context(tempfile.TemporaryDirectory(prefix="sentinel-aml-gocache."))
        resolved_appdata = appdata_dir or stack.enter_context(tempfile.TemporaryDirectory(prefix="sentinel-aml-appdata."))
        print(f"go release shared GOCACHE: {resolved_cache}", file=stdout, flush=True)
        print(f"go release shared APPDATA: {resolved_appdata}", file=stdout, flush=True)
        env = release_env(os.environ, resolved_cache, resolved_appdata)
        for package in packages:
            print(f"go test package: {package}", file=stdout, flush=True)
            try:
                completed = runner(
                    [go, "test", "-timeout", f"{package_timeout}s", "-count=1", package],
                    cwd=repo_root,
                    env=env,
                    timeout=package_timeout + 30,
                )
            except subprocess.TimeoutExpired:
                print(f"go test timed out after {package_timeout + 30}s: {package}", file=stderr, flush=True)
                return 1
            if completed.stdout:
                print(completed.stdout, end="", file=stdout, flush=True)
            if completed.stderr:
                print(completed.stderr, end="", file=stderr, flush=True)
            if completed.returncode != 0:
                print(f"go test failed for package: {package}", file=stderr, flush=True)
                return completed.returncode
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default=os.environ.get("GO", "go"))
    parser.add_argument("--package-timeout", type=int, default=120)
    parser.add_argument("--cache-dir", default=os.environ.get("SENTINEL_AML_SHARED_GOCACHE"))
    parser.add_argument("--appdata-dir", default=os.environ.get("SENTINEL_AML_SHARED_APPDATA"))
    args = parser.parse_args(argv)
    if args.package_timeout <= 0:
        parser.error("--package-timeout must be positive")
    if bool(args.cache_dir) != bool(args.appdata_dir):
        parser.error("--cache-dir and --appdata-dir must be provided together")
    return run_release_tests(
        Path.cwd(),
        go=args.go,
        package_timeout=args.package_timeout,
        cache_dir=args.cache_dir,
        appdata_dir=args.appdata_dir,
    )


if __name__ == "__main__":
    raise SystemExit(main())
