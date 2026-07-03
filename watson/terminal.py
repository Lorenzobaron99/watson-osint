"""Terminal Manager — rich command execution with background processes.

Upgrade from single-shot subprocess to:
- Background process execution with async tracking
- Output streaming and log retrieval
- Process lifecycle (poll, wait, kill, stdin write)
- PTY mode for interactive commands
- Watch patterns for output monitoring
- Concurrent process pool with size limits

Inspired by Hermes Agent's terminal tool capabilities.
"""

from __future__ import annotations

import logging
import os
import pty
import select
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("watson.terminal")


@dataclass
class Process:
    """A managed process — foreground or background."""
    session_id: str
    command: str
    workdir: str
    process: subprocess.Popen | None = None
    status: str = "pending"  # pending, running, completed, killed, error
    exit_code: int | None = None
    output: list[str] = field(default_factory=list)
    error: str = ""
    started_at: float = 0.0
    finished_at: float | None = None
    pty_fd: int | None = None  # PTY file descriptor (if PTY mode)
    background: bool = False
    timeout: float = 300.0
    max_output_lines: int = 5000
    _output_lock: threading.Lock = field(default_factory=threading.Lock)
    _watch_patterns: list[str] = field(default_factory=list)
    _watch_callbacks: dict[str, callable] = field(default_factory=dict)

    @property
    def output_text(self) -> str:
        with self._output_lock:
            return "\n".join(self.output[-1000:])  # last 1000 lines

    @property
    def duration(self) -> float:
        if self.started_at == 0:
            return 0
        end = self.finished_at or time.time()
        return round(end - self.started_at, 2)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "command": self.command[:200],
            "workdir": self.workdir,
            "status": self.status,
            "exit_code": self.exit_code,
            "output_length": len(self.output),
            "error": self.error[:500] if self.error else None,
            "duration": self.duration,
            "background": self.background,
        }


class TerminalManager:
    """Manages concurrent command execution with background support.

    Usage:
        tm = TerminalManager(max_processes=10)

        # Foreground
        result = tm.run("ls -la", workdir="/tmp")
        print(result.output_text)

        # Background
        session_id = tm.run_background("python server.py")
        # ... later ...
        proc = tm.poll(session_id)
        if proc.status == "completed":
            print(proc.output_text)
    """

    def __init__(self, max_processes: int = 20):
        self._processes: dict[str, Process] = {}
        self._max_processes = max_processes
        self._lock = threading.Lock()

    # ── Execution ──────────────────────────────────────────────────

    def run(
        self,
        command: str,
        workdir: str | None = None,
        timeout: float = 300.0,
        pty_mode: bool = False,
        env: dict[str, str] | None = None,
    ) -> Process:
        """Execute a command and wait for completion (foreground).

        Args:
            command: Shell command to execute
            workdir: Working directory (defaults to cwd)
            timeout: Max execution time in seconds
            pty_mode: Use pseudo-terminal (for interactive commands)
            env: Additional environment variables

        Returns:
            Process object with output and exit code
        """
        proc = self._create_process(
            command, workdir=workdir or os.getcwd(),
            background=False, timeout=timeout, pty_mode=pty_mode,
        )
        self._run_sync(proc, env=env)
        return proc

    def run_background(
        self,
        command: str,
        workdir: str | None = None,
        timeout: float = 1800.0,
        pty_mode: bool = False,
        watch_patterns: list[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> str:
        """Execute a command in the background.

        Returns:
            session_id for later polling/control
        """
        proc = self._create_process(
            command, workdir=workdir or os.getcwd(),
            background=True, timeout=timeout, pty_mode=pty_mode,
        )
        if watch_patterns:
            proc._watch_patterns = watch_patterns

        thread = threading.Thread(
            target=self._run_thread, args=(proc, env), daemon=True
        )
        thread.start()

        return proc.session_id

    def _create_process(
        self,
        command: str,
        workdir: str,
        background: bool,
        timeout: float,
        pty_mode: bool,
    ) -> Process:
        """Create a Process object and register it."""
        session_id = f"term-{uuid.uuid4().hex[:8]}"

        with self._lock:
            # Clean up old completed processes if over limit
            if len(self._processes) >= self._max_processes:
                self._cleanup_old()

            proc = Process(
                session_id=session_id,
                command=command,
                workdir=workdir,
                background=background,
                timeout=timeout,
                started_at=time.time(),
            )
            self._processes[session_id] = proc

        return proc

    def _run_sync(self, proc: Process, env: dict[str, str] | None = None):
        """Execute a process synchronously."""
        try:
            proc.status = "running"

            if proc.pty_fd is not None:
                # PTY mode
                self._run_pty(proc, env)
            else:
                # Standard subprocess
                merged_env = os.environ.copy()
                if env:
                    merged_env.update(env)

                proc.process = subprocess.Popen(
                    proc.command,
                    shell=True,
                    cwd=proc.workdir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=merged_env,
                )

                try:
                    stdout, stderr = proc.process.communicate(timeout=proc.timeout)
                    proc.exit_code = proc.process.returncode

                    if stdout:
                        proc.output = stdout.split("\n")[: proc.max_output_lines]
                    if stderr:
                        proc.error = stderr[:2000]

                    proc.status = "completed" if proc.exit_code == 0 else "error"
                except subprocess.TimeoutExpired:
                    proc.process.kill()
                    proc.process.communicate()
                    proc.exit_code = -1
                    proc.status = "killed"
                    proc.error = f"Timed out after {proc.timeout}s"

        except Exception as e:
            proc.status = "error"
            proc.error = str(e)[:1000]
        finally:
            proc.finished_at = time.time()

    def _run_thread(self, proc: Process, env: dict[str, str] | None = None):
        """Run process in background thread."""
        self._run_sync(proc, env)

    def _run_pty(self, proc: Process, env: dict[str, str] | None = None):
        """Execute command in a pseudo-terminal."""
        master_fd, slave_fd = pty.openpty()

        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)

        proc.process = subprocess.Popen(
            proc.command,
            shell=True,
            cwd=proc.workdir,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            env=merged_env,
            preexec_fn=os.setsid,
        )

        os.close(slave_fd)
        proc.pty_fd = master_fd

        try:
            deadline = time.time() + proc.timeout
            buffer = b""

            while time.time() < deadline:
                r, _, _ = select.select([master_fd], [], [], 1.0)
                if r:
                    try:
                        data = os.read(master_fd, 4096)
                        if not data:
                            break
                        buffer += data
                        # Split and store lines
                        while b"\n" in buffer:
                            line, buffer = buffer.split(b"\n", 1)
                            line_str = line.decode("utf-8", errors="replace")
                            with proc._output_lock:
                                proc.output.append(line_str)
                                if len(proc.output) > proc.max_output_lines:
                                    proc.output = proc.output[-proc.max_output_lines:]
                    except OSError:
                        break

                # Check if process exited
                if proc.process.poll() is not None:
                    break

            # Drain remaining output
            try:
                os.set_blocking(master_fd, False)
                remaining = os.read(master_fd, 65536)
                if remaining:
                    for line in remaining.decode("utf-8", errors="replace").split("\n"):
                        if line.strip():
                            with proc._output_lock:
                                proc.output.append(line)
            except OSError:
                pass

            proc.exit_code = proc.process.returncode
            if proc.exit_code is None:
                proc.process.kill()
                proc.process.wait()
                proc.exit_code = proc.process.returncode or -1
                proc.status = "killed"
                proc.error = f"PTY timed out after {proc.timeout}s"

            proc.status = "completed" if proc.exit_code == 0 else "error"

        except Exception as e:
            proc.status = "error"
            proc.error = str(e)[:1000]
        finally:
            os.close(master_fd)
            proc.finished_at = time.time()

    # ── Process Control ────────────────────────────────────────────

    def poll(self, session_id: str) -> Process | None:
        """Get process status and any new output."""
        proc = self._processes.get(session_id)
        return proc

    def wait(self, session_id: str, timeout: float = 60.0) -> Process | None:
        """Block until process completes or timeout."""
        proc = self._processes.get(session_id)
        if not proc:
            return None

        deadline = time.time() + timeout
        while time.time() < deadline:
            if proc.status in ("completed", "killed", "error"):
                return proc
            time.sleep(0.5)

        return proc  # timed out — return current state

    def kill(self, session_id: str) -> bool:
        """Kill a running process."""
        proc = self._processes.get(session_id)
        if not proc or not proc.process:
            return False

        try:
            if proc.pty_fd is not None:
                os.killpg(os.getpgid(proc.process.pid), signal.SIGTERM)
            else:
                proc.process.kill()
            proc.status = "killed"
            proc.exit_code = -9
            proc.finished_at = time.time()
            return True
        except Exception:
            return False

    def write(self, session_id: str, data: str) -> bool:
        """Send data to process stdin."""
        proc = self._processes.get(session_id)
        if not proc or not proc.process or proc.status != "running":
            return False

        try:
            if proc.pty_fd is not None:
                os.write(proc.pty_fd, data.encode())
            else:
                proc.process.stdin.write(data)
                proc.process.stdin.flush()
            return True
        except Exception:
            return False

    def submit(self, session_id: str, data: str) -> bool:
        """Send data + newline to process stdin (answer a prompt)."""
        return self.write(session_id, data + "\n")

    def close_stdin(self, session_id: str) -> bool:
        """Close stdin (send EOF)."""
        proc = self._processes.get(session_id)
        if not proc or not proc.process:
            return False

        try:
            if proc.pty_fd is not None:
                # PTY — can't really close stdin, but sending EOF char
                os.write(proc.pty_fd, b"\x04")
            else:
                proc.process.stdin.close()
            return True
        except Exception:
            return False

    def list_all(self) -> list[dict]:
        """List all processes."""
        with self._lock:
            return [p.to_dict() for p in self._processes.values()]

    def _cleanup_old(self):
        """Remove old completed processes to free space."""
        old = [
            sid for sid, p in self._processes.items()
            if p.status in ("completed", "killed", "error")
            and p.finished_at
            and time.time() - p.finished_at > 300  # 5 min
        ]
        for sid in old:
            del self._processes[sid]


# Singleton
terminal = TerminalManager()
