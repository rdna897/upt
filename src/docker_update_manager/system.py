from __future__ import annotations
import json, os, subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

class CommandError(RuntimeError):
    def __init__(self, args: Sequence[str], message: str, code: int = 1):
        self.args_run, self.code = list(args), code
        super().__init__(message.strip() or f"command failed ({code})")

def run(args: Sequence[str], *, cwd: str | None = None, timeout: int = 120, check: bool = True) -> str:
    try:
        p = subprocess.run(list(args), cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, shell=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise CommandError(args, str(e)) from None
    if check and p.returncode:
        # Docker can echo credential-helper details; return only a bounded final error line.
        lines = [x for x in p.stderr.splitlines() if x.strip()]
        raise CommandError(args, (lines[-1] if lines else "command failed")[:500], p.returncode)
    return p.stdout

@dataclass(frozen=True)
class ComposeInvocationOutcome:
    """Typed subprocess outcome; never derived from text or CommandError.code.

    completed: the client was normally reaped with a non-negative return code.
    timeout/signal/launch_error/unknown: completion is unproved and work may
    remain in flight on the Docker side.
    """
    category: str
    returncode: int | None
    phase: str

    @property
    def completed_zero(self) -> bool:
        return self.category == "completed" and self.returncode == 0

    def record(self) -> dict:
        return {"phase": self.phase, "category": self.category, "code": self.returncode}


INVOCATION_CATEGORIES = frozenset({"completed", "timeout", "signal", "launch_error", "unknown"})


def invoke(args: Sequence[str], *, phase: str, cwd: str | None = None, timeout: int = 600) -> ComposeInvocationOutcome:
    """Run once and classify the outcome. Output is discarded: it may hold secrets.

    Interpreter-level interruption (KeyboardInterrupt, SystemExit) propagates;
    the caller's durable marker then makes the outcome manual.
    """
    try:
        p = subprocess.run(list(args), cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=timeout, shell=False)
    except subprocess.TimeoutExpired:
        return ComposeInvocationOutcome("timeout", None, phase)
    except OSError:
        return ComposeInvocationOutcome("launch_error", None, phase)
    except Exception:
        return ComposeInvocationOutcome("unknown", None, phase)
    code = p.returncode
    if type(code) is not int:
        return ComposeInvocationOutcome("unknown", None, phase)
    if code < 0:
        return ComposeInvocationOutcome("signal", code, phase)
    return ComposeInvocationOutcome("completed", code, phase)

def json_run(args: Sequence[str], **kw):
    return json.loads(run(args, **kw))

def run_compose_progress(args: Sequence[str], reporter, service: str, *, cwd=None, timeout=1800) -> str:
    """Stream Docker Compose's real JSON progress events; never infer totals."""
    cmd=list(args)
    if cmd[:2] == ["docker","compose"] and "--progress" not in cmd:
        cmd[2:2]=["--progress","json","--ansi","never"]
    try:
        p=subprocess.Popen(cmd,cwd=cwd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                           shell=False,bufsize=1)
    except OSError as e: raise CommandError(cmd,str(e)) from None
    lines=[]; started=__import__("time").monotonic()
    try:
        assert p.stdout is not None
        for raw in p.stdout:
            line=raw.strip()
            if not line: continue
            lines.append(line)
            try:
                event=json.loads(line); layer=str(event.get("id") or event.get("name") or "image")[:24]
                status=str(event.get("status") or event.get("text") or event.get("message") or "working")
                current=event.get("current"); total=event.get("total")
                if isinstance(current,(int,float)) and isinstance(total,(int,float)) and total>0:
                    pct=current/total*100
                    reporter.progress(f"{layer} — {status}: {pct:.0f}% ({human_size(int(current))}/{human_size(int(total))})",service=service,current=current,total=total,layer=layer)
                else: reporter.progress(f"{layer} — {status}",service=service,layer=layer)
            except (json.JSONDecodeError,TypeError,ValueError): reporter.progress(line[:300],service=service)
            if __import__("time").monotonic()-started > timeout:
                p.terminate(); raise CommandError(cmd,f"command timed out after {timeout}s")
        code=p.wait()
    except BaseException:
        if p.poll() is None: p.terminate()
        raise
    if code:
        raise CommandError(cmd,(lines[-1] if lines else "Docker pull failed")[:500],code)
    return "\n".join(lines)

def human_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    x = float(n)
    for unit in units:
        if x < 1024 or unit == units[-1]: return f"{x:.1f} {unit}"
        x /= 1024
