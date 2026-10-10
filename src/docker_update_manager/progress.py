"""Reusable operation events and terminal/log renderers.

Core code reports semantic events here; it never emits cursor-control sequences.
Future API/web adapters can subscribe to ``Reporter.events`` or ``on_event``.
"""
from __future__ import annotations
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime
import sys, time
from typing import Any, Callable, Iterator, TextIO

try:
    from rich.console import Console
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
except ImportError:  # pragma: no cover - packaging installs Rich; fallback stays usable
    Console = Progress = None

# Real numbered stages per Compose workflow. Core executes 1-7 of Apply; the last
# stage is the durable result record, emitted by the adapter/publication that
# owns that commit and only on success. Post-commit refresh work is never a
# numbered stage.
RECONCILE_STAGE_TOTAL = 8
DISCARD_STAGE_TOTAL = 5
# Ordinary and digest-pin image updates both have 8 real stages, ending in the durable "Record update".
UPDATE_STAGE_TOTAL = 8
UPDATE_RECORD_LABEL = "Record update"
# Compose trust bootstrap: 1-7 run in core; 8 is committed by the trust publication itself.
BOOTSTRAP_STAGE_TOTAL = 8

@dataclass(frozen=True)
class Event:
    kind: str
    operation: str
    message: str
    service: str | None = None
    current: int | None = None
    total: int | None = None
    status: str | None = None
    elapsed: float | None = None
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().astimezone().isoformat(timespec="seconds"))

    def as_dict(self): return asdict(self)

class Reporter:
    """Render events dynamically on a TTY or as timestamped append-only lines."""
    def __init__(self, *, enabled: bool = True, force: bool | None = None,
                 stream: TextIO | None = None, on_event: Callable[[Event], None] | None = None):
        self.enabled = enabled
        self.stream = stream or sys.stdout
        self.tty = bool(self.stream.isatty()) if force is None else force
        self.on_event = on_event
        self.events: list[Event] = []
        self.operation = "operation"
        self.started = time.monotonic()
        self._progress = None; self._overall_id = None; self._status = None
        self.console = Console(file=self.stream, force_terminal=self.tty, highlight=False) if Console else None

    def emit(self, kind: str, message: str, *, service=None, current=None, total=None, status=None, **data):
        ev=Event(kind,self.operation,message,service,current,total,status,time.monotonic()-self.started,data)
        self.events.append(ev)
        if self.on_event: self.on_event(ev)
        if not self.enabled: return ev
        if self.tty:
            if kind == "operation_started" and self.console: self.console.print(f"\n[bold]{message}[/bold]")
            elif kind in {"task_completed","task_warning","task_failed","task_pending","task_running","task_info","operation_completed","task_rolled_back"} and self.console:
                style="red" if kind=="task_failed" else ("yellow" if kind=="task_warning" else ("dim" if kind in {"task_pending","task_info"} else "green"))
                prefix=f"{service}: " if service else ""
                self.console.print(f"[{style}]{prefix}{message}[/{style}]")
        else:
            clock=datetime.now().strftime("%H:%M:%S")
            pos=f" [{current}/{total}]" if current is not None and total else ""
            svc=f" {service}:" if service else ""
            print(f"[{clock}]{pos}{svc} {message}",file=self.stream,flush=True)
        return ev

    def start(self, operation: str, message: str, *, total: int | None = None):
        self.operation=operation; self.started=time.monotonic(); self.emit("operation_started",message,total=total)
        if self.enabled and self.tty and total and Progress:
            self._progress=Progress(SpinnerColumn(),TextColumn("[bold]{task.description}"),BarColumn(bar_width=32),
                TextColumn("{task.completed:.0f}/{task.total:.0f}"),TextColumn("{task.percentage:>3.0f}%"),TimeElapsedColumn(),console=self.console,transient=False)
            self._progress.start(); self._overall_id=self._progress.add_task(message,total=total)

    def advance(self, current: int, total: int, service: str, status: str):
        self.emit("task_completed",status,service=service,current=current,total=total,status=status)
        if self._progress:
            self._progress.update(self._overall_id,completed=current,description=f"Current: {service} — {status}")

    @contextmanager
    def task(self, message: str, *, service: str | None = None, stage: str | None = None) -> Iterator[None]:
        label=f"{service}: {message}" if service else message
        self.emit("task_started",message,service=service,status=stage or "running")
        status_obj=None
        if self.enabled and self.tty and self.console and not self._progress:
            status_obj=self.console.status(f"[bold cyan]●[/] {label}",spinner="dots",spinner_style="cyan")
            status_obj.start()
        elif self._progress:
            self._progress.update(self._overall_id,description=label)
        begun=time.monotonic()
        try:
            yield
        except BaseException as exc:
            if status_obj: status_obj.stop()
            self.emit("task_failed",f"✗ {message}: {exc}",service=service,status="failed")
            raise
        else:
            if status_obj: status_obj.stop()
            self.emit("task_completed",f"✓ {message} ({_duration(time.monotonic()-begun)})",service=service,status="completed")

    def stage(self, number: int, total: int, message: str, state="completed", service=None):
        icons={"completed":"✓","running":"●","pending":"○","warning":"!","failed":"✗","rolled_back":"↩"}
        self.emit("task_"+state,f"[{number}/{total}] {message} {icons.get(state,'')}",service=service,status=state,step=number,steps=total,label=message)

    def note(self,message,service=None):
        """Explanatory, unnumbered transition marker: never a step, never incomplete."""
        self.emit("task_info",message,service=service,status="info")

    def warning(self,message,service=None): self.emit("task_warning",f"! {message}",service=service,status="warning")
    def progress(self,message,service=None,**data):
        self.emit("task_progress",message,service=service,status="running",**data)
        if self._progress: self._progress.update(self._overall_id,description=f"{service + ': ' if service else ''}{message}")
    def finish(self,message: str, **data):
        if self._progress: self._progress.stop(); self._progress=None
        elapsed=time.monotonic()-self.started
        self.emit("operation_completed",f"{message} in {_duration(elapsed)}",elapsed=elapsed,**data)
        return elapsed
    def prompt(self, message: str, input_fn=input) -> str:
        """Pause live rendering so confirmations remain readable and editable."""
        active=bool(self._progress)
        if active: self._progress.stop()
        try: return input_fn(message)
        finally:
            if active: self._progress.start()
    def close(self):
        if self._status: self._status.stop()
        if self._progress: self._progress.stop(); self._progress=None

def _duration(seconds: float) -> str:
    if seconds < 60: return f"{seconds:.1f}s"
    minutes,sec=divmod(int(seconds),60); return f"{minutes}m {sec:02d}s"

NULL_REPORTER=Reporter(enabled=False)
