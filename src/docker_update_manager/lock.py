from __future__ import annotations

import fcntl
import os
from pathlib import Path


class Lock:
    """Advisory exclusive lock opened without following symbolic links."""

    def __init__(self, path, *, no_follow: bool = False):
        self.path, self.no_follow, self.fd = Path(path), no_follow, None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_CREAT | os.O_RDWR
        if self.no_follow:
            flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            self.fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            if self.no_follow and exc.errno in (getattr(os, "ELOOP", 40), 40):
                raise ValueError(f"refusing to lock symlinked path: {self.path}") from None
            raise
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            self.fd = None
            raise RuntimeError("another modifying upt process is running") from None
        return self

    def __exit__(self, *_):
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None
