#!/usr/bin/env python3
import re
import threading
import time
from pathlib import Path


class RequestArchive:
    def __init__(self, root: Path):
        self.root = root / "sessions"
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.counter = 0

    def save(self, serial: str, kind: str, body: str) -> Path:
        safe_serial = re.sub(r"[^A-Za-z0-9_.-]", "_", serial or "unknown")
        with self.lock:
            self.counter += 1
            idx = self.counter
        sess = self.root / safe_serial
        sess.mkdir(parents=True, exist_ok=True)
        file_path = sess / f"{idx:04d}_{int(time.time())}_{kind}.xml"
        file_path.write_text(body, encoding="utf-8", errors="ignore")
        return file_path

    def save_bytes(self, serial: str, kind: str, body: bytes) -> Path:
        return self.save(serial, kind, body.decode("utf-8", errors="ignore"))
