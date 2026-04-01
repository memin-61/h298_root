#!/usr/bin/env python3
import threading
import time
from pathlib import Path


class FileLogger:
    def __init__(self, log_file: Path):
        self.log_file = log_file
        self.lock = threading.Lock()

    def log(self, msg: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        with self.lock:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            with self.log_file.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
