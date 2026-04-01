#!/usr/bin/env python3
import sys
from pathlib import Path


def run() -> int:
    here = Path(__file__).resolve().parent
    parent = str(here.parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    from minimal_h298a.__main__ import main

    return main()


if __name__ == "__main__":
    raise SystemExit(run())
