"""CLI: rebuild the registry manifest (data/index.json) from data/devices/*.json."""

import sys
from pathlib import Path

from glinet_profiler.registry import rebuild

_DATA = Path(__file__).resolve().parent.parent / "src" / "glinet_profiler" / "data"


def main() -> int:
    """Rebuild the bundled registry manifest."""
    count = rebuild(_DATA)
    print(f"Wrote {count} device(s) to {_DATA / 'index.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
