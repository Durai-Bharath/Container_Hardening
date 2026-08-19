from __future__ import annotations

import sys
from typing import Sequence

try:
    from .analyzer import main as analyzer_main
except ImportError:
    from analyzer import main as analyzer_main


def main(argv: Sequence[str] | None = None) -> int:
    return analyzer_main(list(argv) if argv is not None else None)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
