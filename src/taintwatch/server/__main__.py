"""Start the API: ``python -m taintwatch.server [--db FILE] [--host H] [--port P]``."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

import uvicorn

from taintwatch.server.app import create_app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m taintwatch.server", description="Serve the Taintwatch API."
    )
    parser.add_argument("--db", default="taintwatch.db", help="SQLite file for stored runs")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    uvicorn.run(create_app(args.db), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
