#!/usr/bin/env python3
"""Decompress zstd through its CLI while enforcing a hard output limit."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--maximum", type=int, default=5 << 30)
    args = parser.parse_args()
    if args.maximum <= 0 or not args.source.is_file() or args.source.is_symlink():
        raise SystemExit("bounded zstd: invalid input")

    process = subprocess.Popen(
        ["zstd", "--quiet", "--decompress", "--stdout", str(args.source)],
        stdout=subprocess.PIPE,
    )
    written = 0
    try:
        assert process.stdout is not None
        with args.destination.open("xb") as destination:
            while chunk := process.stdout.read(1024 * 1024):
                written += len(chunk)
                if written > args.maximum:
                    process.kill()
                    raise SystemExit("bounded zstd: decompressed stream exceeds limit")
                destination.write(chunk)
        result = process.wait()
        if result != 0:
            raise SystemExit(f"bounded zstd: decoder exited with status {result}")
    except BaseException:
        process.kill()
        process.wait()
        args.destination.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    main()

