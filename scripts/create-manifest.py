#!/usr/bin/env python3
"""Validate a release archive and write its strict external manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import stat
import tarfile
from pathlib import Path


VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
    r"(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
PRODUCTS = {
    "remoteterminal": {
        "bin": ("directory", 0o755),
        "bin/remoteterminal": ("file", 0o755),
        "bin/ttyd": ("file", 0o755),
        "licenses": ("directory", 0o755),
        "licenses/ttyd-LICENSE": ("file", 0o644),
        "metadata": ("directory", 0o755),
        "metadata/build-inputs.json": ("file", 0o644),
        "manifest.json": ("file", 0o644),
    },
    "websetupmanager": {
        "bin": ("directory", 0o755),
        "bin/websetupmanager": ("file", 0o755),
        "metadata": ("directory", 0o755),
        "metadata/version.json": ("file", 0o644),
        "manifest.json": ("file", 0o644),
    },
}
MAX_ENTRIES = 20_000
MAX_COMPRESSED_BYTES = 2 << 30
MAX_UNPACKED_BYTES = 4 << 30


def fail(message: str) -> None:
    raise SystemExit(f"release manifest: {message}")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def safe_name(name: str) -> str:
    if (
        not name
        or len(name) > 4096
        or name.startswith("/")
        or "\\" in name
        or "\x00" in name
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in name)
    ):
        fail(f"unsafe archive path {name!r}")
    trimmed = name[:-1] if name.endswith("/") else name
    normalized = posixpath.normpath(trimmed)
    if normalized in (".", "..") or normalized.startswith("../") or normalized != trimmed:
        fail(f"unsafe archive path {name!r}")
    return normalized


def validate_tar(tar_path: Path, product: str) -> int:
    expected = PRODUCTS[product]
    seen: set[str] = set()
    unpacked = 0
    entry_count = 0
    with tarfile.open(tar_path, mode="r:") as archive:
        for member in archive:
            entry_count += 1
            if entry_count > MAX_ENTRIES:
                fail("archive has too many entries")
            name = safe_name(member.name)
            if name in seen:
                fail(f"archive contains duplicate path {name!r}")
            seen.add(name)
            if name not in expected:
                fail(f"archive contains unexpected path {name!r}")
            expected_type, expected_mode = expected[name]
            actual_type = "directory" if member.isdir() else "file" if member.isfile() else "unsafe"
            if actual_type != expected_type:
                fail(f"archive path has an unsafe type: {name!r}")
            if member.uid != 0 or member.gid != 0 or stat.S_IMODE(member.mode) != expected_mode:
                fail(f"archive path has unsafe ownership or mode: {name!r}")
            if member.isdir():
                if member.size != 0:
                    fail(f"archive directory has a non-zero size: {name!r}")
                continue
            if member.size < 0 or unpacked + member.size > MAX_UNPACKED_BYTES:
                fail("archive expands beyond the supported size")
            unpacked += member.size
    if entry_count == 0:
        fail("archive is empty")
    missing = set(expected) - seen
    if missing:
        fail(f"archive is missing required paths: {sorted(missing)!r}")
    if unpacked <= 0:
        fail("archive contains no regular-file data")
    return unpacked


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--product", choices=sorted(PRODUCTS), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--asset", type=Path, required=True)
    parser.add_argument("--tar", type=Path, required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if not VERSION.fullmatch(args.version):
        fail("version is not semantic version syntax")
    if not args.asset.is_file() or args.asset.is_symlink():
        fail("asset must be a regular file")
    expected_name = f"{args.product}-{args.version}-debian13-amd64.tar.zst"
    if args.asset.name != expected_name:
        fail(f"asset name must be {expected_name!r}")
    size = args.asset.stat().st_size
    if size <= 0 or size > MAX_COMPRESSED_BYTES:
        fail("compressed asset size is outside the supported range")
    unpacked = validate_tar(args.tar, args.product)
    expected_url = (
        "https://github.com/ymiroshnychenko668/linuxcncsetup-releases/releases/"
        f"download/{args.product}-v{args.version}/{expected_name}"
    )
    if args.url != expected_url:
        fail("asset URL does not match the immutable release location")

    manifest = {
        "schema": 1,
        "product": args.product,
        "version": args.version,
        "platform": {
            "os": "linux",
            "architecture": "amd64",
            "distribution": "debian",
            "distribution_version": "13",
        },
        "asset": {
            "name": expected_name,
            "url": expected_url,
            "size": size,
            "sha256": digest(args.asset),
            "unpacked_size": unpacked,
            "format": "tar.zst",
        },
    }
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    main()
