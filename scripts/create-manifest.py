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
        "bin/remoteterminal",
        "bin/ttyd",
        "manifest.json",
        "metadata/build-inputs.json",
    },
    "websetupmanager": {"bin/websetupmanager", "manifest.json"},
}
ALLOWED_FILE_MODES = {0o444, 0o555, 0o644, 0o755}
ALLOWED_DIRECTORY_MODES = {0o555, 0o755}
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
        or "\r" in name
        or "\n" in name
    ):
        fail(f"unsafe archive path {name!r}")
    trimmed = name[:-1] if name.endswith("/") else name
    normalized = posixpath.normpath(trimmed)
    if normalized in (".", "..") or normalized.startswith("../") or normalized != trimmed:
        fail(f"unsafe archive path {name!r}")
    return normalized


def validate_tar(tar_path: Path, product: str) -> int:
    seen: set[str] = set()
    regular: set[str] = set()
    unpacked = 0
    with tarfile.open(tar_path, mode="r:") as archive:
        members = archive.getmembers()
        if not members or len(members) > MAX_ENTRIES:
            fail("archive has an invalid entry count")
        for member in members:
            name = safe_name(member.name)
            if name in seen:
                fail(f"archive contains duplicate path {name!r}")
            seen.add(name)
            mode = stat.S_IMODE(member.mode)
            if member.isdir():
                if member.size != 0 or mode not in ALLOWED_DIRECTORY_MODES:
                    fail(f"archive directory has unsafe metadata: {name!r}")
                continue
            if not member.isfile():
                fail(f"archive contains unsupported entry type: {name!r}")
            if mode not in ALLOWED_FILE_MODES:
                fail(f"archive file has unsafe mode: {name!r}")
            if member.size < 0 or unpacked + member.size > MAX_UNPACKED_BYTES:
                fail("archive expands beyond the supported size")
            unpacked += member.size
            regular.add(name)
    missing = PRODUCTS[product] - regular
    if missing:
        fail(f"archive is missing required files: {sorted(missing)!r}")
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

