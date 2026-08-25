#!/usr/bin/env python3
"""Validate a component payload and write its strict external manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, NamedTuple
from urllib.parse import urlparse


SEMVER_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
VERSION = re.compile(
    rf"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    rf"(?:-{SEMVER_IDENTIFIER}(?:\.{SEMVER_IDENTIFIER})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
RFC3339_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)
SAFE_MIGRATION_NAME = re.compile(r"^[a-z0-9_]+$")


class EntryContract(NamedTuple):
    kind: str
    mode: int
    maximum: int = 0


class FileRecord(NamedTuple):
    size: int
    sha256: str
    contents: bytes | None
    prefix: bytes


PRODUCTS = {
    "remoteterminal": {
        "bin": EntryContract("directory", 0o755),
        "bin/remoteterminal": EntryContract("file", 0o755, 100 << 20),
        "bin/ttyd": EntryContract("file", 0o755, 100 << 20),
        "licenses": EntryContract("directory", 0o755),
        "licenses/ttyd-LICENSE": EntryContract("file", 0o644, 1 << 20),
        "metadata": EntryContract("directory", 0o755),
        "metadata/build-inputs.json": EntryContract("file", 0o644, 1 << 20),
        "manifest.json": EntryContract("file", 0o644, 128 << 10),
    },
    "websetupmanager": {
        "bin": EntryContract("directory", 0o755),
        "bin/websetupmanager": EntryContract("file", 0o755, 256 << 20),
        "metadata": EntryContract("directory", 0o755),
        "metadata/version.json": EntryContract("file", 0o644, 1 << 20),
        "manifest.json": EntryContract("file", 0o644, 1 << 20),
    },
}
PRODUCT_UNPACKED_MAXIMUM = {
    "remoteterminal": 100 << 20,
    "websetupmanager": 258 << 20,
}
JSON_PATHS = {
    "remoteterminal": {"metadata/build-inputs.json", "manifest.json"},
    "websetupmanager": {"metadata/version.json", "manifest.json"},
}
MAX_COMPRESSED_BYTES = 2 << 30
MAX_JSON_DEPTH = 32
TAR_BLOCK_SIZE = 512
TAR_RECORD_SIZE = 10_240
TAR_OVERHEAD_MAXIMUM = 1 << 20
ELF_INSPECTION_MAXIMUM = 64 << 10


def fail(message: str) -> None:
    raise SystemExit(f"release manifest: {message}")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def strict_json(raw: bytes, label: str) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate field {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"invalid number {value}")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        fail(f"{label} is not strict JSON: {error}")

    def check_depth(item: object, depth: int) -> None:
        if depth > MAX_JSON_DEPTH:
            fail(f"{label} is nested too deeply")
        if type(item) is dict:
            for nested in item.values():
                check_depth(nested, depth + 1)
        elif type(item) is list:
            for nested in item:
                check_depth(nested, depth + 1)

    check_depth(value, 0)
    return value


def require_object(value: object, fields: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict:
        fail(f"{label} must be an object")
    actual = set(value)
    if actual != fields:
        fail(
            f"{label} fields differ: missing={sorted(fields - actual)!r}, "
            f"extra={sorted(actual - fields)!r}"
        )
    return value


def require_string(value: object, label: str, maximum: int = 4096) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        fail(f"{label} must be a bounded non-empty string without control characters")
    return value


def require_integer(value: object, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        fail(f"{label} must be an integer greater than or equal to {minimum}")
    return value


def require_sha256(value: object, label: str) -> str:
    if type(value) is not str or not SHA256.fullmatch(value):
        fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def require_commit(value: object, label: str) -> str:
    if type(value) is not str or not GIT_COMMIT.fullmatch(value):
        fail(f"{label} must be a full lowercase Git SHA-1")
    return value


def require_semver(value: object, label: str) -> str:
    if type(value) is not str or not VERSION.fullmatch(value):
        fail(f"{label} must use strict semantic version syntax without leading zeroes")
    return value


def require_build_date(value: object, label: str) -> str:
    if type(value) is not str or not RFC3339_UTC.fullmatch(value):
        fail(f"{label} must be an RFC3339 UTC timestamp")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail(f"{label} must be an RFC3339 UTC timestamp")
    return value


def build_date_for_epoch(epoch: int) -> str:
    try:
        return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        fail("source date epoch is outside the supported timestamp range")


def require_https_url(value: object, label: str) -> str:
    raw = require_string(value, label)
    parsed = urlparse(raw)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.fragment
    ):
        fail(f"{label} must be an absolute HTTPS URL without credentials or fragment")
    return raw


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


def read_file_record(source: BinaryIO, size: int, capture: bool) -> FileRecord:
    value = hashlib.sha256()
    captured = bytearray() if capture else None
    prefix = bytearray()
    consumed = 0
    while consumed < size:
        chunk = source.read(min(1024 * 1024, size - consumed))
        if not chunk:
            fail("archive file is truncated")
        consumed += len(chunk)
        value.update(chunk)
        if len(prefix) < ELF_INSPECTION_MAXIMUM:
            prefix.extend(chunk[: ELF_INSPECTION_MAXIMUM - len(prefix)])
        if captured is not None:
            captured.extend(chunk)
    return FileRecord(
        size,
        value.hexdigest(),
        bytes(captured) if captured is not None else None,
        bytes(prefix),
    )


def parse_tar_octal(raw: bytes, label: str) -> int:
    if raw and raw[0] & 0x80:
        fail(f"{label} uses a non-canonical base-256 integer")
    value = raw.strip(b" \0")
    if not value:
        return 0
    if any(character < ord("0") or character > ord("7") for character in value):
        fail(f"{label} is not a canonical octal integer")
    return int(value, 8)


def validate_tar_checksum(header: bytes, label: str) -> None:
    stored = parse_tar_octal(header[148:156], f"{label} checksum")
    actual = sum(header[:148]) + 8 * ord(" ") + sum(header[156:])
    if stored != actual:
        fail(f"{label} checksum is invalid")


def canonical_tar_size(minimum: int) -> int:
    return ((minimum + TAR_RECORD_SIZE - 1) // TAR_RECORD_SIZE) * TAR_RECORD_SIZE


def scan_canonical_tar(
    tar_path: Path,
    product: str,
    source_date_epoch: int | None,
) -> tuple[dict[str, FileRecord], int]:
    expected = PRODUCTS[product]
    expected_names = list(expected)
    total_maximum = PRODUCT_UNPACKED_MAXIMUM[product]
    try:
        if tar_path.is_symlink() or not tar_path.is_file():
            fail("tar archive must be a regular file")
        raw_size = tar_path.stat().st_size
    except OSError as error:
        fail(f"cannot inspect tar archive: {error}")
    if raw_size <= 0 or raw_size > total_maximum + TAR_OVERHEAD_MAXIMUM:
        fail("tar archive size is outside its product contract")

    records: dict[str, FileRecord] = {}
    unpacked = 0
    common_mtime: int | None = None
    try:
        with tar_path.open("rb") as source:
            for index, expected_name in enumerate(expected_names):
                header = source.read(TAR_BLOCK_SIZE)
                if len(header) != TAR_BLOCK_SIZE or header == bytes(TAR_BLOCK_SIZE):
                    fail("tar archive ends before its exact inventory")
                label = f"tar header {index}"
                canonical_numeric_fields = (
                    (header[100:108], rb"[0-7]{7}\0", "mode"),
                    (header[108:116], rb"[0-7]{7}\0", "uid"),
                    (header[116:124], rb"[0-7]{7}\0", "gid"),
                    (header[124:136], rb"[0-7]{11}\0", "size"),
                    (header[136:148], rb"[0-7]{11}\0", "mtime"),
                    (header[148:156], rb"[0-7]{6}\0 ", "checksum"),
                )
                for field, pattern, field_name in canonical_numeric_fields:
                    if re.fullmatch(pattern, field) is None:
                        fail(f"{label} {field_name} field is not canonical USTAR")
                validate_tar_checksum(header, label)
                if header[257:263] != b"ustar\0" or header[263:265] != b"00":
                    fail(f"{label} is not a canonical USTAR header")
                if (
                    any(header[157:257])
                    or any(header[265:345])
                    or any(header[345:500])
                    or any(header[500:512])
                ):
                    fail(f"{label} uses links, names, devices, or extended path fields")

                contract = expected[expected_name]
                expected_raw_name = (
                    expected_name + "/" if contract.kind == "directory" else expected_name
                ).encode("ascii")
                expected_name_field = expected_raw_name + bytes(
                    100 - len(expected_raw_name)
                )
                raw_name = header[:100].split(b"\0", 1)[0]
                if header[:100] != expected_name_field:
                    fail(
                        f"tar physical inventory differs at position {index}: "
                        f"{raw_name!r} != {expected_raw_name!r}"
                    )
                safe_name(raw_name.decode("ascii").removesuffix("/"))

                typeflag = header[156:157]
                size = parse_tar_octal(header[124:136], f"{label} size")
                mode = parse_tar_octal(header[100:108], f"{label} mode")
                uid = parse_tar_octal(header[108:116], f"{label} uid")
                gid = parse_tar_octal(header[116:124], f"{label} gid")
                mtime = parse_tar_octal(header[136:148], f"{label} mtime")
                if common_mtime is None:
                    common_mtime = mtime
                elif common_mtime != mtime:
                    fail("tar archive member timestamps are inconsistent")
                if source_date_epoch is not None and mtime != source_date_epoch:
                    fail("tar archive timestamp does not match the source commit")
                if uid != 0 or gid != 0 or mode != contract.mode:
                    fail(f"tar archive path has unsafe ownership or mode: {expected_name!r}")

                if contract.kind == "directory":
                    if typeflag != tarfile.DIRTYPE or size != 0:
                        fail(f"tar archive directory has an unsafe type or size: {expected_name!r}")
                    continue
                if typeflag not in (tarfile.REGTYPE, tarfile.AREGTYPE):
                    fail(f"tar archive file has an unsupported physical type: {expected_name!r}")
                if size <= 0 or size > contract.maximum:
                    fail(f"tar archive file size is outside its contract: {expected_name!r}")
                if unpacked + size > total_maximum:
                    fail("tar archive expands beyond its product contract")
                unpacked += size
                records[expected_name] = read_file_record(
                    source, size, expected_name in JSON_PATHS[product]
                )
                padding_size = (-size) % TAR_BLOCK_SIZE
                if padding_size and source.read(padding_size) != bytes(padding_size):
                    fail(f"tar archive file padding is non-canonical: {expected_name!r}")

            first_zero = source.read(TAR_BLOCK_SIZE)
            second_zero = source.read(TAR_BLOCK_SIZE)
            if first_zero != bytes(TAR_BLOCK_SIZE) or second_zero != bytes(TAR_BLOCK_SIZE):
                fail("tar archive has entries or data after its exact inventory")
            minimum_size = source.tell()
            expected_size = canonical_tar_size(minimum_size)
            if raw_size != expected_size:
                fail("tar archive has non-canonical trailing data or record padding")
            record_padding_size = expected_size - minimum_size
            record_padding = source.read(record_padding_size)
            if (
                record_padding != bytes(record_padding_size)
                or source.read(1) != b""
            ):
                fail("tar archive has non-canonical trailing data or record padding")
    except OSError as error:
        fail(f"cannot read tar archive: {error}")
    return records, unpacked


def validate_target(value: object, expected: dict[str, str], label: str) -> dict[str, object]:
    target = require_object(value, set(expected), label)
    if target != expected:
        fail(f"{label} does not identify Debian 13 AMD64")
    return target


def validate_database_compatibility(value: object, label: str) -> dict[str, object]:
    database = require_object(
        value,
        {
            "engine",
            "minimumSourceSchema",
            "maximumSourceSchema",
            "targetSchema",
            "migrationSetSha256",
            "migrations",
        },
        label,
    )
    target = require_integer(database["targetSchema"], f"{label}.targetSchema", 1)
    minimum = require_integer(database["minimumSourceSchema"], f"{label}.minimumSourceSchema")
    maximum = require_integer(database["maximumSourceSchema"], f"{label}.maximumSourceSchema")
    if database["engine"] != "sqlite" or minimum != 0 or maximum != target:
        fail(f"{label} has an invalid schema range")
    migrations = database["migrations"]
    if type(migrations) is not list or len(migrations) != target:
        fail(f"{label}.migrations must contain one entry for every target schema")
    canonical = hashlib.sha256()
    for index, raw_migration in enumerate(migrations, 1):
        migration_label = f"{label}.migrations[{index - 1}]"
        migration = require_object(
            raw_migration, {"version", "name", "sha256"}, migration_label
        )
        migration_version = require_integer(
            migration["version"], f"{migration_label}.version", 1
        )
        name = require_string(migration["name"], f"{migration_label}.name", 255)
        checksum = require_sha256(migration["sha256"], f"{migration_label}.sha256")
        if migration_version != index or not SAFE_MIGRATION_NAME.fullmatch(name):
            fail(f"{migration_label} is not a canonical migration identity")
        canonical.update(f"{migration_version}:{name}:{checksum}\n".encode("ascii"))
    set_digest = require_sha256(
        database["migrationSetSha256"], f"{label}.migrationSetSha256"
    )
    if canonical.hexdigest() != set_digest:
        fail(f"{label}.migrationSetSha256 does not match its migration list")
    return database


def require_source_directory(source_dir: Path) -> Path:
    try:
        if source_dir.is_symlink() or not source_dir.is_dir():
            fail("checked-out source directory is missing or unsafe")
        return source_dir.resolve(strict=True)
    except OSError as error:
        fail(f"cannot inspect checked-out source directory: {error}")


def require_source_child(
    source_dir: Path, relative: str, *, directory: bool
) -> Path:
    current = source_dir
    for component in Path(relative).parts:
        current = current / component
        if current.is_symlink():
            fail(f"checked-out source path is a symlink: {relative!r}")
    if directory and not current.is_dir():
        fail(f"checked-out source directory is missing: {relative!r}")
    if not directory and not current.is_file():
        fail(f"checked-out source file is missing: {relative!r}")
    return current


def websetupmanager_database_from_source(source_dir: Path) -> dict[str, object]:
    migration_dir = require_source_child(
        source_dir, "internal/database/migrations", directory=True
    )
    try:
        candidates = list(migration_dir.glob("*.sql"))
    except OSError as error:
        fail(f"cannot inspect Web Setup Manager migrations: {error}")
    if not candidates:
        fail("checked-out Web Setup Manager source has no migrations")
    parsed: list[tuple[int, str, Path]] = []
    for path in candidates:
        match = re.fullmatch(r"([0-9]+)_([a-z0-9_]+)\.sql", path.name)
        if (
            match is None
            or path.is_symlink()
            or not path.is_file()
        ):
            fail(f"checked-out Web Setup Manager migration is invalid: {path.name!r}")
        parsed.append((int(match.group(1)), match.group(2), path))
    parsed.sort(key=lambda item: item[0])
    migrations: list[dict[str, object]] = []
    for index, (version, name, path) in enumerate(parsed, 1):
        if version != index:
            fail("checked-out Web Setup Manager migration sequence is not contiguous")
        migrations.append(
            {"version": index, "name": name, "sha256": digest(path)}
        )
    target = len(migrations)
    canonical = hashlib.sha256()
    for migration in migrations:
        canonical.update(
            f"{migration['version']}:{migration['name']}:{migration['sha256']}\n".encode(
                "ascii"
            )
        )
    return {
        "engine": "sqlite",
        "minimumSourceSchema": 0,
        "maximumSourceSchema": target,
        "targetSchema": target,
        "migrationSetSha256": canonical.hexdigest(),
        "migrations": migrations,
    }


def validate_elf_amd64(record: FileRecord, label: str) -> None:
    header = record.prefix
    if (
        record.size < 64
        or len(header) < 64
        or header[:4] != b"\x7fELF"
        or header[4] != 2
        or header[5] != 1
        or header[6] != 1
        or int.from_bytes(header[16:18], "little") not in (2, 3)
        or int.from_bytes(header[18:20], "little") != 62
        or int.from_bytes(header[20:24], "little") != 1
        or int.from_bytes(header[24:32], "little") == 0
        or int.from_bytes(header[52:54], "little") != 64
    ):
        fail(f"{label} is not an ELF64 little-endian AMD64 executable")
    program_offset = int.from_bytes(header[32:40], "little")
    program_entry_size = int.from_bytes(header[54:56], "little")
    program_count = int.from_bytes(header[56:58], "little")
    program_end = program_offset + program_entry_size * program_count
    if (
        program_offset < 64
        or program_entry_size != 56
        or program_count < 1
        or program_count > 1024
        or program_end > record.size
        or program_end > len(header)
    ):
        fail(f"{label} has an invalid ELF program-header table")
    has_load = False
    has_executable_load = False
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        program = header[offset : offset + program_entry_size]
        program_type = int.from_bytes(program[0:4], "little")
        program_flags = int.from_bytes(program[4:8], "little")
        file_offset = int.from_bytes(program[8:16], "little")
        file_size = int.from_bytes(program[32:40], "little")
        memory_size = int.from_bytes(program[40:48], "little")
        if file_offset > record.size or file_size > record.size - file_offset:
            fail(f"{label} has an out-of-range ELF program segment")
        if program_type == 1:
            if file_size > memory_size:
                fail(f"{label} has an invalid ELF load segment")
            has_load = True
            has_executable_load = has_executable_load or bool(program_flags & 1)
    if not has_load or not has_executable_load:
        fail(f"{label} has no executable ELF load segment")


def validate_expected_source(
    actual_commit: str,
    actual_build_date: str,
    source_commit: str | None,
    source_date_epoch: int | None,
) -> None:
    if (source_commit is None) != (source_date_epoch is None):
        fail("source commit and source date epoch must be supplied together")
    if source_commit is None:
        return
    if actual_commit != require_commit(source_commit, "expected source commit"):
        fail("release metadata commit does not match the checked-out source tag")
    if source_date_epoch is None or source_date_epoch < 0:
        fail("source date epoch must be non-negative")
    if actual_build_date != build_date_for_epoch(source_date_epoch):
        fail("release metadata build date does not match the source commit timestamp")


def validate_websetupmanager(
    records: dict[str, FileRecord],
    version: str,
    source_commit: str | None,
    source_date_epoch: int | None,
    source_dir: Path | None,
) -> None:
    validate_elf_amd64(
        records["bin/websetupmanager"], "Web Setup Manager executable"
    )
    metadata = require_object(
        strict_json(
            records["metadata/version.json"].contents or b"",
            "Web Setup Manager version metadata",
        ),
        {
            "metadataSchema",
            "product",
            "version",
            "commit",
            "buildDate",
            "goVersion",
            "target",
            "databaseCompatibility",
        },
        "Web Setup Manager version metadata",
    )
    if (
        require_integer(
            metadata["metadataSchema"], "Web Setup Manager metadata schema", 1
        )
        != 1
        or metadata["product"] != "websetupmanager"
    ):
        fail("Web Setup Manager version metadata identity is invalid")
    if require_semver(metadata["version"], "Web Setup Manager version") != version:
        fail("Web Setup Manager metadata version does not match the release version")
    commit = require_commit(metadata["commit"], "Web Setup Manager commit")
    build_date = require_build_date(metadata["buildDate"], "Web Setup Manager build date")
    if not require_string(
        metadata["goVersion"], "Web Setup Manager Go version", 128
    ).startswith("go1."):
        fail("Web Setup Manager Go version is invalid")
    target = validate_target(
        metadata["target"],
        {
            "os": "linux",
            "architecture": "amd64",
            "distribution": "debian",
            "distributionVersion": "13",
        },
        "Web Setup Manager target",
    )
    database = validate_database_compatibility(
        metadata["databaseCompatibility"],
        "Web Setup Manager database compatibility",
    )
    if source_dir is not None:
        actual_database = websetupmanager_database_from_source(
            require_source_directory(source_dir)
        )
        if database != actual_database:
            fail(
                "Web Setup Manager database compatibility does not match checked-out migrations"
            )
    validate_expected_source(commit, build_date, source_commit, source_date_epoch)

    manifest = require_object(
        strict_json(
            records["manifest.json"].contents or b"",
            "Web Setup Manager inner manifest",
        ),
        {
            "manifestSchema",
            "component",
            "version",
            "source",
            "target",
            "databaseCompatibility",
            "payload",
        },
        "Web Setup Manager inner manifest",
    )
    source = require_object(
        manifest["source"], {"commit", "buildDate"}, "Web Setup Manager manifest source"
    )
    manifest_database = validate_database_compatibility(
        manifest["databaseCompatibility"],
        "Web Setup Manager manifest database compatibility",
    )
    if (
        require_integer(
            manifest["manifestSchema"], "Web Setup Manager manifest schema", 1
        )
        != 1
        or manifest["component"] != "websetupmanager"
        or manifest["version"] != version
        or source != {"commit": commit, "buildDate": build_date}
        or manifest["target"] != target
        or manifest_database != database
    ):
        fail("Web Setup Manager inner manifest does not match its version metadata")

    expected_payload = (
        ("bin/websetupmanager", "0755"),
        ("metadata/version.json", "0644"),
    )
    payload = manifest["payload"]
    if type(payload) is not list or len(payload) != len(expected_payload):
        fail("Web Setup Manager payload inventory is not exact")
    for index, (raw_artifact, expected) in enumerate(zip(payload, expected_payload)):
        expected_path, expected_mode = expected
        label = f"Web Setup Manager payload[{index}]"
        artifact = require_object(
            raw_artifact, {"mode", "path", "sha256", "size", "type"}, label
        )
        record = records[expected_path]
        if (
            artifact["path"] != expected_path
            or artifact["mode"] != expected_mode
            or artifact["type"] != "file"
            or type(artifact["size"]) is not int
            or artifact["size"] != record.size
            or artifact["sha256"] != record.sha256
        ):
            fail(f"{label} does not match archive file {expected_path!r}")


REMOTE_TERMINAL_INPUT_KEYS = {
    "DEBIAN_RELEASE",
    "DEBIAN_ARCH",
    "DEBIAN_AMD64_IMAGE",
    "GO_VERSION",
    "GO_ARCHIVE_URL",
    "GO_ARCHIVE_SHA256",
    "TTYD_VERSION",
    "TTYD_COMMIT",
    "TTYD_ARCHIVE_URL",
    "TTYD_ARCHIVE_SHA256",
    "TTYD_LICENSE_SHA256",
    "TTYD_PATCH_SHA256",
    "TTYD_WEB_INPUTS_SHA256",
    "COREPACK_VERSION",
    "COREPACK_ARCHIVE_URL",
    "COREPACK_ARCHIVE_SHA256",
    "YARN_VERSION",
    "YARN_JS_SHA256",
}


def parse_remote_terminal_inputs(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        fail("Remote Terminal release/inputs.env is missing or unsafe")
    try:
        if path.stat().st_size <= 0 or path.stat().st_size > 1 << 20:
            fail("Remote Terminal release/inputs.env size is outside its contract")
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        fail(f"cannot read Remote Terminal release inputs: {error}")
    values: dict[str, str] = {}
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if line != stripped or not re.fullmatch(
            r"[A-Z][A-Z0-9_]*=[^\s'\"`$;\\]+", stripped
        ):
            fail(f"Remote Terminal release input line {number} is not canonical")
        key, value = stripped.split("=", 1)
        if key in values:
            fail(f"Remote Terminal release input {key!r} is duplicated")
        values[key] = value
    if set(values) != REMOTE_TERMINAL_INPUT_KEYS:
        fail("Remote Terminal release input field set differs from its contract")
    return values


def remote_terminal_source_tree_digest(source_dir: Path) -> str:
    excluded_directories = {
        ".git",
        ".github",
        "build",
        "dist",
        "node_modules",
        "coverage",
    }
    entries: list[str] = []
    def walk_error(error: OSError) -> None:
        fail(f"cannot traverse Remote Terminal source: {error}")

    for current, directories, files in os.walk(
        source_dir, topdown=True, followlinks=False, onerror=walk_error
    ):
        retained: list[str] = []
        for name in sorted(directories):
            path = Path(current) / name
            if name in excluded_directories:
                continue
            if path.is_symlink():
                fail(f"Remote Terminal source contains a directory symlink: {path}")
            retained.append(name)
        directories[:] = retained
        for name in sorted(files):
            if name.endswith(".log") or name.endswith(".tsbuildinfo"):
                continue
            path = Path(current) / name
            if path.is_symlink() or not path.is_file():
                fail(f"Remote Terminal source contains an unsafe file: {path}")
            relative = path.relative_to(source_dir).as_posix()
            entries.append(f"{relative}:{digest(path)}")
    entries.sort()
    return hashlib.sha256("\n".join(entries).encode()).hexdigest()


def validate_remote_terminal_source(
    inputs: dict[str, object], source_dir: Path
) -> None:
    source_dir = require_source_directory(source_dir)
    require_source_child(source_dir, "release", directory=True)
    inputs_path = require_source_child(
        source_dir, "release/inputs.env", directory=False
    )
    patch_path = require_source_child(
        source_dir,
        "release/ttyd-disable-browser-clipboard.patch",
        directory=False,
    )
    pins = parse_remote_terminal_inputs(inputs_path)
    if patch_path.is_symlink() or not patch_path.is_file():
        fail("Remote Terminal source patch is missing or unsafe")
    if pins["TTYD_PATCH_SHA256"] != digest(patch_path):
        fail("Remote Terminal source patch does not match its pinned digest")

    source = inputs["source"]
    input_files = inputs["inputFiles"]
    target = inputs["target"]
    environment = inputs["buildEnvironment"]
    application = inputs["application"]
    toolchains = inputs["toolchains"]
    ttyd = inputs["ttyd"]
    if any(
        type(value) is not dict
        for value in (
            source,
            input_files,
            target,
            environment,
            application,
            toolchains,
            ttyd,
        )
    ):
        fail("Remote Terminal source-bound metadata objects are invalid")
    go = toolchains["go"]
    corepack = toolchains["corepack"]
    yarn = toolchains["yarn"]
    if any(type(value) is not dict for value in (go, corepack, yarn)):
        fail("Remote Terminal source-bound toolchain objects are invalid")

    expected_input_digests = {
        "release/inputs.env": digest(inputs_path),
        "release/ttyd-disable-browser-clipboard.patch": digest(patch_path),
    }
    if input_files != expected_input_digests:
        fail("Remote Terminal input-file digests do not match checked-out source")
    if source["treeSha256"] != remote_terminal_source_tree_digest(source_dir):
        fail("Remote Terminal source-tree digest does not match checked-out source")
    if target != {
        "distribution": "debian",
        "release": pins["DEBIAN_RELEASE"],
        "os": "linux",
        "arch": pins["DEBIAN_ARCH"],
    }:
        fail("Remote Terminal target does not match release/inputs.env")
    if environment != {"baseImage": pins["DEBIAN_AMD64_IMAGE"]}:
        fail("Remote Terminal base image does not match release/inputs.env")
    if application["goVersion"] != "go" + pins["GO_VERSION"] or go != {
        "version": f"go version go{pins['GO_VERSION']} linux/amd64",
        "url": pins["GO_ARCHIVE_URL"],
        "sha256": pins["GO_ARCHIVE_SHA256"],
    }:
        fail("Remote Terminal Go identity does not match release/inputs.env")
    if corepack != {
        "version": pins["COREPACK_VERSION"],
        "url": pins["COREPACK_ARCHIVE_URL"],
        "sha256": pins["COREPACK_ARCHIVE_SHA256"],
    } or yarn != {
        "version": pins["YARN_VERSION"],
        "javascriptSha256": pins["YARN_JS_SHA256"],
    }:
        fail("Remote Terminal frontend toolchains do not match release/inputs.env")
    expected_ttyd = {
        "version": pins["TTYD_VERSION"],
        "commit": pins["TTYD_COMMIT"],
        "sourceUrl": pins["TTYD_ARCHIVE_URL"],
        "sourceSha256": pins["TTYD_ARCHIVE_SHA256"],
        "licensePath": "licenses/ttyd-LICENSE",
        "licenseSha256": pins["TTYD_LICENSE_SHA256"],
        "patchSha256": pins["TTYD_PATCH_SHA256"],
        "patchedWebInputsSha256": pins["TTYD_WEB_INPUTS_SHA256"],
    }
    if ttyd != expected_ttyd:
        fail("Remote Terminal ttyd identity does not match release/inputs.env")


def validate_remote_terminal_metadata(
    records: dict[str, FileRecord],
    version: str,
    source_commit: str | None,
    source_date_epoch: int | None,
    source_dir: Path | None,
) -> None:
    validate_elf_amd64(records["bin/remoteterminal"], "Remote Terminal executable")
    validate_elf_amd64(records["bin/ttyd"], "Remote Terminal ttyd executable")
    inputs = require_object(
        strict_json(
            records["metadata/build-inputs.json"].contents or b"",
            "Remote Terminal build inputs",
        ),
        {
            "schemaVersion",
            "application",
            "target",
            "buildEnvironment",
            "source",
            "toolchains",
            "ttyd",
            "inputFiles",
            "debianPackages",
        },
        "Remote Terminal build inputs",
    )
    if (
        require_integer(inputs["schemaVersion"], "Remote Terminal build-input schema", 1)
        != 1
    ):
        fail("Remote Terminal build-input schema is unsupported")
    application = require_object(
        inputs["application"],
        {"name", "version", "commit", "buildDate", "goVersion", "os", "arch"},
        "Remote Terminal application metadata",
    )
    if (
        application["name"] != "remoteterminal"
        or application["os"] != "linux"
        or application["arch"] != "amd64"
    ):
        fail("Remote Terminal application identity is invalid")
    if require_semver(application["version"], "Remote Terminal version") != version:
        fail("Remote Terminal metadata version does not match the release version")
    commit = require_commit(application["commit"], "Remote Terminal commit")
    build_date = require_build_date(application["buildDate"], "Remote Terminal build date")
    if not require_string(
        application["goVersion"], "Remote Terminal Go version", 128
    ).startswith("go1."):
        fail("Remote Terminal Go version is invalid")
    target = validate_target(
        inputs["target"],
        {"distribution": "debian", "release": "13", "os": "linux", "arch": "amd64"},
        "Remote Terminal target",
    )
    environment = require_object(
        inputs["buildEnvironment"], {"baseImage"}, "Remote Terminal build environment"
    )
    base_image = require_string(
        environment["baseImage"], "Remote Terminal base image", 512
    )
    if not re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", base_image):
        fail("Remote Terminal base image must be digest-pinned")
    source = require_object(
        inputs["source"],
        {"commit", "treeSha256", "sourceDateEpoch"},
        "Remote Terminal source",
    )
    if require_commit(source["commit"], "Remote Terminal source commit") != commit:
        fail("Remote Terminal source commit does not match the application commit")
    require_sha256(source["treeSha256"], "Remote Terminal source tree digest")
    epoch = require_integer(source["sourceDateEpoch"], "Remote Terminal source date epoch")
    if build_date != build_date_for_epoch(epoch):
        fail("Remote Terminal build date does not match its source date epoch")
    validate_expected_source(commit, build_date, source_commit, source_date_epoch)
    if source_date_epoch is not None and epoch != source_date_epoch:
        fail("Remote Terminal source date epoch does not match the checked-out source tag")

    validate_remote_terminal_toolchains(inputs["toolchains"])
    validate_remote_terminal_ttyd(
        inputs["ttyd"], records["licenses/ttyd-LICENSE"]
    )
    input_files = require_object(
        inputs["inputFiles"],
        {"release/inputs.env", "release/ttyd-disable-browser-clipboard.patch"},
        "Remote Terminal input files",
    )
    for path, checksum in input_files.items():
        require_sha256(checksum, f"Remote Terminal input file {path!r}")
    if source_dir is not None:
        validate_remote_terminal_source(inputs, source_dir)
    packages = inputs["debianPackages"]
    if type(packages) is not list or not packages or len(packages) > 10_000:
        fail("Remote Terminal Debian package inventory is invalid")
    normalized_packages = [
        require_string(item, "Remote Terminal Debian package", 1024) for item in packages
    ]
    if normalized_packages != sorted(set(normalized_packages)):
        fail("Remote Terminal Debian package inventory must be sorted and unique")

    manifest = require_object(
        strict_json(
            records["manifest.json"].contents or b"", "Remote Terminal inner manifest"
        ),
        {
            "schemaVersion",
            "name",
            "version",
            "commit",
            "buildDate",
            "target",
            "includesCodeServer",
            "artifacts",
        },
        "Remote Terminal inner manifest",
    )
    if (
        require_integer(
            manifest["schemaVersion"], "Remote Terminal manifest schema", 1
        )
        != 1
        or manifest["name"] != "remoteterminal"
        or manifest["version"] != version
        or manifest["commit"] != commit
        or manifest["buildDate"] != build_date
        or manifest["target"] != target
        or manifest["includesCodeServer"] is not False
    ):
        fail("Remote Terminal inner manifest does not match its build inputs")
    validate_remote_terminal_artifacts(manifest["artifacts"], records)


def validate_remote_terminal_toolchains(value: object) -> None:
    toolchains = require_object(
        value, {"go", "node", "npm", "corepack", "yarn"}, "Remote Terminal toolchains"
    )
    go = require_object(
        toolchains["go"], {"version", "url", "sha256"}, "Remote Terminal Go toolchain"
    )
    go_version = require_string(
        go["version"], "Remote Terminal Go toolchain version", 128
    )
    if not re.fullmatch(r"go version go1\.[0-9A-Za-z.]+ linux/amd64", go_version):
        fail("Remote Terminal Go toolchain version is invalid")
    require_https_url(go["url"], "Remote Terminal Go toolchain URL")
    require_sha256(go["sha256"], "Remote Terminal Go toolchain digest")
    require_string(toolchains["node"], "Remote Terminal Node version", 128)
    require_string(toolchains["npm"], "Remote Terminal npm version", 128)
    corepack = require_object(
        toolchains["corepack"],
        {"version", "url", "sha256"},
        "Remote Terminal Corepack toolchain",
    )
    require_string(corepack["version"], "Remote Terminal Corepack version", 128)
    require_https_url(corepack["url"], "Remote Terminal Corepack URL")
    require_sha256(corepack["sha256"], "Remote Terminal Corepack digest")
    yarn = require_object(
        toolchains["yarn"],
        {"version", "javascriptSha256"},
        "Remote Terminal Yarn toolchain",
    )
    require_string(yarn["version"], "Remote Terminal Yarn version", 128)
    require_sha256(yarn["javascriptSha256"], "Remote Terminal Yarn digest")


def validate_remote_terminal_ttyd(value: object, license_record: FileRecord) -> None:
    ttyd = require_object(
        value,
        {
            "version",
            "commit",
            "sourceUrl",
            "sourceSha256",
            "licensePath",
            "licenseSha256",
            "patchSha256",
            "patchedWebInputsSha256",
        },
        "Remote Terminal ttyd inputs",
    )
    require_string(ttyd["version"], "ttyd version", 128)
    require_commit(ttyd["commit"], "ttyd commit")
    require_https_url(ttyd["sourceUrl"], "ttyd source URL")
    require_sha256(ttyd["sourceSha256"], "ttyd source digest")
    if ttyd["licensePath"] != "licenses/ttyd-LICENSE":
        fail("ttyd license path is invalid")
    if require_sha256(ttyd["licenseSha256"], "ttyd license digest") != license_record.sha256:
        fail("ttyd license digest does not match the bundled license")
    require_sha256(ttyd["patchSha256"], "ttyd patch digest")
    require_sha256(ttyd["patchedWebInputsSha256"], "ttyd patched web-input digest")


def validate_remote_terminal_artifacts(
    value: object, records: dict[str, FileRecord]
) -> None:
    expected = (
        ("bin/remoteterminal", "0755"),
        ("bin/ttyd", "0755"),
        ("licenses/ttyd-LICENSE", "0644"),
        ("metadata/build-inputs.json", "0644"),
    )
    if type(value) is not list or len(value) != len(expected):
        fail("Remote Terminal artifact inventory is not exact")
    for index, (raw_artifact, expected_identity) in enumerate(zip(value, expected)):
        expected_path, expected_mode = expected_identity
        label = f"Remote Terminal artifact[{index}]"
        artifact = require_object(
            raw_artifact, {"path", "sha256", "size", "mode"}, label
        )
        record = records[expected_path]
        if (
            artifact["path"] != expected_path
            or artifact["mode"] != expected_mode
            or type(artifact["size"]) is not int
            or artifact["size"] != record.size
            or artifact["sha256"] != record.sha256
        ):
            fail(f"{label} does not match archive file {expected_path!r}")


def validate_tar(
    tar_path: Path,
    product: str,
    version: str,
    source_commit: str | None = None,
    source_date_epoch: int | None = None,
    source_dir: Path | None = None,
) -> int:
    require_semver(version, "release version")
    if (source_commit is None) != (source_date_epoch is None):
        fail("source commit and source date epoch must be supplied together")
    if source_dir is not None and (source_commit is None or source_date_epoch is None):
        fail("source directory requires the expected source commit and timestamp")
    records, unpacked = scan_canonical_tar(tar_path, product, source_date_epoch)
    if product == "websetupmanager":
        validate_websetupmanager(
            records, version, source_commit, source_date_epoch, source_dir
        )
    else:
        validate_remote_terminal_metadata(
            records, version, source_commit, source_date_epoch, source_dir
        )
    return unpacked


def validate_sidecar(asset: Path, sidecar: Path) -> None:
    if (
        not sidecar.is_file()
        or sidecar.is_symlink()
        or sidecar.name != asset.name + ".sha256"
    ):
        fail("checksum sidecar must be the expected regular file")
    sidecar_size = sidecar.stat().st_size
    if sidecar_size <= 0 or sidecar_size > 256:
        fail("checksum sidecar size is outside its contract")
    try:
        raw = sidecar.read_bytes()
    except OSError as error:
        fail(f"cannot read checksum sidecar: {error}")
    expected = f"{digest(asset)}  {asset.name}\n".encode("ascii")
    if raw != expected:
        fail("checksum sidecar is not the canonical one-line asset digest")


def validate_component_output(directory: Path, product: str, version: str) -> None:
    require_semver(version, "release version")
    expected_name = f"{product}-{version}-debian13-amd64.tar.zst"
    try:
        entries = list(directory.iterdir())
    except OSError as error:
        fail(f"cannot inspect component output: {error}")
    if {entry.name for entry in entries} != {expected_name, expected_name + ".sha256"}:
        fail("component output must contain exactly the asset and its checksum sidecar")
    asset = directory / expected_name
    sidecar = directory / (expected_name + ".sha256")
    if not asset.is_file() or asset.is_symlink():
        fail("component asset must be a regular file")
    size = asset.stat().st_size
    if size <= 0 or size > MAX_COMPRESSED_BYTES:
        fail("compressed asset size is outside the supported range")
    validate_sidecar(asset, sidecar)


def nonnegative_integer(raw: str) -> int:
    if not re.fullmatch(r"[0-9]+", raw):
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return int(raw)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--product", choices=sorted(PRODUCTS), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--component-output", type=Path)
    parser.add_argument("--asset", type=Path)
    parser.add_argument("--sidecar", type=Path)
    parser.add_argument("--tar", type=Path)
    parser.add_argument("--url")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--source-date-epoch", type=nonnegative_integer)
    parser.add_argument("--source-dir", type=Path)
    args = parser.parse_args()

    require_semver(args.version, "release version")
    if args.component_output is not None:
        if any(
            value is not None
            for value in (
                args.asset,
                args.sidecar,
                args.tar,
                args.url,
                args.output,
                args.source_commit,
                args.source_date_epoch,
                args.source_dir,
            )
        ):
            fail("component-output validation does not accept manifest arguments")
        validate_component_output(args.component_output, args.product, args.version)
        return
    if any(value is None for value in (args.asset, args.tar, args.url, args.output)):
        parser.error("--asset, --tar, --url, and --output are required")
    source_arguments = (
        args.source_commit,
        args.source_date_epoch,
        args.source_dir,
    )
    if any(value is not None for value in source_arguments) and any(
        value is None for value in source_arguments
    ):
        fail("source commit, source date epoch, and source directory must be supplied together")

    asset: Path = args.asset
    tar_path: Path = args.tar
    output: Path = args.output
    if not asset.is_file() or asset.is_symlink():
        fail("asset must be a regular file")
    expected_name = f"{args.product}-{args.version}-debian13-amd64.tar.zst"
    if asset.name != expected_name:
        fail(f"asset name must be {expected_name!r}")
    size = asset.stat().st_size
    if size <= 0 or size > MAX_COMPRESSED_BYTES:
        fail("compressed asset size is outside the supported range")
    asset_sha256 = digest(asset)
    if args.sidecar is not None:
        validate_sidecar(asset, args.sidecar)
    unpacked = validate_tar(
        tar_path,
        args.product,
        args.version,
        args.source_commit,
        args.source_date_epoch,
        args.source_dir,
    )
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
            "sha256": asset_sha256,
            "unpacked_size": unpacked,
            "format": "tar.zst",
        },
    }
    output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    main()
