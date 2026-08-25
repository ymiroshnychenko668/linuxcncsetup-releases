from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import re
import subprocess
import tarfile
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "create_manifest", ROOT / "scripts" / "create-manifest.py"
)
assert SPEC is not None and SPEC.loader is not None
CREATE_MANIFEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CREATE_MANIFEST)

VERSION = "1.2.3"
COMMIT = "a" * 40
SOURCE_DATE_EPOCH = 1787650000
BUILD_DATE = datetime.fromtimestamp(SOURCE_DATE_EPOCH, timezone.utc).strftime(
    "%Y-%m-%dT%H:%M:%SZ"
)
SHA = "b" * 64
MIGRATION_SQL = b"CREATE TABLE release_fixture (id INTEGER PRIMARY KEY);\n"
LICENSE_CONTENTS = b"MIT license\n"


def elf_amd64(marker: bytes) -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = (62).to_bytes(2, "little")
    header[20:24] = (1).to_bytes(4, "little")
    header[24:32] = (0x400000).to_bytes(8, "little")
    header[32:40] = (64).to_bytes(8, "little")
    header[52:54] = (64).to_bytes(2, "little")
    header[54:56] = (56).to_bytes(2, "little")
    header[56:58] = (1).to_bytes(2, "little")
    program = bytearray(56)
    program[0:4] = (1).to_bytes(4, "little")
    program[4:8] = (5).to_bytes(4, "little")
    program[16:24] = (0x400000).to_bytes(8, "little")
    program[24:32] = (0x400000).to_bytes(8, "little")
    size = len(header) + len(program) + len(marker)
    program[32:40] = size.to_bytes(8, "little")
    program[40:48] = size.to_bytes(8, "little")
    program[48:56] = (0x1000).to_bytes(8, "little")
    return bytes(header + program) + marker


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def artifact(path: str, mode: str, contents: bytes, include_type: bool = False) -> dict[str, object]:
    result: dict[str, object] = {
        "path": path,
        "mode": mode,
        "size": len(contents),
        "sha256": sha256(contents),
    }
    if include_type:
        result["type"] = "file"
    return result


def migration_contract() -> dict[str, object]:
    migration_sha = sha256(MIGRATION_SQL)
    migrations = [{"version": 1, "name": "initial", "sha256": migration_sha}]
    canonical = f"1:initial:{migration_sha}\n".encode("ascii")
    return {
        "engine": "sqlite",
        "minimumSourceSchema": 0,
        "maximumSourceSchema": 1,
        "targetSchema": 1,
        "migrationSetSha256": sha256(canonical),
        "migrations": migrations,
    }


def websetupmanager_bodies(
    metadata_mutator=None,
    manifest_mutator=None,
    duplicate_metadata_version: bool = False,
    duplicate_manifest_version: bool = False,
) -> dict[str, bytes]:
    binary = elf_amd64(b"websetupmanager")
    target = {
        "os": "linux",
        "architecture": "amd64",
        "distribution": "debian",
        "distributionVersion": "13",
    }
    database = migration_contract()
    metadata = {
        "metadataSchema": 1,
        "product": "websetupmanager",
        "version": VERSION,
        "commit": COMMIT,
        "buildDate": BUILD_DATE,
        "goVersion": "go1.26.5",
        "target": target,
        "databaseCompatibility": database,
    }
    if metadata_mutator is not None:
        metadata_mutator(metadata)
    metadata_raw = json_bytes(metadata)
    if duplicate_metadata_version:
        metadata_raw = metadata_raw.rstrip()[:-1] + b',"version":"1.2.3"}\n'
    manifest = {
        "manifestSchema": 1,
        "component": "websetupmanager",
        "version": metadata["version"],
        "source": {"commit": metadata["commit"], "buildDate": metadata["buildDate"]},
        "target": copy.deepcopy(metadata["target"]),
        "databaseCompatibility": copy.deepcopy(metadata["databaseCompatibility"]),
        "payload": [
            artifact("bin/websetupmanager", "0755", binary, True),
            artifact("metadata/version.json", "0644", metadata_raw, True),
        ],
    }
    if manifest_mutator is not None:
        manifest_mutator(manifest)
    manifest_raw = json_bytes(manifest)
    if duplicate_manifest_version:
        manifest_raw = manifest_raw.rstrip()[:-1] + b',"version":"1.2.3"}\n'
    return {
        "bin/websetupmanager": binary,
        "metadata/version.json": metadata_raw,
        "manifest.json": manifest_raw,
    }


def make_websetupmanager_source(root: Path) -> Path:
    migration_dir = root / "internal" / "database" / "migrations"
    migration_dir.mkdir(parents=True)
    (migration_dir / "001_initial.sql").write_bytes(MIGRATION_SQL)
    return root


def make_remote_terminal_source(root: Path) -> Path:
    release = root / "release"
    release.mkdir(parents=True)
    patch = b"fixture ttyd patch\n"
    (release / "ttyd-disable-browser-clipboard.patch").write_bytes(patch)
    values = {
        "DEBIAN_RELEASE": "13",
        "DEBIAN_ARCH": "amd64",
        "DEBIAN_AMD64_IMAGE": "debian:13-slim@sha256:" + SHA,
        "GO_VERSION": "1.26.5",
        "GO_ARCHIVE_URL": "https://go.dev/go.tar.gz",
        "GO_ARCHIVE_SHA256": SHA,
        "TTYD_VERSION": "1.7.7",
        "TTYD_COMMIT": "c" * 40,
        "TTYD_ARCHIVE_URL": "https://github.com/tsl0922/ttyd/archive/source.tar.gz",
        "TTYD_ARCHIVE_SHA256": SHA,
        "TTYD_LICENSE_SHA256": sha256(LICENSE_CONTENTS),
        "TTYD_PATCH_SHA256": sha256(patch),
        "TTYD_WEB_INPUTS_SHA256": SHA,
        "COREPACK_VERSION": "0.29.4",
        "COREPACK_ARCHIVE_URL": "https://registry.npmjs.org/corepack.tgz",
        "COREPACK_ARCHIVE_SHA256": SHA,
        "YARN_VERSION": "3.6.3",
        "YARN_JS_SHA256": SHA,
    }
    (release / "inputs.env").write_text(
        "\n".join(f"{key}={value}" for key, value in values.items()) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (root / "README.md").write_text("fixture source\n", encoding="utf-8")
    return root


def remote_terminal_bodies(
    manifest_mutator=None,
    inputs_mutator=None,
    source_dir: Path | None = None,
) -> dict[str, bytes]:
    application_binary = elf_amd64(b"remoteterminal")
    ttyd_binary = elf_amd64(b"ttyd")
    license_contents = LICENSE_CONTENTS
    target = {"distribution": "debian", "release": "13", "os": "linux", "arch": "amd64"}
    pins = (
        CREATE_MANIFEST.parse_remote_terminal_inputs(source_dir / "release" / "inputs.env")
        if source_dir is not None
        else None
    )
    inputs = {
        "schemaVersion": 1,
        "application": {
            "name": "remoteterminal",
            "version": VERSION,
            "commit": COMMIT,
            "buildDate": BUILD_DATE,
            "goVersion": "go1.26.5",
            "os": "linux",
            "arch": "amd64",
        },
        "target": target,
        "buildEnvironment": {
            "baseImage": pins["DEBIAN_AMD64_IMAGE"] if pins is not None else "debian:13-slim@sha256:" + SHA
        },
        "source": {
            "commit": COMMIT,
            "treeSha256": (
                CREATE_MANIFEST.remote_terminal_source_tree_digest(source_dir)
                if source_dir is not None
                else SHA
            ),
            "sourceDateEpoch": SOURCE_DATE_EPOCH,
        },
        "toolchains": {
            "go": {
                "version": f"go version go{pins['GO_VERSION'] if pins is not None else '1.26.5'} linux/amd64",
                "url": pins["GO_ARCHIVE_URL"] if pins is not None else "https://go.dev/go.tar.gz",
                "sha256": pins["GO_ARCHIVE_SHA256"] if pins is not None else SHA,
            },
            "node": "v22.0.0",
            "npm": "10.0.0",
            "corepack": {
                "version": pins["COREPACK_VERSION"] if pins is not None else "0.29.4",
                "url": pins["COREPACK_ARCHIVE_URL"] if pins is not None else "https://registry.npmjs.org/corepack.tgz",
                "sha256": pins["COREPACK_ARCHIVE_SHA256"] if pins is not None else SHA,
            },
            "yarn": {
                "version": pins["YARN_VERSION"] if pins is not None else "3.6.3",
                "javascriptSha256": pins["YARN_JS_SHA256"] if pins is not None else SHA,
            },
        },
        "ttyd": {
            "version": pins["TTYD_VERSION"] if pins is not None else "1.7.7",
            "commit": pins["TTYD_COMMIT"] if pins is not None else "c" * 40,
            "sourceUrl": pins["TTYD_ARCHIVE_URL"] if pins is not None else "https://github.com/tsl0922/ttyd/archive/source.tar.gz",
            "sourceSha256": pins["TTYD_ARCHIVE_SHA256"] if pins is not None else SHA,
            "licensePath": "licenses/ttyd-LICENSE",
            "licenseSha256": pins["TTYD_LICENSE_SHA256"] if pins is not None else sha256(license_contents),
            "patchSha256": pins["TTYD_PATCH_SHA256"] if pins is not None else SHA,
            "patchedWebInputsSha256": pins["TTYD_WEB_INPUTS_SHA256"] if pins is not None else SHA,
        },
        "inputFiles": {
            "release/inputs.env": (
                CREATE_MANIFEST.digest(source_dir / "release" / "inputs.env")
                if source_dir is not None
                else SHA
            ),
            "release/ttyd-disable-browser-clipboard.patch": (
                CREATE_MANIFEST.digest(source_dir / "release" / "ttyd-disable-browser-clipboard.patch")
                if source_dir is not None
                else SHA
            ),
        },
        "debianPackages": ["libc6=1", "zlib1g=1"],
    }
    if inputs_mutator is not None:
        inputs_mutator(inputs)
    inputs_raw = json_bytes(inputs)
    manifest = {
        "schemaVersion": 1,
        "name": "remoteterminal",
        "version": inputs["application"]["version"],
        "commit": inputs["application"]["commit"],
        "buildDate": inputs["application"]["buildDate"],
        "target": copy.deepcopy(inputs["target"]),
        "includesCodeServer": False,
        "artifacts": [
            artifact("bin/remoteterminal", "0755", application_binary),
            artifact("bin/ttyd", "0755", ttyd_binary),
            artifact("licenses/ttyd-LICENSE", "0644", license_contents),
            artifact("metadata/build-inputs.json", "0644", inputs_raw),
        ],
    }
    if manifest_mutator is not None:
        manifest_mutator(manifest)
    return {
        "bin/remoteterminal": application_binary,
        "bin/ttyd": ttyd_binary,
        "licenses/ttyd-LICENSE": license_contents,
        "metadata/build-inputs.json": inputs_raw,
        "manifest.json": json_bytes(manifest),
    }


def archive_entries(product: str, bodies: dict[str, bytes]) -> list[dict[str, object]]:
    if product == "websetupmanager":
        order = ["bin", "bin/websetupmanager", "metadata", "metadata/version.json", "manifest.json"]
    else:
        order = [
            "bin",
            "bin/remoteterminal",
            "bin/ttyd",
            "licenses",
            "licenses/ttyd-LICENSE",
            "metadata",
            "metadata/build-inputs.json",
            "manifest.json",
        ]
    entries = []
    for name in order:
        contract = CREATE_MANIFEST.PRODUCTS[product][name]
        entries.append(
            {
                "name": name,
                "type": tarfile.DIRTYPE if contract.kind == "directory" else tarfile.REGTYPE,
                "mode": contract.mode,
                "uid": 0,
                "gid": 0,
                "body": None if contract.kind == "directory" else bodies[name],
            }
        )
    return entries


def write_tar(
    path: Path,
    entries: list[dict[str, object]],
    archive_format: int | None = None,
) -> int:
    unpacked = 0
    if archive_format is None:
        archive_format = (
            tarfile.PAX_FORMAT
            if any(raw.get("pax_headers") for raw in entries)
            else tarfile.USTAR_FORMAT
        )
    with tarfile.open(path, "w:", format=archive_format) as archive:
        for raw in entries:
            entry = tarfile.TarInfo(str(raw["name"]))
            entry.type = raw["type"]
            entry.mode = int(raw["mode"])
            entry.uid = int(raw.get("uid", 0))
            entry.gid = int(raw.get("gid", 0))
            entry.mtime = SOURCE_DATE_EPOCH
            entry.pax_headers = dict(raw.get("pax_headers", {}))
            body = raw.get("body")
            if body is None:
                entry.size = 0
                archive.addfile(entry)
            else:
                entry.size = len(body)
                archive.addfile(entry, io.BytesIO(body))
                unpacked += len(body)
    return unpacked


class ManifestTests(unittest.TestCase):
    def make_tar(
        self,
        directory: Path,
        product: str,
        bodies: dict[str, bytes],
        mutate_entries=None,
        archive_format: int | None = None,
    ) -> tuple[Path, int]:
        entries = archive_entries(product, bodies)
        if mutate_entries is not None:
            mutate_entries(entries)
        path = directory / "payload.tar"
        return path, write_tar(path, entries, archive_format)

    def validate(self, path: Path, product: str) -> int:
        return CREATE_MANIFEST.validate_tar(
            path, product, VERSION, COMMIT, SOURCE_DATE_EPOCH
        )

    def test_valid_websetupmanager_archive_and_canonical_outer_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_dir = make_websetupmanager_source(root / "source")
            tar_path, expected_unpacked = self.make_tar(
                root, "websetupmanager", websetupmanager_bodies()
            )
            self.assertEqual(self.validate(tar_path, "websetupmanager"), expected_unpacked)
            asset = root / f"websetupmanager-{VERSION}-debian13-amd64.tar.zst"
            subprocess.run(
                ["zstd", "--quiet", "-19", str(tar_path), "-o", str(asset)], check=True
            )
            sidecar = Path(str(asset) + ".sha256")
            sidecar.write_text(f"{CREATE_MANIFEST.digest(asset)}  {asset.name}\n", encoding="ascii")
            output = root / "outer.json"
            url = (
                "https://github.com/ymiroshnychenko668/linuxcncsetup-releases/"
                f"releases/download/websetupmanager-v{VERSION}/{asset.name}"
            )
            subprocess.run(
                [
                    "python3",
                    str(ROOT / "scripts" / "create-manifest.py"),
                    "--product",
                    "websetupmanager",
                    "--version",
                    VERSION,
                    "--asset",
                    str(asset),
                    "--sidecar",
                    str(sidecar),
                    "--tar",
                    str(tar_path),
                    "--url",
                    url,
                    "--source-commit",
                    COMMIT,
                    "--source-date-epoch",
                    str(SOURCE_DATE_EPOCH),
                    "--source-dir",
                    str(source_dir),
                    "--output",
                    str(output),
                ],
                check=True,
            )
            value = json.loads(output.read_bytes())
            self.assertEqual(value["asset"]["unpacked_size"], expected_unpacked)
            self.assertEqual(value["asset"]["sha256"], CREATE_MANIFEST.digest(asset))

    def test_valid_remote_terminal_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_dir = make_remote_terminal_source(root / "source")
            bodies = remote_terminal_bodies(source_dir=source_dir)
            tar_version = subprocess.run(
                ["tar", "--version"], capture_output=True, text=True, check=False
            ).stdout
            if "GNU tar" in tar_version:
                payload = root / "producer-payload"
                for directory in ("bin", "licenses", "metadata"):
                    (payload / directory).mkdir(parents=True, mode=0o755)
                    (payload / directory).chmod(0o755)
                for name, contents in bodies.items():
                    destination = payload / name
                    destination.write_bytes(contents)
                    destination.chmod(0o755 if name.startswith("bin/") else 0o644)
                path = root / "payload.tar"
                subprocess.run(
                    [
                        "tar",
                        "--sort=name",
                        f"--mtime=@{SOURCE_DATE_EPOCH}",
                        "--owner=0",
                        "--group=0",
                        "--numeric-owner",
                        "--format=ustar",
                        "-C",
                        str(payload),
                        "-cf",
                        str(path),
                        "bin",
                        "licenses",
                        "metadata",
                        "manifest.json",
                    ],
                    check=True,
                )
                unpacked = sum(len(contents) for contents in bodies.values())
            else:
                path, unpacked = self.make_tar(
                    root,
                    "remoteterminal",
                    bodies,
                    archive_format=tarfile.USTAR_FORMAT,
                )
            self.assertEqual(
                CREATE_MANIFEST.validate_tar(
                    path,
                    "remoteterminal",
                    VERSION,
                    COMMIT,
                    SOURCE_DATE_EPOCH,
                    source_dir,
                ),
                unpacked,
            )

    def test_only_go_compatible_regular_types_are_accepted(self) -> None:
        for typeflag, accepted in (
            (tarfile.AREGTYPE, True),
            (tarfile.CONTTYPE, False),
            (tarfile.GNUTYPE_SPARSE, False),
        ):
            with self.subTest(typeflag=typeflag), tempfile.TemporaryDirectory() as temporary:
                def mutate(entries):
                    next(item for item in entries if item["name"] == "bin/websetupmanager")["type"] = typeflag

                path, _ = self.make_tar(
                    Path(temporary), "websetupmanager", websetupmanager_bodies(), mutate
                )
                if accepted:
                    self.validate(path, "websetupmanager")
                else:
                    with self.assertRaises(SystemExit):
                        self.validate(path, "websetupmanager")

        with tempfile.TemporaryDirectory() as temporary:
            def make_pax_sparse(entries):
                item = next(
                    entry for entry in entries if entry["name"] == "bin/websetupmanager"
                )
                size = len(item["body"])
                item["pax_headers"] = {
                    "GNU.sparse.map": f"0,{size}",
                    "GNU.sparse.size": str(size),
                }

            path, _ = self.make_tar(
                Path(temporary),
                "websetupmanager",
                websetupmanager_bodies(),
                make_pax_sparse,
            )
            with self.assertRaises(SystemExit):
                self.validate(path, "websetupmanager")

        with tempfile.TemporaryDirectory() as temporary:
            def add_pax_extension(entries):
                item = next(
                    entry for entry in entries if entry["name"] == "bin/websetupmanager"
                )
                item["pax_headers"] = {"comment": "hidden physical extension"}

            path, _ = self.make_tar(
                Path(temporary),
                "websetupmanager",
                websetupmanager_bodies(),
                add_pax_extension,
            )
            with self.assertRaises(SystemExit):
                self.validate(path, "websetupmanager")

    def test_raw_tar_rejects_trailing_data_and_noncanonical_record_size(self) -> None:
        for trailing in (b"unexpected", bytes(10_240)):
            with self.subTest(trailing=bool(trailing.strip(b"\0"))), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                path, _ = self.make_tar(
                    root, "websetupmanager", websetupmanager_bodies()
                )
                with path.open("ab") as archive:
                    archive.write(trailing)
                with self.assertRaises(SystemExit):
                    self.validate(path, "websetupmanager")

    def test_websetupmanager_zero_and_oversized_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bodies = websetupmanager_bodies()
            bodies["bin/websetupmanager"] = b""
            path, _ = self.make_tar(Path(temporary), "websetupmanager", bodies)
            with self.assertRaises(SystemExit):
                self.validate(path, "websetupmanager")

        contract = CREATE_MANIFEST.PRODUCTS["websetupmanager"]["bin/websetupmanager"]
        self.assertEqual(contract.maximum, 256 << 20)
        CREATE_MANIFEST.PRODUCTS["websetupmanager"]["bin/websetupmanager"] = (
            CREATE_MANIFEST.EntryContract("file", 0o755, 4)
        )
        try:
            with tempfile.TemporaryDirectory() as temporary:
                bodies = websetupmanager_bodies()
                path, _ = self.make_tar(Path(temporary), "websetupmanager", bodies)
                with self.assertRaises(SystemExit):
                    self.validate(path, "websetupmanager")
        finally:
            CREATE_MANIFEST.PRODUCTS["websetupmanager"]["bin/websetupmanager"] = contract

    def test_authoritative_product_total_limits_are_enforced(self) -> None:
        expected_file_limits = {
            "remoteterminal": {
                "bin/remoteterminal": 100 << 20,
                "bin/ttyd": 100 << 20,
                "licenses/ttyd-LICENSE": 1 << 20,
                "metadata/build-inputs.json": 1 << 20,
                "manifest.json": 128 << 10,
            },
            "websetupmanager": {
                "bin/websetupmanager": 256 << 20,
                "metadata/version.json": 1 << 20,
                "manifest.json": 1 << 20,
            },
        }
        for product, limits in expected_file_limits.items():
            with self.subTest(product=product):
                self.assertEqual(
                    {
                        path: contract.maximum
                        for path, contract in CREATE_MANIFEST.PRODUCTS[product].items()
                        if contract.kind == "file"
                    },
                    limits,
                )
        self.assertEqual(
            CREATE_MANIFEST.PRODUCT_UNPACKED_MAXIMUM,
            {"remoteterminal": 100 << 20, "websetupmanager": 258 << 20},
        )
        bodies = websetupmanager_bodies()
        fixture_size = sum(len(contents) for contents in bodies.values())
        original = CREATE_MANIFEST.PRODUCT_UNPACKED_MAXIMUM["websetupmanager"]
        CREATE_MANIFEST.PRODUCT_UNPACKED_MAXIMUM["websetupmanager"] = fixture_size - 1
        try:
            with tempfile.TemporaryDirectory() as temporary:
                path, _ = self.make_tar(
                    Path(temporary), "websetupmanager", bodies
                )
                with self.assertRaises(SystemExit):
                    self.validate(path, "websetupmanager")
        finally:
            CREATE_MANIFEST.PRODUCT_UNPACKED_MAXIMUM["websetupmanager"] = original

    def test_websetupmanager_inner_tampering_is_rejected(self) -> None:
        cases = {
            "version": lambda metadata: metadata.__setitem__("version", "1.2.4"),
            "source-commit": lambda metadata: metadata.__setitem__("commit", "c" * 40),
            "target": lambda metadata: metadata["target"].__setitem__("architecture", "arm64"),
            "migration-set": lambda metadata: metadata["databaseCompatibility"].__setitem__(
                "migrationSetSha256", "0" * 64
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                path, _ = self.make_tar(
                    Path(temporary),
                    "websetupmanager",
                    websetupmanager_bodies(metadata_mutator=mutate),
                )
                with self.assertRaises(SystemExit):
                    self.validate(path, "websetupmanager")

        with tempfile.TemporaryDirectory() as temporary:
            def tamper_payload(manifest):
                manifest["payload"][0]["sha256"] = "0" * 64

            path, _ = self.make_tar(
                Path(temporary),
                "websetupmanager",
                websetupmanager_bodies(manifest_mutator=tamper_payload),
            )
            with self.assertRaises(SystemExit):
                self.validate(path, "websetupmanager")

        for field, value in (("targetSchema", True), ("maximumSourceSchema", 1.0)):
            with self.subTest(database_field=field), tempfile.TemporaryDirectory() as temporary:
                def tamper_database_type(manifest, field=field, value=value):
                    manifest["databaseCompatibility"][field] = value

                path, _ = self.make_tar(
                    Path(temporary),
                    "websetupmanager",
                    websetupmanager_bodies(manifest_mutator=tamper_database_type),
                )
                with self.assertRaises(SystemExit):
                    self.validate(path, "websetupmanager")

    def test_source_bindings_reject_migration_and_remote_tree_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_dir = make_websetupmanager_source(root / "source")
            path, _ = self.make_tar(
                root, "websetupmanager", websetupmanager_bodies()
            )
            self.assertGreater(
                CREATE_MANIFEST.validate_tar(
                    path,
                    "websetupmanager",
                    VERSION,
                    COMMIT,
                    SOURCE_DATE_EPOCH,
                    source_dir,
                ),
                0,
            )
            (
                source_dir / "internal" / "database" / "migrations" / "001_initial.sql"
            ).write_bytes(MIGRATION_SQL + b"-- tampered\n")
            with self.assertRaises(SystemExit):
                CREATE_MANIFEST.validate_tar(
                    path,
                    "websetupmanager",
                    VERSION,
                    COMMIT,
                    SOURCE_DATE_EPOCH,
                    source_dir,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_dir = make_remote_terminal_source(root / "source")
            path, _ = self.make_tar(
                root,
                "remoteterminal",
                remote_terminal_bodies(source_dir=source_dir),
                archive_format=tarfile.USTAR_FORMAT,
            )
            self.assertGreater(
                CREATE_MANIFEST.validate_tar(
                    path,
                    "remoteterminal",
                    VERSION,
                    COMMIT,
                    SOURCE_DATE_EPOCH,
                    source_dir,
                ),
                0,
            )
            (source_dir / "README.md").write_text("changed source\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                CREATE_MANIFEST.validate_tar(
                    path,
                    "remoteterminal",
                    VERSION,
                    COMMIT,
                    SOURCE_DATE_EPOCH,
                    source_dir,
                )
            (source_dir / "README.md").write_text(
                "fixture source\n", encoding="utf-8"
            )
            inputs_path = source_dir / "release" / "inputs.env"
            inputs_path.write_text(
                inputs_path.read_text(encoding="utf-8").replace(
                    "GO_VERSION=1.26.5", "GO_VERSION=1.26.6"
                ),
                encoding="utf-8",
                newline="\n",
            )
            with self.assertRaises(SystemExit):
                CREATE_MANIFEST.validate_tar(
                    path,
                    "remoteterminal",
                    VERSION,
                    COMMIT,
                    SOURCE_DATE_EPOCH,
                    source_dir,
                )

    def test_invalid_elf_is_rejected_even_when_payload_digest_matches(self) -> None:
        cases = (
            ("arm64-machine", 18, (183).to_bytes(2, "little")),
            ("missing-program-table", 56, (0).to_bytes(2, "little")),
        )
        for name, offset, replacement in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                bodies = websetupmanager_bodies()
                binary = bytearray(bodies["bin/websetupmanager"])
                binary[offset : offset + len(replacement)] = replacement
                bodies["bin/websetupmanager"] = bytes(binary)
                manifest = json.loads(bodies["manifest.json"])
                manifest["payload"][0]["sha256"] = sha256(bytes(binary))
                manifest["payload"][0]["size"] = len(binary)
                bodies["manifest.json"] = json_bytes(manifest)
                path, _ = self.make_tar(
                    Path(temporary), "websetupmanager", bodies
                )
                with self.assertRaises(SystemExit):
                    self.validate(path, "websetupmanager")

    def test_duplicate_inner_json_field_is_rejected(self) -> None:
        for location, arguments in (
            ("metadata", {"duplicate_metadata_version": True}),
            ("manifest", {"duplicate_manifest_version": True}),
        ):
            with self.subTest(location=location), tempfile.TemporaryDirectory() as temporary:
                path, _ = self.make_tar(
                    Path(temporary),
                    "websetupmanager",
                    websetupmanager_bodies(**arguments),
                )
                with self.assertRaises(SystemExit):
                    self.validate(path, "websetupmanager")

        with self.assertRaises(SystemExit):
            CREATE_MANIFEST.strict_json(
                b'{"outer":{"key":1,"key":2}}', "nested duplicate fixture"
            )
        nested = b"0"
        for _ in range(CREATE_MANIFEST.MAX_JSON_DEPTH + 1):
            nested = b"[" + nested + b"]"
        with self.assertRaises(SystemExit):
            CREATE_MANIFEST.strict_json(nested, "nested depth fixture")

    def test_missing_required_archive_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            def remove_metadata(entries):
                entries[:] = [item for item in entries if item["name"] != "metadata/version.json"]

            path, _ = self.make_tar(
                Path(temporary),
                "websetupmanager",
                websetupmanager_bodies(),
                remove_metadata,
            )
            with self.assertRaises(SystemExit):
                self.validate(path, "websetupmanager")

    def test_remote_terminal_identity_and_artifact_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            def tamper_identity(inputs):
                inputs["source"]["commit"] = "c" * 40

            path, _ = self.make_tar(
                Path(temporary),
                "remoteterminal",
                remote_terminal_bodies(inputs_mutator=tamper_identity),
            )
            with self.assertRaises(SystemExit):
                self.validate(path, "remoteterminal")

        with tempfile.TemporaryDirectory() as temporary:
            def tamper_artifact(manifest):
                manifest["artifacts"][1]["sha256"] = "0" * 64

            path, _ = self.make_tar(
                Path(temporary),
                "remoteterminal",
                remote_terminal_bodies(manifest_mutator=tamper_artifact),
            )
            with self.assertRaises(SystemExit):
                self.validate(path, "remoteterminal")

    def test_unsafe_paths_types_duplicates_modes_and_ownership_are_rejected(self) -> None:
        mutations = {
            "traversal": lambda entries: entries.append(
                {"name": "../escape", "type": tarfile.REGTYPE, "mode": 0o644, "body": b"x"}
            ),
            "symlink": lambda entries: entries.append(
                {"name": "bin/link", "type": tarfile.SYMTYPE, "mode": 0o755, "body": None}
            ),
            "duplicate": lambda entries: entries.append(copy.deepcopy(entries[1])),
            "writable": lambda entries: entries[1].__setitem__("mode", 0o777),
            "non-root": lambda entries: entries[1].__setitem__("uid", 1000),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                path, _ = self.make_tar(
                    Path(temporary), "websetupmanager", websetupmanager_bodies(), mutate
                )
                with self.assertRaises(SystemExit):
                    self.validate(path, "websetupmanager")

    def test_component_output_and_sidecar_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            asset = root / f"websetupmanager-{VERSION}-debian13-amd64.tar.zst"
            asset.write_bytes(b"asset")
            sidecar = Path(str(asset) + ".sha256")
            sidecar.write_text(f"{sha256(asset.read_bytes())}  {asset.name}\n", encoding="ascii")
            CREATE_MANIFEST.validate_component_output(root, "websetupmanager", VERSION)

            sidecar.write_text(f"{sha256(asset.read_bytes())} *{asset.name}\n", encoding="ascii")
            with self.assertRaises(SystemExit):
                CREATE_MANIFEST.validate_component_output(root, "websetupmanager", VERSION)
            sidecar.write_text(f"{sha256(asset.read_bytes())}  {asset.name}\n", encoding="ascii")
            (root / "extra").write_bytes(b"unexpected")
            with self.assertRaises(SystemExit):
                CREATE_MANIFEST.validate_component_output(root, "websetupmanager", VERSION)

    def test_strict_semver_rejects_leading_zeroes(self) -> None:
        for invalid in ("01.2.3", "1.02.3", "1.2.03", "1.2.3-01"):
            with self.subTest(version=invalid), self.assertRaises(SystemExit):
                CREATE_MANIFEST.require_semver(invalid, "test version")
        for valid in ("0.1.0", "1.2.3-rc.1+build.4"):
            self.assertEqual(CREATE_MANIFEST.require_semver(valid, "test version"), valid)

    def test_workflow_actions_are_pinned_to_full_commits(self) -> None:
        workflows = ROOT / ".github" / "workflows"
        actions = []
        workflow_files = sorted(
            path
            for path in workflows.iterdir()
            if path.suffix in {".yml", ".yaml"}
        )
        for workflow in workflow_files:
            for line in workflow.read_text(encoding="utf-8").splitlines():
                match = re.match(r"\s*-?\s*uses:\s*(\S+)\s*$", line)
                if match is not None and not match.group(1).startswith("./"):
                    actions.append((workflow.name, match.group(1)))
        self.assertTrue(actions)
        for workflow, action in actions:
            with self.subTest(workflow=workflow, action=action):
                self.assertRegex(action, r"^[^@\s]+@[0-9a-f]{40}$")

    def test_signer_compares_public_key_identity_as_der(self) -> None:
        script = (ROOT / "scripts" / "sign-and-publish-release.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('generated_public="$work_dir/release-public.der"', script)
        self.assertIn('committed_public="$work_dir/committed-public.der"', script)
        self.assertEqual(script.count("-outform DER"), 2)
        self.assertNotIn("release-public.pem", script)

    def test_bounded_decompressor_rejects_excess_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input"
            source.write_bytes(b"x" * 4096)
            compressed = root / "input.zst"
            subprocess.run(
                ["zstd", "--quiet", "-19", str(source), "-o", str(compressed)], check=True
            )
            result = subprocess.run(
                [
                    "python3",
                    str(ROOT / "scripts" / "decompress-zstd.py"),
                    str(compressed),
                    str(root / "output"),
                    "--maximum",
                    "1024",
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "output").exists())


if __name__ == "__main__":
    unittest.main()
