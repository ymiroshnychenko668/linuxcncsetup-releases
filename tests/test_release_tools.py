from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "create_manifest", ROOT / "scripts" / "create-manifest.py"
)
assert SPEC is not None and SPEC.loader is not None
CREATE_MANIFEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CREATE_MANIFEST)


def add_file(archive: tarfile.TarFile, name: str, content: bytes, mode: int = 0o644) -> None:
    entry = tarfile.TarInfo(name)
    entry.mode = mode
    entry.uid = 0
    entry.gid = 0
    entry.size = len(content)
    archive.addfile(entry, io.BytesIO(content))


def add_directory(archive: tarfile.TarFile, name: str) -> None:
    entry = tarfile.TarInfo(name)
    entry.type = tarfile.DIRTYPE
    entry.mode = 0o755
    entry.uid = 0
    entry.gid = 0
    archive.addfile(entry)


class ManifestTests(unittest.TestCase):
    def make_remote_terminal_tar(self, directory: Path) -> tuple[Path, int]:
        path = directory / "payload.tar"
        bodies = {
            "bin/remoteterminal": b"application",
            "bin/ttyd": b"ttyd",
            "licenses/ttyd-LICENSE": b"license\n",
            "manifest.json": b"{}\n",
            "metadata/build-inputs.json": b"{}\n",
        }
        with tarfile.open(path, "w:") as archive:
            add_directory(archive, "bin")
            add_directory(archive, "licenses")
            add_directory(archive, "metadata")
            for name, content in bodies.items():
                add_file(archive, name, content, 0o755 if name.startswith("bin/") else 0o644)
        return path, sum(map(len, bodies.values()))

    def test_valid_archive_and_canonical_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tar_path, expected_unpacked = self.make_remote_terminal_tar(root)
            asset = root / "remoteterminal-1.2.3-debian13-amd64.tar.zst"
            subprocess.run(
                ["zstd", "--quiet", "-19", str(tar_path), "-o", str(asset)], check=True
            )
            output = root / "manifest.json"
            url = (
                "https://github.com/ymiroshnychenko668/linuxcncsetup-releases/"
                "releases/download/remoteterminal-v1.2.3/"
                "remoteterminal-1.2.3-debian13-amd64.tar.zst"
            )
            subprocess.run(
                [
                    "python3",
                    str(ROOT / "scripts" / "create-manifest.py"),
                    "--product",
                    "remoteterminal",
                    "--version",
                    "1.2.3",
                    "--asset",
                    str(asset),
                    "--tar",
                    str(tar_path),
                    "--url",
                    url,
                    "--output",
                    str(output),
                ],
                check=True,
            )
            raw = output.read_bytes()
            self.assertTrue(raw.endswith(b"\n"))
            value = json.loads(raw)
            self.assertEqual(value["asset"]["unpacked_size"], expected_unpacked)
            self.assertEqual(value["platform"]["architecture"], "amd64")

    def test_traversal_symlink_duplicate_and_unsafe_mode_are_rejected(self) -> None:
        cases = {
            "traversal": [("../escape", tarfile.REGTYPE, 0o644)],
            "symlink": [("bin/link", tarfile.SYMTYPE, 0o755)],
            "duplicate": [
                ("bin/remoteterminal", tarfile.REGTYPE, 0o755),
                ("bin/remoteterminal", tarfile.REGTYPE, 0o755),
            ],
            "writable": [("bin/remoteterminal", tarfile.REGTYPE, 0o777)],
        }
        for name, entries in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "unsafe.tar"
                with tarfile.open(path, "w:") as archive:
                    for entry_name, entry_type, mode in entries:
                        entry = tarfile.TarInfo(entry_name)
                        entry.type = entry_type
                        entry.mode = mode
                        if entry_type == tarfile.SYMTYPE:
                            entry.linkname = "/etc/passwd"
                        else:
                            entry.size = 1
                        archive.addfile(entry, None if entry_type == tarfile.SYMTYPE else io.BytesIO(b"x"))
                with self.assertRaises(SystemExit):
                    CREATE_MANIFEST.validate_tar(path, "remoteterminal")

    def test_extra_missing_and_non_root_entries_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid, _ = self.make_remote_terminal_tar(root)

            missing = root / "missing.tar"
            with tarfile.open(missing, "w:") as archive:
                add_directory(archive, "bin")
                add_file(archive, "bin/remoteterminal", b"app", 0o755)
            with self.assertRaises(SystemExit):
                CREATE_MANIFEST.validate_tar(missing, "remoteterminal")

            extra = root / "extra.tar"
            with tarfile.open(valid, "r:") as source, tarfile.open(extra, "w:") as destination:
                for member in source:
                    payload = source.extractfile(member) if member.isfile() else None
                    destination.addfile(member, payload)
                add_file(destination, "unexpected", b"x")
            with self.assertRaises(SystemExit):
                CREATE_MANIFEST.validate_tar(extra, "remoteterminal")

            non_root = root / "non-root.tar"
            with tarfile.open(valid, "r:") as source, tarfile.open(non_root, "w:") as destination:
                for member in source:
                    payload = source.extractfile(member) if member.isfile() else None
                    if member.name == "manifest.json":
                        member.uid = 1000
                    destination.addfile(member, payload)
            with self.assertRaises(SystemExit):
                CREATE_MANIFEST.validate_tar(non_root, "remoteterminal")

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
