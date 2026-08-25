# Release format

The signed manifest schema is intentionally small and strict:

```json
{
  "asset": {
    "format": "tar.zst",
    "name": "remoteterminal-1.2.3-debian13-amd64.tar.zst",
    "sha256": "<64 lowercase hex characters>",
    "size": 123,
    "unpacked_size": 456,
    "url": "https://github.com/ymiroshnychenko668/linuxcncsetup-releases/releases/download/remoteterminal-v1.2.3/remoteterminal-1.2.3-debian13-amd64.tar.zst"
  },
  "platform": {
    "architecture": "amd64",
    "distribution": "debian",
    "distribution_version": "13",
    "os": "linux"
  },
  "product": "remoteterminal",
  "schema": 1,
  "version": "1.2.3"
}
```

The detached `.manifest.sig` file is the raw 64-byte Ed25519 signature over
the exact `.manifest.json` bytes. `unpacked_size` is the exact sum of the byte
sizes of all regular files in the tar archive; tar framing and directories are
not included.

The payload has no outer version directory. Remote Terminal contains exactly
`bin/remoteterminal`, `bin/ttyd`, `licenses/ttyd-LICENSE`,
`metadata/build-inputs.json`, `manifest.json`, and their three parent
directories. Web Setup Manager contains exactly `bin/websetupmanager`,
`metadata/version.json`, `manifest.json`, and their two parent directories.
Files must be root-owned and use their contract modes (`0755` for executables,
`0644` for data); directories are root-owned `0755`. Extra paths, links,
devices, traversal, duplicates, control characters, and mode/ownership drift
are rejected before publication. The TUI independently rejects unsafe archive
entries while extracting the signed payload.

The raw tar is canonical USTAR in the exact inventory order. Only physical
regular-file type flags (`0` and the legacy NUL spelling) and directory type
`5` are accepted; PAX/GNU extension headers and non-canonical trailing records
are rejected. Every required file must be non-empty. Remote Terminal bounds
each of its application and `ttyd` binaries at 100 MiB, its build metadata and
license at 1 MiB, its inner manifest at 128 KiB, and the sum of all regular
files at 100 MiB. Web Setup Manager bounds its binary at 256 MiB, both JSON
files at 1 MiB, and their total regular-file size at 258 MiB.

Before signing, the public workflow independently parses both inner JSON files
with duplicate-key rejection. It binds their product, strict semantic version,
Debian target, source commit and timestamp to the checked-out private tag,
checks every payload size and digest, and validates Web Setup Manager's ordered
SQLite migration identities and canonical migration-set digest against the
checked-out SQL files. Remote Terminal's source-tree, release-input and pinned
toolchain identities are likewise recomputed from its checkout. Executables
must be structurally valid ELF64 little-endian AMD64 files with an executable
load segment. The component build output is exactly the asset plus a canonical
one-line `.sha256` sidecar; additional
scratch output is rejected.

To verify downloaded assets locally (requires Python 3, OpenSSL, and zstd):

```sh
./scripts/verify-release.sh \
  remoteterminal-1.2.3-debian13-amd64.manifest.json \
  remoteterminal-1.2.3-debian13-amd64.manifest.sig \
  remoteterminal-1.2.3-debian13-amd64.tar.zst
```
