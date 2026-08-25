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

To verify downloaded assets locally (requires Python 3, OpenSSL, and zstd):

```sh
./scripts/verify-release.sh \
  remoteterminal-1.2.3-debian13-amd64.manifest.json \
  remoteterminal-1.2.3-debian13-amd64.manifest.sig \
  remoteterminal-1.2.3-debian13-amd64.tar.zst
```
