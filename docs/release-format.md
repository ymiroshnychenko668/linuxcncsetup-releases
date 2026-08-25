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
the exact `.manifest.json` bytes. The payload has no outer version directory;
its paths begin with `bin/`, `metadata/`, `licenses/`, or `manifest.json`.
Links, devices, path traversal, duplicate names, and group/world-writable files
are rejected both before publication and during TUI extraction.

To verify downloaded assets locally (requires Python 3, OpenSSL, and zstd):

```sh
./scripts/verify-release.sh \
  remoteterminal-1.2.3-debian13-amd64.manifest.json \
  remoteterminal-1.2.3-debian13-amd64.manifest.sig \
  remoteterminal-1.2.3-debian13-amd64.tar.zst
```

