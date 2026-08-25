# LinuxCNC Setup — signed binary releases

This public repository contains immutable Debian 13 AMD64 binary releases for:

- `remoteterminal`
- `websetupmanager`

The application source repositories are private. The `linuxcncsetup` TUI remains
source-built on the target, but it downloads only a source-controlled, pinned
release of these two applications. ARM64 is intentionally unsupported.

## Trust model

Every release contains a deterministic `tar.zst` payload, its SHA-256 sidecar,
an exact JSON manifest, and a raw 64-byte Ed25519 signature over the manifest.
The TUI embeds both the public key and the SHA-256 of each approved manifest. It
does not consult a mutable `latest` URL.

The current public key is [`keys/release-2026-01.pem`](keys/release-2026-01.pem).
Its raw form is also recorded in [`keys/keyring.json`](keys/keyring.json) for the
Go verifier. The private key is held in the repository's encrypted Actions
secret and in the maintainer's local macOS Keychain; it is never committed.

## Manual publication

Publication is deliberately manual:

1. Test and tag the private component repository as `vX.Y.Z`.
2. Run the `publish-signed-release` workflow and select the component/version.
3. Review the resulting public release.
4. Pin its manifest URL, digest, version, and signing-key ID in the private TUI.

The workflow checks out the private tag using a component-specific read-only
deploy key, builds in pinned Debian 13 AMD64 containers, validates archive
safety, signs the exact manifest bytes, and refuses to replace an existing
release. Runtime updates happen only when an operator explicitly chooses the
install/update action in the TUI.

See [`docs/release-format.md`](docs/release-format.md) for the wire format and
local verification command.

