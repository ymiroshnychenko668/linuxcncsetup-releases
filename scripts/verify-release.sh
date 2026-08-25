#!/usr/bin/env bash

set -Eeuo pipefail

if (($# != 3)); then
    printf 'usage: %s MANIFEST SIGNATURE ASSET\n' "$0" >&2
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_dir=$(cd -- "$script_dir/.." && pwd)
manifest=$1
signature=$2
asset=$3

for path in "$manifest" "$signature" "$asset"; do
    [[ -f "$path" && ! -L "$path" ]] || {
        printf 'not a regular file: %s\n' "$path" >&2
        exit 1
    }
done

[[ $(wc -c < "$signature" | tr -d ' ') == 64 ]] || {
    printf 'signature is not 64 raw bytes\n' >&2
    exit 1
}
openssl pkeyutl -verify -pubin \
    -inkey "$repository_dir/keys/release-2026-01.pem" \
    -rawin -in "$manifest" -sigfile "$signature" >/dev/null

readarray -t metadata < <(python3 - "$manifest" "$asset" <<'PY'
import hashlib
import json
import os
import sys

manifest_path, asset_path = sys.argv[1:]
with open(manifest_path, "rb") as source:
    raw = source.read()
value = json.loads(raw)
if value.get("schema") != 1 or value.get("asset", {}).get("format") != "tar.zst":
    raise SystemExit("unsupported release manifest")
if value["asset"]["name"] != os.path.basename(asset_path):
    raise SystemExit("asset name does not match manifest")
digest = hashlib.sha256()
with open(asset_path, "rb") as source:
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
if digest.hexdigest() != value["asset"]["sha256"]:
    raise SystemExit("asset SHA-256 does not match manifest")
if os.path.getsize(asset_path) != value["asset"]["size"]:
    raise SystemExit("asset size does not match manifest")
print(value["product"])
print(value["version"])
print(value["asset"]["unpacked_size"])
PY
)
[[ ${#metadata[@]} == 3 ]]

temporary_tar=$(mktemp "${TMPDIR:-/tmp}/linuxcnc-release-verify.XXXXXX.tar")
temporary_manifest="${temporary_tar%.tar}.json"
cleanup() {
    rm -f -- "$temporary_tar" "$temporary_manifest"
}
trap cleanup EXIT
zstd --quiet --test "$asset"
rm -f -- "$temporary_tar"
case "${metadata[0]}" in
    remoteterminal) tar_maximum=$((101 << 20)) ;;
    websetupmanager) tar_maximum=$((259 << 20)) ;;
    *)
        printf 'unsupported product in release manifest\n' >&2
        exit 1
        ;;
esac
python3 "$repository_dir/scripts/decompress-zstd.py" \
    "$asset" "$temporary_tar" --maximum "$tar_maximum"
python3 "$repository_dir/scripts/create-manifest.py" \
    --product "${metadata[0]}" \
    --version "${metadata[1]}" \
    --asset "$asset" \
    --tar "$temporary_tar" \
    --url "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["asset"]["url"])' "$manifest")" \
    --output "$temporary_manifest"
cmp --silent "$manifest" "$temporary_manifest" || {
    printf 'manifest is not canonical or unpacked size differs\n' >&2
    exit 1
}
printf 'Verified %s %s for Debian 13 AMD64\n' "${metadata[0]}" "${metadata[1]}"
