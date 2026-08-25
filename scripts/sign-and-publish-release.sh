#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

if (($# != 4)); then
    printf 'usage: %s COMPONENT VERSION SOURCE_DIR DIST_DIR\n' "$0" >&2
    exit 2
fi

component=$1
version=$2
source_dir=$(cd -- "$3" && pwd)
dist_dir=$(cd -- "$4" && pwd)
repository_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ "$component" == remoteterminal || "$component" == websetupmanager ]]
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?(\+[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]
[[ -n "${RELEASE_SIGNING_PRIVATE_KEY:-}" ]] || {
    printf 'RELEASE_SIGNING_PRIVATE_KEY is unavailable\n' >&2
    exit 1
}

source_tag="v${version}"
source_commit=$(git -C "$source_dir" rev-parse --verify HEAD)
git -C "$source_dir" tag --points-at "$source_commit" | grep -Fx -- "$source_tag" >/dev/null
release_tag="${component}-v${version}"
if gh release view "$release_tag" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
    printf 'release already exists and will not be overwritten: %s\n' "$release_tag" >&2
    exit 1
fi

asset_name="${component}-${version}-debian13-amd64.tar.zst"
asset="$dist_dir/$asset_name"
sidecar="$asset.sha256"
manifest="$dist_dir/${component}-${version}-debian13-amd64.manifest.json"
signature="$dist_dir/${component}-${version}-debian13-amd64.manifest.sig"
for path in "$asset" "$sidecar" "$manifest"; do
    [[ -f "$path" && ! -L "$path" ]] || {
        printf 'missing regular release input: %s\n' "$path" >&2
        exit 1
    }
done
[[ ! -e "$signature" && ! -L "$signature" ]] || {
    printf 'signature output already exists\n' >&2
    exit 1
}
(
    cd "$dist_dir"
    sha256sum --check --status "$(basename -- "$sidecar")"
)

work_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/linuxcnc-sign.XXXXXX")
cleanup() {
    rm -rf -- "$work_dir"
}
trap cleanup EXIT
tar_path="$work_dir/payload.tar"
python3 "$repository_dir/scripts/decompress-zstd.py" \
    "$asset" "$tar_path" --maximum $((5 << 30))
canonical_manifest="$work_dir/manifest.json"
asset_url="https://github.com/$GITHUB_REPOSITORY/releases/download/$release_tag/$asset_name"
python3 "$repository_dir/scripts/create-manifest.py" \
    --product "$component" --version "$version" --asset "$asset" \
    --tar "$tar_path" --url "$asset_url" --output "$canonical_manifest"
cmp --silent "$manifest" "$canonical_manifest" || {
    printf 'unsigned manifest changed after the isolated build step\n' >&2
    exit 1
}

private_key="$work_dir/release-private.pem"
printf '%s' "$RELEASE_SIGNING_PRIVATE_KEY" > "$private_key"
chmod 0600 "$private_key"
generated_public="$work_dir/release-public.pem"
openssl pkey -in "$private_key" -pubout -out "$generated_public"
cmp --silent "$generated_public" "$repository_dir/keys/release-2026-01.pem" || {
    printf 'signing secret does not match the committed public key\n' >&2
    exit 1
}
openssl pkeyutl -sign -rawin -inkey "$private_key" -in "$manifest" -out "$signature"
chmod 0644 "$signature"
[[ $(wc -c < "$signature" | tr -d ' ') == 64 ]]
openssl pkeyutl -verify -pubin \
    -inkey "$repository_dir/keys/release-2026-01.pem" \
    -rawin -in "$manifest" -sigfile "$signature" >/dev/null
"$repository_dir/scripts/verify-release.sh" "$manifest" "$signature" "$asset"

notes="$work_dir/notes.md"
{
    printf '# %s %s\n\n' "$component" "$version"
    printf -- '- Target: Debian 13 AMD64\n'
    printf -- '- Private source tag: `%s`\n' "$source_tag"
    printf -- '- Private source commit: `%s`\n' "$source_commit"
    printf -- '- Signing key: `release-2026-01`\n'
    printf -- '- Update policy: manual, via the pinned `linuxcncsetup` TUI\n'
} > "$notes"

gh release create "$release_tag" \
    --repo "$GITHUB_REPOSITORY" \
    --target "$GITHUB_SHA" \
    --title "$component $version — Debian 13 AMD64" \
    --notes-file "$notes" \
    "$asset" "$sidecar" "$manifest" "$signature"

