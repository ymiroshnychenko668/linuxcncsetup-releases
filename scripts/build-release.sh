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
dist_input=$4
repository_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ "$component" == remoteterminal || "$component" == websetupmanager ]] || {
    printf 'unsupported component: %s\n' "$component" >&2
    exit 1
}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?(\+[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]] || {
    printf 'version must use semantic version syntax\n' >&2
    exit 1
}

source_tag="v${version}"
source_commit=$(git -C "$source_dir" rev-parse --verify HEAD)
git -C "$source_dir" tag --points-at "$source_commit" | grep -Fx -- "$source_tag" >/dev/null || {
    printf 'checked-out source is not exact tag %s\n' "$source_tag" >&2
    exit 1
}
source_epoch=$(git -C "$source_dir" show -s --format=%ct "$source_commit")

mkdir -p -- "$dist_input"
dist_dir=$(cd -- "$dist_input" && pwd)
if find "$dist_dir" -mindepth 1 -print -quit | grep -q .; then
    printf 'distribution directory must be empty: %s\n' "$dist_dir" >&2
    exit 1
fi

docker buildx build \
    --platform linux/amd64 \
    --file "$source_dir/release/Dockerfile.debian13-amd64" \
    --build-arg "RELEASE_VERSION=$version" \
    --build-arg "BUILD_COMMIT=$source_commit" \
    --build-arg "SOURCE_DATE_EPOCH=$source_epoch" \
    --output "type=local,dest=$dist_dir" \
    "$source_dir"

asset_name="${component}-${version}-debian13-amd64.tar.zst"
asset="$dist_dir/$asset_name"
sidecar="$asset.sha256"
[[ -f "$asset" && ! -L "$asset" && -f "$sidecar" && ! -L "$sidecar" ]] || {
    printf 'component build did not produce the expected release files\n' >&2
    exit 1
}
if find "$dist_dir" -mindepth 1 -maxdepth 1 ! -type f -print -quit | grep -q .; then
    printf 'component output contains a non-regular top-level entry\n' >&2
    exit 1
fi
(
    cd "$dist_dir"
    sha256sum --check --status "$(basename -- "$sidecar")"
)

tar_path="$dist_dir/.payload.tar"
python3 "$repository_dir/scripts/decompress-zstd.py" \
    "$asset" "$tar_path" --maximum $((5 << 30))
manifest_name="${component}-${version}-debian13-amd64.manifest.json"
manifest="$dist_dir/$manifest_name"
release_tag="${component}-v${version}"
asset_url="https://github.com/$GITHUB_REPOSITORY/releases/download/$release_tag/$asset_name"
python3 "$repository_dir/scripts/create-manifest.py" \
    --product "$component" \
    --version "$version" \
    --asset "$asset" \
    --tar "$tar_path" \
    --url "$asset_url" \
    --output "$manifest"
rm -f -- "$tar_path"
chmod 0644 "$asset" "$sidecar" "$manifest"
printf 'Built and validated unsigned %s %s payload\n' "$component" "$version"

