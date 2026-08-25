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
semver_pattern='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
[[ "$version" =~ $semver_pattern ]] || {
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
if [[ "$component" == remoteterminal ]]; then
    tar_maximum=$((101 << 20))
else
    tar_maximum=$((259 << 20))
fi

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
python3 "$repository_dir/scripts/create-manifest.py" \
    --product "$component" \
    --version "$version" \
    --component-output "$dist_dir"

tar_path="$dist_dir/.payload.tar"
python3 "$repository_dir/scripts/decompress-zstd.py" \
    "$asset" "$tar_path" --maximum "$tar_maximum"
manifest_name="${component}-${version}-debian13-amd64.manifest.json"
manifest="$dist_dir/$manifest_name"
release_tag="${component}-v${version}"
asset_url="https://github.com/$GITHUB_REPOSITORY/releases/download/$release_tag/$asset_name"
python3 "$repository_dir/scripts/create-manifest.py" \
    --product "$component" \
    --version "$version" \
    --asset "$asset" \
    --sidecar "$sidecar" \
    --tar "$tar_path" \
    --url "$asset_url" \
    --source-commit "$source_commit" \
    --source-date-epoch "$source_epoch" \
    --source-dir "$source_dir" \
    --output "$manifest"
rm -f -- "$tar_path"
chmod 0644 "$asset" "$sidecar" "$manifest"
printf 'Built and validated unsigned %s %s payload\n' "$component" "$version"
