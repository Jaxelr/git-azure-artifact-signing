#!/usr/bin/env bash

set -euo pipefail

metadata_path="${1:-${ACS_METADATA_PATH:-}}"
principal="${2:-}"

if [[ -z "$metadata_path" ]]; then
    echo "Usage: $0 <metadata-path> [signing-principal]" >&2
    echo "Alternatively, set ACS_METADATA_PATH." >&2
    exit 2
fi

if [[ ! -f "$metadata_path" ]]; then
    echo "Metadata file not found: $metadata_path" >&2
    exit 1
fi

repository_root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "Run this script from inside the Git repository." >&2
    exit 1
}
git_directory="$(git rev-parse --path-format=absolute --git-dir)"
output_directory="$git_directory/artifact-signing"
signer_path="$output_directory/git-acs-sign"
metadata_path="$(realpath "$metadata_path")"

mkdir -p "$output_directory"

(
    cd "$repository_root"
    go build -o "$signer_path" ./cmd/git-acs-sign
)

setup_arguments=(
    setup
    --metadata "$metadata_path"
    --program "$signer_path"
)
if [[ -n "$principal" ]]; then
    setup_arguments+=(--principal "$principal")
fi

"$signer_path" "${setup_arguments[@]}"
