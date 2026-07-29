#!/usr/bin/env bash

set -euo pipefail

project_name="${1:?usage: scripts/release.sh PROJECT_NAME}"
repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

if [[ -n "$(git status --porcelain)" ]]; then
    echo "Refusing to release from a dirty working tree." >&2
    exit 1
fi

version="$(
    .venv/bin/python -c \
        'import pathlib, tomllib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])'
)"
expected_tag="$version"

if ! tagged_commit="$(git rev-parse --verify --quiet "refs/tags/${expected_tag}^{commit}")"; then
    echo "Required release tag ${expected_tag} does not exist." >&2
    exit 1
fi

head_commit="$(git rev-parse HEAD)"
if [[ "$tagged_commit" != "$head_commit" ]]; then
    echo "Tag ${expected_tag} does not point to HEAD." >&2
    exit 1
fi

if [[ -z "${PYPI_TOKEN:-}" ]]; then
    echo "PYPI_TOKEN is not set; refusing to upload." >&2
    exit 1
fi

wheel="dist/${project_name}-${version}-py3-none-any.whl"
sdist="dist/${project_name}-${version}.tar.gz"
if [[ ! -f "$wheel" || ! -f "$sdist" ]]; then
    echo "Expected release artifacts are missing:" >&2
    echo "  ${wheel}" >&2
    echo "  ${sdist}" >&2
    exit 1
fi

.venv/bin/python -m twine check "$wheel" "$sdist"

upload_arguments=(
    --username __token__
    --password "$PYPI_TOKEN"
)
if [[ -n "${PYPI_REPOSITORY_URL:-}" ]]; then
    upload_arguments+=(--repository-url "$PYPI_REPOSITORY_URL")
fi

.venv/bin/python -m twine upload "${upload_arguments[@]}" "$wheel" "$sdist"
