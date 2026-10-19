#!/usr/bin/env bash
# Explicit local administration of reviewed commits; never called by HTTP/model output.
# Parse the complete operation before executing: a checkout may be updated while
# the long-running candidate checks are still in progress.
main() {
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
operation="${1:-}"
if [[ "$operation" == rollback ]]; then
  prefix="${2:?Usage: release.sh rollback PRIVATE_PREFIX}"
else
  revision="${2:?Usage: release.sh prepare|activate FULL_COMMIT_SHA PRIVATE_PREFIX}"
  prefix="${3:?Private release directory required}"
  [[ "$revision" =~ ^[a-f0-9]{40}$ ]] || { echo 'Use a complete reviewed commit SHA.' >&2; exit 1; }
fi
[[ "$operation" == prepare || "$operation" == activate || "$operation" == rollback ]] || exit 1
umask 077
mkdir -p -- "$prefix/releases"
prefix="$(cd -- "$prefix" && pwd -P)"
[[ ! -L "$prefix/releases" ]] || { echo 'Release directory must not be a symlink.' >&2; exit 1; }
[[ "$(stat -c %a "$prefix")" == 700 && "$(stat -c %a "$prefix/releases")" == 700 ]] || { echo 'Private directories must have mode 0700.' >&2; exit 1; }
exec 9>"$prefix/.release-lock"
flock -n 9 || { echo 'Another release operation is running.' >&2; exit 1; }
verify_release() {
  local selected="$1"
  [[ "$selected" =~ ^[a-f0-9]{40}$ && ! -L "$prefix/releases/$selected" && -f "$prefix/releases/$selected/.ready" ]] || return 1
  [[ "$(cat "$prefix/releases/$selected/.ready")" == "$selected" ]] || return 1
  (cd -- "$prefix/releases/$selected" && sha256sum --quiet --check .release-sha256)
}
switch_to() {
  local selected="$1"
  verify_release "$selected" || { echo 'Release is missing, untested or modified.' >&2; exit 1; }
  [[ ! -e "$prefix/current" || -L "$prefix/current" ]] || { echo 'current must be a managed symlink.' >&2; exit 1; }
  local old=""
  [[ ! -e "$prefix/previous" || -L "$prefix/previous" ]] || { echo 'previous must be a managed symlink.' >&2; exit 1; }
  if [[ -L "$prefix/current" ]]; then
    old="$(readlink -- "$prefix/current")"
    [[ "$old" =~ ^releases/[a-f0-9]{40}$ ]] || exit 1
  fi
  if [[ "$old" == "releases/$selected" ]]; then
    echo 'This release is already selected.'
    return
  fi
  # A damaged current release must not prevent recovery to a verified one.
  # Keep the last verified previous target instead of promoting damaged code.
  if [[ -n "$old" ]] && verify_release "${old#releases/}"; then
    ln -s -- "$old" "$prefix/.previous-$$"
    mv -Tf -- "$prefix/.previous-$$" "$prefix/previous"
  fi
  ln -s -- "releases/$selected" "$prefix/.current-$$"
  mv -Tf -- "$prefix/.current-$$" "$prefix/current"
  echo 'Release selected. Start current/scripts/start.sh with your existing external --data directory.'
}
case "$operation" in
  prepare)
    command -v node >/dev/null
    command -v chromium >/dev/null
    [[ "$(git -C "$project_dir" rev-parse --verify "$revision^{commit}")" == "$revision" ]]
    git -C "$project_dir" merge-base --is-ancestor "$revision" origin/main
    stage="$prefix/releases/$revision"
    [[ ! -e "$stage" && ! -L "$stage" ]] || { echo 'Release directory already exists; use a new commit or inspect the existing release.' >&2; exit 1; }
    mkdir -- "$stage"
    # Reviewed repository code is trusted and executes during tests. No runtime data is copied.
    git -C "$project_dir" archive "$revision" | tar -x -C "$stage"
    cd -- "$stage"
    git -C "$project_dir" archive "$revision" | tar -tf - | while IFS= read -r file; do
      [[ "$file" == */ ]] || sha256sum -- "$file"
    done > .release-sha256
    python3 -m venv .venv
    .venv/bin/python -m pip install --cache-dir "$prefix/pip-cache" --disable-pip-version-check --require-hashes -r requirements.lock
    .venv/bin/python scripts/build_requirements.py --check
    .venv/bin/python -m unittest discover -v
    node --check cyber_platform/static/app.js
    python3 -m venv .checks
    .checks/bin/python -m pip install --cache-dir "$prefix/pip-cache" --disable-pip-version-check -r requirements-security.txt playwright==1.58.0
    .checks/bin/python -m pip install --cache-dir "$prefix/pip-cache" --require-hashes -r requirements.lock
    .checks/bin/bandit -r cyber_platform
    .checks/bin/pip-audit --require-hashes --disable-pip --strict -r requirements.lock --cache-dir "$prefix/audit-cache"
    .checks/bin/python -m tests.browser_smoke
    .venv/bin/python -m pip wheel --cache-dir "$prefix/pip-cache" --no-deps --wheel-dir .state/dist .
    sha256sum --quiet --check .release-sha256
    printf '%s\n' "$revision" > .ready
    echo 'All required checks passed. This release is prepared but not activated.'
    ;;
  activate) switch_to "$revision" ;;
  rollback)
    [[ -L "$prefix/previous" ]] || { echo 'No previous release exists.' >&2; exit 1; }
    previous="$(readlink -- "$prefix/previous")"
    [[ "$previous" =~ ^releases/[a-f0-9]{40}$ ]] || exit 1
    switch_to "${previous#releases/}"
    ;;
esac
}
main "$@"; exit $?
