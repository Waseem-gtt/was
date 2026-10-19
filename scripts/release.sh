#!/usr/bin/env bash
# Explicit local administration of reviewed commits; never called by HTTP/model output.
# Parse the complete operation before executing: a checkout may be updated while
# the long-running candidate checks are still in progress.
main() {
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
release_python="$project_dir/.venv/bin/python"
if [[ ! -x "$release_python" ]]; then
  release_python="$(command -v python3)"
fi
operation="${1:-}"
signed_manifest=""
signed_trust=""
signature_pin=""
if [[ "$operation" == rollback ]]; then
  prefix="${2:?Usage: release.sh rollback PRIVATE_PREFIX}"
  [[ $# == 2 ]] || { echo 'Rollback accepts only the private prefix.' >&2; exit 1; }
else
  revision="${2:?Usage: release.sh prepare|activate FULL_COMMIT_SHA PRIVATE_PREFIX}"
  prefix="${3:?Private release directory required}"
  [[ "$revision" =~ ^[a-f0-9]{40}$ ]] || { echo 'Use a complete reviewed commit SHA.' >&2; exit 1; }
  if [[ $# == 6 && "$4" == --signed ]]; then
    signed_manifest="$(realpath -s -- "$5")"
    signed_trust="$(realpath -s -- "$6")"
  elif [[ $# != 3 ]]; then
    echo 'Usage: release.sh prepare|activate SHA PREFIX [--signed ENVELOPE TRUST]' >&2
    exit 1
  fi
fi
[[ "$operation" == prepare || "$operation" == activate || "$operation" == rollback ]] || exit 1
umask 077
mkdir -p -- "$prefix/releases"
prefix="$(cd -- "$prefix" && pwd -P)"
[[ ! -L "$prefix/releases" ]] || { echo 'Release directory must not be a symlink.' >&2; exit 1; }
[[ "$(stat -c %a "$prefix")" == 700 && "$(stat -c %a "$prefix/releases")" == 700 ]] || { echo 'Private directories must have mode 0700.' >&2; exit 1; }
exec 9>"$prefix/.release-lock"
flock -n 9 || { echo 'Another release operation is running.' >&2; exit 1; }
if [[ -e "$prefix/.require-signatures" || -L "$prefix/.require-signatures" ]]; then
  if [[ "$operation" != rollback && -z "$signed_manifest" ]]; then
    echo 'This prefix requires a signed manifest and its pinned trust keys.' >&2
    exit 1
  fi
  if [[ ! -f "$prefix/.require-signatures" || -L "$prefix/.require-signatures" || "$(stat -c %a "$prefix/.require-signatures")" != 600 || "$(stat -c %h "$prefix/.require-signatures")" != 1 || "$(stat -c %u "$prefix/.require-signatures")" != "$(id -u)" || "$(stat -c %s "$prefix/.require-signatures")" != 65 ]]; then
    echo 'Signature policy is unsafe or corrupted.' >&2
    exit 1
  fi
  IFS= read -r signature_pin < "$prefix/.require-signatures"
  [[ "$signature_pin" =~ ^[a-f0-9]{64}$ ]] || exit 1
fi
verify_signature() {
  local record="${1:-check}" result digest
  local args=("$release_python" -m cyber_platform.release_admin verify "$signed_manifest" "$signed_trust" --commit "$revision" --state "$prefix/signature-state")
  [[ -z "$signature_pin" ]] || args+=(--trust-digest "$signature_pin")
  [[ "$record" != record ]] || args+=(--record)
  result="$(cd -- "$project_dir" && "${args[@]}")"
  digest="$("$release_python" -c 'import json,sys; print(json.load(sys.stdin)["trust_digest"])' <<< "$result")"
  [[ "$digest" =~ ^[a-f0-9]{64}$ ]] || exit 1
  if [[ -z "$signature_pin" ]]; then
    # Persist the verified trust fingerprint before enabling signed activation.
    "$release_python" - "$prefix" "$digest" <<'PY'
import os,sys
directory=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
    fd=os.open('.require-signatures',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
    try:
        data=(sys.argv[2]+'\n').encode('ascii')
        with os.fdopen(fd,'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.fsync(directory)
finally:
    os.close(directory)
PY
    signature_pin="$digest"
  fi
  echo 'Signed release metadata and pinned trust verified.'
}
if [[ -n "$signed_manifest" ]]; then
  verify_signature check
fi
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
  if [[ "$operation" != rollback && -n "$signed_manifest" ]]; then
    # Advance the high-water mark only for an otherwise eligible activation.
    # An identical retry is accepted if a crash happens before symlink switching.
    verify_signature record
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
    if [[ -f scripts/verify_wheel.py ]]; then
      .venv/bin/python -m pip install --no-deps --no-index --target .state/wheel-check .state/dist/*.whl
      .venv/bin/python scripts/verify_wheel.py .state/wheel-check
    fi
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
