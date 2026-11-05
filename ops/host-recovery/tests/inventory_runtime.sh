#!/usr/bin/env bash
# Read-only prerequisite inventory. Never query a daemon or start a runtime.
set -euo pipefail

if [[ ${GITHUB_ACTIONS:-} != true || ${RUNNER_ENVIRONMENT:-} != github-hosted ||
      $# != 2 || ! $1 =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' 'runtime inventory requires a disposable hosted Actions runner, exact source SHA and Go reader' >&2
  exit 2
fi

# The setup-go reader only inspects build metadata; it never builds or runs the
# inspected program. Do not resolve it through an inherited executable search path.
go_reader="$(readlink -e -- "$2")"
case "$go_reader" in
  /opt/hostedtoolcache/go/*/x64/bin/go|/usr/local/go/bin/go) ;;
  *) printf '%s\n' 'unsupported Go metadata reader' >&2; exit 2 ;;
esac
if [[ ! -f $go_reader || ! -x $go_reader ||
      ( $(stat -c %u -- "$go_reader") != 0 && $(stat -c %u -- "$go_reader") != "$EUID" ) ||
      $(find "$go_reader" -maxdepth 0 -perm /022 -print) != '' ]]; then
  printf '%s\n' 'unprotected Go metadata reader' >&2
  exit 2
fi
reader_before="$(sha256sum -- "$go_reader")"

export PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C
export GOENV=off GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG CONTAINERD_ADDRESS CONTAINERD_NAMESPACE
printf 'schema=host-recovery-runtime-inventory-v1\nsource_revision=%s\n' "$1"
printf '%s\n' 'qualification=not_performed' 'source_mapping_verified=false' \
  'dedicated_runtime_provisioned=false' 'containment_qualified=false' \
  'complete_fence_proven=false' 'start_allowed=false' 'production_acceptance=false'
printf 'kernel_release=%s\narchitecture=%s\n' "$(uname -r)" "$(uname -m)"
printf 'pid1=%s\ncgroup_filesystem=%s\n' "$(</proc/1/comm)" "$(stat -f -c %T /sys/fs/cgroup)"
printf 'go_metadata_reader=%s\ngo_metadata_reader_sha256=%s\n' "$go_reader" "${reader_before%% *}"
timeout 5s "$go_reader" version

failed=0
for tool in dockerd containerd containerd-shim-runc-v2 runc docker ctr systemd; do
  printf '\n[tool:%s]\n' "$tool"
  if ! executable="$(command -v "$tool")"; then
    printf '%s\n' 'state=missing'
    failed=1
    continue
  fi
  executable="$(readlink -e -- "$executable")"
  # These are the hosted image's tools, never executables from the checkout,
  # a runtime socket, an inherited PATH entry or an installer download.
  case "$executable" in
    /usr/bin/*|/usr/sbin/*|/usr/lib/systemd/systemd) ;;
    *) printf '%s\n' 'state=unsupported_executable_location'; failed=1; continue ;;
  esac
  if [[ ! -f $executable || ! -x $executable ||
        $(stat -c %u -- "$executable") != 0 ||
        $(find "$executable" -maxdepth 0 -perm /022 -print) != '' ]]; then
    printf '%s\n' 'state=unprotected_executable'
    failed=1
    continue
  fi
  before="$(sha256sum -- "$executable")"
  printf 'path=%s\nsha256=%s\nversion_begin\n' "$executable" "${before%% *}"
  # --version is local for every tool in this fixed list. In particular, do
  # not use `docker version`, `ctr version`, `info`, `ps`, or socket discovery.
  if ! timeout 5s "$executable" --version; then
    printf '%s\n' 'state=version_failed'
    failed=1
  fi
  printf '%s\n' 'version_end'
  if [[ $tool != systemd ]]; then
    printf '%s\n' 'go_build_metadata_begin'
    if ! timeout 5s "$go_reader" version -m "$executable"; then
      printf '%s\n' 'state=go_metadata_read_failed'
      failed=1
    fi
    printf '%s\n' 'go_build_metadata_end'
  fi
  after="$(sha256sum -- "$executable")"
  if [[ $before != "$after" ]]; then
    printf '%s\n' 'state=executable_changed'
    failed=1
  fi
done

reader_after="$(sha256sum -- "$go_reader")"
if [[ $reader_before != "$reader_after" ]]; then
  printf '%s\n' 'state=go_metadata_reader_changed'
  failed=1
fi
printf '\ninventory_complete=true\nrequired_tools_present_and_read=%s\n' "$((1-failed))"
exit "$failed"
