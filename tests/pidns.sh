#!/usr/bin/env bash
# PID-namespace isolation tests. Linux-only; auto-skip elsewhere.
#
# These verify the actual confinement properties: the sandboxed process
# can't see, signal, or affect host processes.
set -uo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/lib.sh
source "$DIR/lib.sh"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "pidns.sh: not Linux, skipping entire suite"
  exit 0
fi

require_tools true echo sleep sh cat ps wc kill grep

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Helper: invoke uj with the standard sandbox triplet plus --best-effort,
# so tests work even when unprivileged user namespaces are disabled (we
# fall through to no-PID-isolation and skip those checks loudly).
uj() {
  "$BIN" --best-effort --system-ro --rw "$TMP/wsp" -- "$@"
}

mkdir -p "$TMP/wsp"

test_pid_one_inside_namespace() {
  echo "test: sandboxed process sees itself as PID 1"
  out=$(uj /bin/sh -c 'echo $$')
  if [[ "$out" == "1" ]]; then
    ok "got PID 1 inside namespace"
  elif [[ -n "$out" ]] && [[ "$out" -gt 1 ]]; then
    skip "got PID $out — host disabled unprivileged user namespaces"
  else
    fail "unexpected output: '$out'"
  fi
}

test_proc_only_shows_own_subtree() {
  echo "test: /proc inside namespace only shows the agent's own subtree"
  # Count processes visible in /proc inside the sandbox. A fresh PID
  # namespace with just `sh` running should have 1-2 entries (sh + ps).
  count=$(uj /bin/sh -c 'ls /proc | grep -E "^[0-9]+$" | wc -l' 2>/dev/null || echo 0)
  if [[ "$count" -le 5 ]] && [[ "$count" -ge 1 ]]; then
    ok "/proc shows $count entries (host has hundreds)"
  elif [[ "$count" -gt 50 ]]; then
    skip "/proc shows $count entries — host disabled unprivileged user namespaces"
  else
    fail "unexpected count: $count"
  fi
}

test_cant_signal_host_pid() {
  echo "test: sandboxed process cannot kill a host PID"
  # Spawn a long-running host process, capture its PID, try to kill it from inside.
  sleep 60 &
  host_pid=$!
  trap 'kill $host_pid 2>/dev/null; rm -rf "$TMP"' EXIT

  # Inside the sandbox, attempt to signal the host PID. ESRCH is the
  # success signal — the PID literally doesn't exist in our namespace.
  out=$(uj /bin/sh -c "kill -0 $host_pid 2>&1; echo rc=\$?" 2>&1)
  kill "$host_pid" 2>/dev/null
  trap 'rm -rf "$TMP"' EXIT

  if echo "$out" | grep -q "rc=1"; then
    ok "host PID $host_pid invisible from inside"
  elif echo "$out" | grep -q "rc=0"; then
    # Either PID-ns isolation didn't kick in, or the host PID happens to
    # collide with a namespace-internal PID (extremely unlikely for a 6-digit pid).
    skip "host PID was reachable — likely host disabled unprivileged user namespaces"
  else
    fail "unexpected output: '$out'"
  fi
}

test_pid_one_death_kills_subtree() {
  echo "test: when PID 1 dies, sibling processes in the namespace die too"
  # Spawn sh -c that backgrounds a sleep, then exits. The kernel should
  # SIGKILL the sleep when sh (PID 1 in the namespace) dies.
  start=$(date +%s)
  uj /bin/sh -c 'sleep 30 & exit 0' >/dev/null 2>&1
  end=$(date +%s)
  elapsed=$((end - start))
  if [[ $elapsed -lt 5 ]]; then
    ok "agent-jail returned in ${elapsed}s (sleep was reaped, not waited on)"
  else
    fail "agent-jail waited ${elapsed}s for orphaned sleep — namespace teardown failed"
  fi
}

test_pid_one_death_kills_subtree
test_pid_one_inside_namespace
test_proc_only_shows_own_subtree
test_cant_signal_host_pid

summary_and_exit
