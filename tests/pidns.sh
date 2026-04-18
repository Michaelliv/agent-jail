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
mkdir -p "$TMP/wsp"

# Helper: invoke uj with the standard sandbox triplet plus --best-effort.
uj() {
  "$BIN" --best-effort --system-ro --rw "$TMP/wsp" -- "$@"
}

# Up-front capability probe: agent-jail's pickPlan() runs its own probe
# and silently disables PID-ns when it can't be set up. Detect the same
# decision here by reading the child's PID — it's 1 inside a fresh PID
# namespace, anything else means PID-ns didn't activate. If it didn't,
# the entire suite skips: there's nothing meaningful to test.
probe_out=$(uj /bin/sh -c 'echo $$' 2>/dev/null || echo "")
if [[ "$probe_out" != "1" ]]; then
  echo "pidns.sh: PID-namespace isolation not active on this host (\$\$=$probe_out)."
  echo "  Likely cause: unprivileged user namespaces disabled, or uid_map writes"
  echo "  restricted (some CI runners). Skipping suite."
  echo
  echo "0 passed, 0 failed, 1 skipped"
  exit 0
fi

echo "PID-ns active (probe child saw \$\$=1). Running confinement tests."
echo

test_pid_one_inside_namespace() {
  echo "test: sandboxed process sees itself as PID 1"
  out=$(uj /bin/sh -c 'echo $$')
  [[ "$out" == "1" ]] && ok "got PID 1" || fail "got '$out'"
}

test_proc_only_shows_own_subtree() {
  echo "test: /proc inside namespace only shows the agent's own subtree"
  # A fresh PID namespace should only contain the agent's own subtree.
  # Grant --ro /proc so Landlock doesn't deny the read; the count we see
  # then reflects the PID namespace, not the LSM filter.
  count=$("$BIN" --best-effort --system-ro --rw "$TMP/wsp" --ro /proc \
    -- /bin/sh -c 'ls /proc | grep -E "^[0-9]+$" | wc -l' 2>/dev/null)
  if [[ "$count" -ge 1 ]] && [[ "$count" -le 10 ]]; then
    ok "/proc shows $count entries (host has hundreds)"
  else
    fail "unexpected count: $count"
  fi
}

test_cant_signal_host_pid() {
  echo "test: sandboxed process cannot kill a host PID"
  sleep 60 &
  host_pid=$!
  trap 'kill $host_pid 2>/dev/null; rm -rf "$TMP"' EXIT

  # ESRCH (rc=1) means the PID doesn't exist in our namespace. Permission
  # denied (rc=1 too in shell, but kill prints "Operation not permitted")
  # would only happen if PID-ns failed and uid blocked us — the upfront
  # probe ruled that out.
  out=$(uj /bin/sh -c "kill -0 $host_pid 2>&1; echo rc=\$?" 2>&1)
  kill "$host_pid" 2>/dev/null
  trap 'rm -rf "$TMP"' EXIT

  if echo "$out" | grep -q "rc=1"; then
    ok "host PID $host_pid invisible from inside"
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
