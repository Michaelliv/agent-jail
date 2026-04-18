#!/usr/bin/env bash
# Deterministic sandbox-contract tests via the `probe` binary.
#
# Unlike security.sh / landlock.sh which spawn real shell commands and
# grep their output, these tests spawn `probe` as the sandboxed child
# and assert on its exit code. Each probe invocation attempts one
# syscall and maps the kernel's errno to a fixed exit code (see
# tests/probe/probe.zig). The test just checks the number.
#
# This gives us exact answers to "did the kernel return EACCES vs
# ENOENT vs EROFS" without shell-string-matching.
#
# Runs on Linux (Landlock + uid backends) and macOS (sandbox-exec).
# Skips cleanly on hosts without any sandbox backend.
set -uo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/lib.sh
source "$DIR/lib.sh"

PROBE="${PROBE_BIN:-./zig-out/bin/probe}"
[[ -x "$PROBE" ]] || { echo "probe binary missing at $PROBE — run 'zig build'" >&2; exit 1; }

TMP=$(mktemp -d)
chmod 0755 "$TMP"
trap 'rm -rf "$TMP" 2>/dev/null' EXIT

# Expected exit codes from the probe binary.
EX_OK=0
EX_EACCES=13
EX_ENOENT=2
EX_EROFS=30
EX_EPERM=1

# Capability detection.
is_linux() { [[ "$(uname -s)" == "Linux" ]]; }
is_macos() { [[ "$(uname -s)" == "Darwin" ]]; }

has_landlock() {
  is_linux || return 1
  [[ -r /sys/kernel/security/lsm ]] || return 1
  grep -q landlock /sys/kernel/security/lsm
}

has_sandbox_exec() {
  is_macos || return 1
  command -v sandbox-exec >/dev/null 2>&1
}

# Pick the backend name for reporting.
backend_name() {
  if has_landlock; then echo "landlock"
  elif has_sandbox_exec; then echo "sandbox-exec"
  else echo "none"
  fi
}

if [[ "$(backend_name)" == "none" ]]; then
  echo "No sandbox backend on this host (need Landlock on Linux or sandbox-exec on macOS)."
  echo "0 passed, 0 failed, 1 skipped"
  exit 0
fi

echo "Running probe tests against backend: $(backend_name)"
echo

# Run `probe VERB ARG...` inside agent-jail with the given sandbox flags.
# Usage:  run_probe <aj-flags...> -- <probe-verb> [probe-arg...]
# Returns the probe's exit code.
run_probe() {
  local aj_args=()
  while [[ $# -gt 0 && "$1" != "--" ]]; do
    aj_args+=("$1")
    shift
  done
  [[ "${1:-}" == "--" ]] && shift
  "$BIN" $(landlock_system_ro) "${aj_args[@]}" -- "$PROBE" "$@" 2>/dev/null
}

# Assert: running the probe verb inside the given sandbox exits with $expected.
assert_probe() {
  local desc=$1 expected=$2; shift 2
  run_probe "$@"
  local rc=$?
  if [[ $rc -eq $expected ]]; then
    ok "$desc (rc=$rc)"
  else
    fail "$desc: expected $expected, got $rc"
  fi
}

# ── Reads ──────────────────────────────────────────────────────────

test_rw_path_readable() {
  echo "read inside --rw succeeds"
  rm -rf "$TMP/wsp" && mkdir -p "$TMP/wsp" && echo hi > "$TMP/wsp/f"
  assert_probe "read $TMP/wsp/f → ok" $EX_OK \
    --rw "$TMP/wsp" -- read "$TMP/wsp/f"
}

test_ro_path_readable() {
  echo "read inside --ro succeeds"
  rm -rf "$TMP/ro" "$TMP/wsp" && mkdir -p "$TMP/ro" "$TMP/wsp"
  echo hi > "$TMP/ro/f"
  assert_probe "read $TMP/ro/f → ok" $EX_OK \
    --rw "$TMP/wsp" --ro "$TMP/ro" -- read "$TMP/ro/f"
}

test_outside_path_denied() {
  echo "[linux] read outside --rw is denied (default-deny model)"
  if is_macos; then
    skip "macOS uses default-allow + targeted --hide (by design)"
    return
  fi
  rm -rf "$TMP/forbidden" "$TMP/wsp" && mkdir -p "$TMP/forbidden" "$TMP/wsp"
  echo secret > "$TMP/forbidden/data"
  run_probe --rw "$TMP/wsp" -- read "$TMP/forbidden/data"
  local rc=$?
  if [[ $rc -eq $EX_EACCES || $rc -eq $EX_EPERM ]]; then
    ok "read $TMP/forbidden/data blocked (rc=$rc)"
  else
    fail "read blocked: expected EACCES/EPERM, got $rc"
  fi
}

# ── Writes ─────────────────────────────────────────────────────────

test_rw_path_writable() {
  echo "write inside --rw succeeds"
  rm -rf "$TMP/wsp" && mkdir -p "$TMP/wsp"
  assert_probe "write $TMP/wsp/out → ok" $EX_OK \
    --rw "$TMP/wsp" -- write "$TMP/wsp/out"
}

test_ro_path_not_writable() {
  echo "[linux] write to --ro is blocked"
  if is_macos; then
    # On macOS --ro is an advisory passthrough; the kernel doesn't
    # enforce it (see darwin.zig comment). --hide is the real primitive.
    skip "macOS --ro is advisory (see darwin.zig)"
    return
  fi
  rm -rf "$TMP/ro" "$TMP/wsp" && mkdir -p "$TMP/ro" "$TMP/wsp"
  run_probe --rw "$TMP/wsp" --ro "$TMP/ro" -- write "$TMP/ro/x"
  local rc=$?
  if [[ $rc -eq $EX_EACCES || $rc -eq $EX_EPERM ]]; then
    ok "write to --ro blocked (rc=$rc)"
  else
    fail "write to --ro: expected EACCES/EPERM, got $rc"
  fi
}

test_outside_write_denied() {
  echo "[linux] write outside --rw is blocked (default-deny model)"
  if is_macos; then
    skip "macOS uses default-allow + targeted --hide"
    return
  fi
  rm -rf "$TMP/forbidden" "$TMP/wsp" && mkdir -p "$TMP/forbidden" "$TMP/wsp"
  run_probe --rw "$TMP/wsp" -- write "$TMP/forbidden/pwn"
  local rc=$?
  if [[ $rc -eq $EX_EACCES || $rc -eq $EX_EPERM ]]; then
    ok "write to outside blocked (rc=$rc)"
  else
    fail "outside write: expected EACCES/EPERM, got $rc"
  fi
  [[ ! -f "$TMP/forbidden/pwn" ]] || fail "file got created despite denial"
}

# ── --hide ─────────────────────────────────────────────────────────

test_hide_denies_read() {
  echo "read of --hide path is blocked (cross-platform primitive)"
  rm -rf "$TMP/secret" "$TMP/wsp" && mkdir -p "$TMP/secret" "$TMP/wsp"
  echo x > "$TMP/secret/f"
  run_probe --rw "$TMP/wsp" --hide "$TMP/secret" -- read "$TMP/secret/f"
  local rc=$?
  # --hide is enforced on all backends:
  #   Landlock default-deny: EACCES
  #   uid-switch chmod 0700: EACCES
  #   sandbox-exec (deny file-read*): EPERM
  if [[ $rc -eq $EX_EACCES || $rc -eq $EX_EPERM ]]; then
    ok "read of hidden path blocked (rc=$rc)"
  else
    fail "expected EACCES/EPERM, got $rc"
  fi
}

# ── --uid drop ─────────────────────────────────────────────────────

test_uid_actually_drops() {
  if ! is_root; then skip "uid drop (need root)"; return; fi
  echo "--uid drops uid in the child"
  local uid; uid=$(pick_unpriv_uid)
  rm -rf "$TMP/wsp" && mkdir -p "$TMP/wsp"
  chown "$uid:$uid" "$TMP/wsp" 2>/dev/null || true
  out=$("$BIN" $(landlock_system_ro) --uid "$uid" --rw "$TMP/wsp" -- "$PROBE" uid 2>/dev/null)
  [[ "$out" == "$uid" ]] && ok "uid=$uid in child" || fail "got '$out'"
}

test_setuid_back_to_root_fails() {
  if ! is_root; then skip "setuid drop irreversible (need root)"; return; fi
  echo "child can't setuid(0) after drop"
  local uid; uid=$(pick_unpriv_uid)
  rm -rf "$TMP/wsp" && mkdir -p "$TMP/wsp"
  chown "$uid:$uid" "$TMP/wsp" 2>/dev/null || true
  run_probe --uid "$uid" --rw "$TMP/wsp" -- setuid 0
  local rc=$?
  [[ $rc -eq $EX_EPERM ]] && ok "setuid(0) → EPERM" || fail "expected EPERM, got $rc"
}

# ── --system-ro ────────────────────────────────────────────────────

test_system_ro_grants_etc_read() {
  echo "[linux] --system-ro lets child read /etc/passwd"
  if is_macos; then
    # On macOS /etc is readable under (allow default) regardless of
    # --system-ro, so this test isn't meaningful there.
    skip "macOS default-allow makes /etc readable without --system-ro"
    return
  fi
  rm -rf "$TMP/wsp" && mkdir -p "$TMP/wsp"
  "$BIN" --system-ro --rw "$TMP/wsp" -- "$PROBE" read /etc/passwd 2>/dev/null
  local rc=$?
  [[ $rc -eq $EX_OK ]] && ok "/etc/passwd readable" || fail "got $rc"
}

test_system_ro_blocks_etc_write() {
  echo "--system-ro blocks writes to /etc"
  rm -rf "$TMP/wsp" && mkdir -p "$TMP/wsp"
  "$BIN" --system-ro --rw "$TMP/wsp" -- "$PROBE" write /etc/agent-jail-probe-should-fail 2>/dev/null
  local rc=$?
  if [[ $rc -eq $EX_EACCES || $rc -eq $EX_EPERM || $rc -eq $EX_EROFS ]]; then
    ok "/etc write blocked (rc=$rc)"
  else
    fail "/etc write: expected EACCES/EPERM/EROFS, got $rc"
  fi
  [[ ! -f /etc/agent-jail-probe-should-fail ]] || fail "file appeared in /etc!"
}

# ── Env passthrough (documents current behavior) ───────────────────
#
# agent-jail intentionally passes env through unchanged — scrubbing is
# the caller's policy. These tests pin that contract so we notice if
# it ever changes.

test_env_is_passed_through() {
  echo "caller env visible in sandboxed child"
  rm -rf "$TMP/wsp" && mkdir -p "$TMP/wsp"
  out=$(AGENT_JAIL_PROBE_CANARY=xyzzy \
    "$BIN" $(landlock_system_ro) --rw "$TMP/wsp" -- "$PROBE" env AGENT_JAIL_PROBE_CANARY 2>/dev/null)
  [[ "$out" == "xyzzy" ]] && ok "env passed through (contract)" || fail "got '$out'"
}

# ── Run all ────────────────────────────────────────────────────────

test_rw_path_readable
test_ro_path_readable
test_outside_path_denied
test_rw_path_writable
test_ro_path_not_writable
test_outside_write_denied
test_hide_denies_read
test_uid_actually_drops
test_setuid_back_to_root_fails
test_system_ro_grants_etc_read
test_system_ro_blocks_etc_write
test_env_is_passed_through

summary_and_exit
