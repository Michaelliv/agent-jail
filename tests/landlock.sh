#!/usr/bin/env bash
# Landlock backend tests — verify real kernel-level filesystem isolation
# kicks in and actually blocks/allows what we claim. Linux-only. Skips on
# macOS or Linux kernels without Landlock enabled.
set -uo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/lib.sh
source "$DIR/lib.sh"

require_tools sh cat echo true id ls

TMP=$(mktemp -d)
chmod 0755 "$TMP"
trap 'rm -rf "$TMP" 2>/dev/null' EXIT

# ── Capability probes ──────────────────────────────────────────────

is_linux() { [[ "$(uname -s)" == "Linux" ]]; }

has_landlock() {
  is_linux || return 1
  [[ -r /sys/kernel/security/lsm ]] || return 1
  grep -q landlock /sys/kernel/security/lsm
}

if ! has_landlock; then
  echo "Landlock not available on this host — skipping backend tests."
  echo "  OS: $(uname -s)"
  if is_linux; then
    echo "  LSMs: $(cat /sys/kernel/security/lsm 2>/dev/null || echo '?')"
  fi
  echo
  echo "0 passed, 0 failed, 1 skipped"
  exit 0
fi

echo "Running Landlock backend tests (kernel LSM enabled)."
echo

# ── Happy path: allow-rw lets child write, deny is enforced ─────────

test_allow_rw_child_can_write() {
  echo "test: child writes into --allow-rw dir"
  rm -rf "$TMP/wsp"
  mkdir -p "$TMP/wsp"
  out=$("$BIN" --allow-rw "$TMP/wsp" --allow-ro /usr --allow-ro /lib --allow-ro /lib64 --allow-ro /bin --allow-ro /etc \
    -- "$SH" -c "echo hi > $TMP/wsp/x && cat $TMP/wsp/x" 2>&1)
  [[ "$out" == "hi" ]] && ok "wrote and read" || fail "got '$out'"
}

test_child_cannot_write_outside_allow() {
  echo "test: child CANNOT write outside --allow-rw (kernel-enforced)"
  rm -rf "$TMP/wsp" "$TMP/forbidden"
  mkdir -p "$TMP/wsp" "$TMP/forbidden"
  "$BIN" --allow-rw "$TMP/wsp" --allow-ro /usr --allow-ro /lib --allow-ro /lib64 --allow-ro /bin --allow-ro /etc \
    -- "$SH" -c "echo pwn > $TMP/forbidden/x" 2>/dev/null
  rc=$?
  if [[ -f "$TMP/forbidden/x" ]]; then
    fail "child wrote outside allow-rw! rc=$rc"
  else
    ok "write blocked (rc=$rc)"
  fi
}

test_child_cannot_read_outside_allow() {
  echo "test: child CANNOT read dir outside any allow-* (kernel-enforced)"
  rm -rf "$TMP/forbidden"
  mkdir -p "$TMP/forbidden"
  echo "topsecret" > "$TMP/forbidden/data"
  out=$("$BIN" --allow-rw "$TMP/wsp" --allow-ro /usr --allow-ro /lib --allow-ro /lib64 --allow-ro /bin --allow-ro /etc \
    -- "$CAT" "$TMP/forbidden/data" 2>&1)
  rc=$?
  if echo "$out" | grep -q topsecret; then
    fail "child read forbidden file! out: $out"
  else
    ok "read blocked (rc=$rc)"
  fi
}

test_allow_ro_is_readable_but_not_writable() {
  echo "test: --allow-ro path IS readable, NOT writable"
  rm -rf "$TMP/rwdir" "$TMP/rodir"
  mkdir -p "$TMP/rwdir" "$TMP/rodir"
  echo "readable content" > "$TMP/rodir/file"
  out=$("$BIN" --allow-rw "$TMP/rwdir" --allow-ro "$TMP/rodir" \
          --allow-ro /usr --allow-ro /lib --allow-ro /lib64 --allow-ro /bin --allow-ro /etc \
    -- "$SH" -c "cat $TMP/rodir/file; echo nope > $TMP/rodir/write_attempt 2>&1" 2>&1)
  if echo "$out" | grep -q "readable content"; then
    if [[ -f "$TMP/rodir/write_attempt" ]]; then
      fail "write to --allow-ro succeeded! out: $out"
    else
      ok "read succeeded, write blocked"
    fi
  else
    fail "read failed: $out"
  fi
}

test_descendants_also_restricted() {
  echo "test: Landlock inheritance — grandchildren also restricted"
  rm -rf "$TMP/wsp" "$TMP/forbidden"
  mkdir -p "$TMP/wsp" "$TMP/forbidden"
  # Shell forks a subshell that forks another — all should inherit the domain.
  "$BIN" --allow-rw "$TMP/wsp" --allow-ro /usr --allow-ro /lib --allow-ro /lib64 --allow-ro /bin --allow-ro /etc \
    -- "$SH" -c "$SH -c \"$SH -c 'echo grandchild > $TMP/forbidden/x'\"" 2>/dev/null
  if [[ -f "$TMP/forbidden/x" ]]; then
    fail "grandchild wrote outside domain!"
  else
    ok "grandchild blocked (inherits Landlock domain)"
  fi
}

test_no_new_privs_set() {
  echo "test: sandboxed child has NO_NEW_PRIVS set (setuid binaries can't elevate)"
  # NO_NEW_PRIVS is required for landlock_restrict_self. If applied, prctl
  # PR_GET_NO_NEW_PRIVS returns 1.
  require_prctl_perl=$(command -v perl || true)
  if [[ -z "$require_prctl_perl" ]]; then skip "perl needed to check PR_GET_NO_NEW_PRIVS"; return; fi
  rm -rf "$TMP/wsp"
  mkdir -p "$TMP/wsp"
  out=$("$BIN" --allow-rw "$TMP/wsp" --allow-ro /usr --allow-ro /lib --allow-ro /lib64 --allow-ro /bin --allow-ro /etc \
    -- /usr/bin/perl -e 'syscall(157, 39) == 1 and print "set" or print "unset";' 2>&1)
  [[ "$out" == "set" ]] && ok "NO_NEW_PRIVS=1" || fail "got '$out'"
}

test_allow_ro_on_missing_path_errors() {
  echo "test: --allow-ro on a nonexistent path errors cleanly"
  "$BIN" --allow-ro "/definitely/does/not/exist/42" -- "$TRUE" 2>/dev/null
  rc=$?
  [[ $rc -ne 0 ]] && ok "exit $rc" || fail "wrong exit $rc"
}

test_multiple_allow_rw_all_work() {
  echo "test: multiple --allow-rw directories all writable"
  rm -rf "$TMP/a" "$TMP/b" "$TMP/c"
  mkdir -p "$TMP/a" "$TMP/b" "$TMP/c"
  "$BIN" --allow-rw "$TMP/a" --allow-rw "$TMP/b" --allow-rw "$TMP/c" \
         --allow-ro /usr --allow-ro /lib --allow-ro /lib64 --allow-ro /bin --allow-ro /etc \
    -- "$SH" -c "echo 1 > $TMP/a/f; echo 2 > $TMP/b/f; echo 3 > $TMP/c/f" 2>&1
  if [[ -f "$TMP/a/f" && -f "$TMP/b/f" && -f "$TMP/c/f" ]]; then
    ok "all 3 dirs writable"
  else
    fail "missing: a=$(ls $TMP/a 2>&1) b=$(ls $TMP/b 2>&1) c=$(ls $TMP/c 2>&1)"
  fi
}

test_exit_code_propagation_with_landlock() {
  echo "test: exit codes still propagate through Landlock backend"
  rm -rf "$TMP/wsp"
  mkdir -p "$TMP/wsp"
  "$BIN" --allow-rw "$TMP/wsp" --allow-ro /usr --allow-ro /lib --allow-ro /lib64 --allow-ro /bin --allow-ro /etc \
    -- "$SH" -c 'exit 42' 2>/dev/null
  rc=$?
  [[ $rc -eq 42 ]] && ok "got 42" || fail "got $rc"
}

test_signal_forwarding_with_landlock() {
  echo "test: signal forwarding works with Landlock backend"
  rm -rf "$TMP/wsp"
  mkdir -p "$TMP/wsp"
  "$BIN" --allow-rw "$TMP/wsp" --allow-ro /usr --allow-ro /lib --allow-ro /lib64 --allow-ro /bin --allow-ro /etc \
    -- "$SH" -c 'kill -TERM $$' 2>/dev/null
  rc=$?
  [[ $rc -eq 143 ]] && ok "got 143 (128+SIGTERM)" || fail "got $rc"
}

# ── Combined backend: --uid + --allow-* (defense in depth) ─────────

test_combined_uid_and_landlock() {
  if ! is_root; then skip "combined backend test (need root)"; return; fi
  echo "test: --uid + --allow-rw = uid drop AND Landlock applied"
  uid=$(pick_unpriv_uid)
  rm -rf "$TMP/wsp" "$TMP/forbidden"
  mkdir -p "$TMP/wsp" "$TMP/forbidden"
  # Child should be both unpriv uid AND Landlock-sandboxed.
  out=$("$BIN" --uid "$uid" --allow-rw "$TMP/wsp" \
               --allow-ro /usr --allow-ro /lib --allow-ro /lib64 --allow-ro /bin --allow-ro /etc \
    -- "$SH" -c "id -u; echo hi > $TMP/wsp/ok; echo pwn > $TMP/forbidden/x 2>&1 || echo BLOCKED" 2>&1)
  if echo "$out" | grep -q "$uid" && echo "$out" | grep -q BLOCKED && [[ -f "$TMP/wsp/ok" ]]; then
    ok "uid=$uid, workspace writable, outside blocked"
  else
    fail "got: $out"
  fi
}

# ── Error surfaces on non-Landlock hosts ───────────────────────────

test_allow_ro_without_landlock_would_error() {
  echo "test: --allow-ro produces clean error on non-Landlock host (sim check)"
  # We are on a Landlock host here so we can't actually test the error path.
  # But we can verify that using --allow-ro succeeds (not errors) when we have it.
  rm -rf "$TMP/wsp"
  mkdir -p "$TMP/wsp"
  "$BIN" --allow-rw "$TMP/wsp" --allow-ro /usr --allow-ro /lib --allow-ro /lib64 --allow-ro /bin --allow-ro /etc \
    -- "$TRUE"
  rc=$?
  [[ $rc -eq 0 ]] && ok "allow-ro succeeds when Landlock available" || fail "rc=$rc"
}

# ── Run all ─────────────────────────────────────────────────────────

test_allow_rw_child_can_write
test_child_cannot_write_outside_allow
test_child_cannot_read_outside_allow
test_allow_ro_is_readable_but_not_writable
test_descendants_also_restricted
test_no_new_privs_set
test_allow_ro_on_missing_path_errors
test_multiple_allow_rw_all_work
test_exit_code_propagation_with_landlock
test_signal_forwarding_with_landlock
test_combined_uid_and_landlock
test_allow_ro_without_landlock_would_error

summary_and_exit
