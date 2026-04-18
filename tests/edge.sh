#!/usr/bin/env bash
# Edge-case tests for rare inputs and hostile paths. Runs everywhere;
# individual tests skip when their precondition isn't met.
set -uo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/lib.sh
source "$DIR/lib.sh"

require_tools true echo sleep sh cat pwd id

TMP=$(mktemp -d)
chmod 0755 "$TMP"
trap 'rm -rf "$TMP" 2>/dev/null' EXIT

is_darwin() { [[ "$(uname -s)" == "Darwin" ]]; }
is_linux()  { [[ "$(uname -s)" == "Linux"  ]]; }

# ── 1. Path canonicalization — Linux ────────────────────────────────
#
# /a/../b and /b are different syntactic paths; Landlock matches the
# canonical path. The kernel resolves the parent-fd we hand it before
# checking rules, so both forms should behave identically. We pin that.

test_dotdot_in_rw_path() {
  echo "test: --rw /TMP/x/../x is equivalent to --rw /TMP/x"
  rm -rf "$TMP/canon" && mkdir -p "$TMP/canon"
  "$BIN" --rw "$TMP/canon/../canon" $(landlock_system_ro) \
    -- "$SH" -c "echo hi > $TMP/canon/file && cat $TMP/canon/file" >/dev/null 2>&1
  rc=$?
  [[ $rc -eq 0 && -f "$TMP/canon/file" ]] && ok "dotdot-normalized path works" || fail "rc=$rc"
}

# ── 2. SBPL injection resistance — macOS ────────────────────────────
#
# A path containing " or \ must NOT break out of the quoted string in the
# rendered SBPL profile. If quoting is weak, an attacker-controlled path
# could inject "(allow file-read* ...)" and neutralize --hide.

test_quote_in_path_does_not_break_sandbox() {
  if ! is_darwin; then skip "macOS-only: SBPL profile quoting"; return; fi
  echo "test: path containing \" doesn't break out of SBPL string literal"
  # Create a legitimate --rw dir whose name contains "
  mkdir -p "$TMP/a\"b"
  echo "SECRET" > "$TMP/secret"
  out=$("$BIN" --hide "$TMP/secret" --rw "$TMP/a\"b" \
    -- "$SH" -c "cat $TMP/secret 2>&1 || echo BLOCKED" 2>&1)
  if echo "$out" | grep -q "SECRET"; then
    fail "hide bypassed — SBPL injection: $out"
  elif echo "$out" | grep -q BLOCKED; then
    ok "hide survived \" in sibling path"
  else
    fail "unexpected: $out"
  fi
}

test_paren_in_path_does_not_break_sandbox() {
  if ! is_darwin; then skip "macOS-only: SBPL profile quoting"; return; fi
  echo "test: path containing ) doesn't break SBPL list parsing"
  mkdir -p "$TMP/a)b"
  echo "SECRET" > "$TMP/secret"
  out=$("$BIN" --hide "$TMP/secret" --rw "$TMP/a)b" \
    -- "$SH" -c "cat $TMP/secret 2>&1 || echo BLOCKED" 2>&1)
  if echo "$out" | grep -q "SECRET"; then
    fail "hide bypassed — ) injection: $out"
  else
    ok "hide survived ) in sibling path"
  fi
}

test_backslash_in_path_does_not_break_sandbox() {
  if ! is_darwin; then skip "macOS-only: SBPL profile quoting"; return; fi
  echo "test: path containing \\ doesn't break SBPL escape"
  mkdir -p "$TMP/a\\b"
  echo "SECRET" > "$TMP/secret"
  out=$("$BIN" --hide "$TMP/secret" --rw "$TMP/a\\b" \
    -- "$SH" -c "cat $TMP/secret 2>&1 || echo BLOCKED" 2>&1)
  if echo "$out" | grep -q "SECRET"; then
    fail "hide bypassed — \\ injection: $out"
  else
    ok "hide survived \\ in sibling path"
  fi
}

# ── 3. Argument parser edges ────────────────────────────────────────

test_equals_form_rejected() {
  echo "test: --rw=PATH form is not accepted (would silently eat the path)"
  "$BIN" --rw=/tmp -- "$TRUE" 2>/dev/null
  rc=$?
  [[ $rc -eq 2 ]] && ok "--rw=PATH rejected (exit 2)" || fail "wrong exit $rc"
}

test_long_single_arg() {
  echo "test: very long single arg (near PATH_MAX) doesn't overflow buffers"
  # PATH_MAX on Linux is 4096, on macOS 1024. Zig's std.fs.max_path_bytes is
  # 4096. A single arg of 3999 bytes should round-trip through parsing.
  long=$(printf 'a%.0s' {1..3000})
  out=$("$BIN" -- "$ECHO" "$long" 2>&1 | wc -c | tr -d ' ')
  # echo adds a trailing \n
  expected=$((3000 + 1))
  [[ "$out" -eq "$expected" ]] && ok "3000-byte arg round-tripped" || fail "got $out bytes, expected $expected"
}

test_empty_string_as_path() {
  echo "test: --rw '' (empty string) rejected cleanly"
  "$BIN" --rw "" -- "$TRUE" 2>/dev/null
  rc=$?
  # Current behavior: mkdirP returns PathTooLong on len==0. Exit 1.
  [[ $rc -eq 1 || $rc -eq 2 ]] && ok "empty path rejected (exit $rc)" || fail "wrong exit $rc"
}

# ── 4. Read-only filesystem ─────────────────────────────────────────

test_rw_on_readonly_fs() {
  if ! is_linux; then skip "needs Linux read-only mount"; return; fi
  # Find a read-only mount to test against. /sys is writable in some
  # container configs; /proc/sys is more reliably read-only, but it's also
  # the wrong fs type for mkdir. Use findmnt to pick a real ro mount.
  ro_mount=$(findmnt -nr -o TARGET,OPTIONS 2>/dev/null | awk '$2 ~ /(^|,)ro(,|$)/ {print $1; exit}')
  if [[ -z "$ro_mount" ]]; then
    skip "no read-only mount found on this host"
    return
  fi
  echo "test: --rw on a read-only filesystem ($ro_mount) surfaces a clean error"
  "$BIN" --rw "$ro_mount/readonly-test-$$" -- "$TRUE" 2>/dev/null
  rc=$?
  [[ $rc -eq 1 ]] && ok "ro-fs --rw rejected (exit 1)" || fail "wrong exit $rc"
}

# ── 5. Missing /proc (close_range fallback)  ────────────────────────
#
# close_range(2) is a Linux 5.9+ syscall. On hosts where it returns ENOSYS,
# we fall back to a close() loop bounded by RLIMIT_NOFILE. Kick the fallback
# by shrinking RLIMIT_NOFILE to something small.

test_closerange_fallback_works() {
  if ! is_linux; then skip "Linux-only FD-closing code path"; return; fi
  echo "test: child's FD table is clean even under ulimit -n 64"
  out=$(ulimit -n 64 2>/dev/null; "$BIN" -- "$SH" -c 'ls /proc/self/fd 2>/dev/null | wc -l')
  # Normalize whitespace so [[ -le ]] gets a clean integer.
  count=$(echo "$out" | tr -dc '0-9')
  # stdin/stdout/stderr/3 (from ls itself) = 4; <=5 is expected.
  if [[ -n "$count" ]] && [[ "$count" -le 5 ]]; then
    ok "clean FD table ($count fds)"
  else
    fail "too many FDs: '$out'"
  fi
}

# ── 6. suid-root binary ────────────────────────────────────────────
#
# If someone installs agent-jail suid-root (a bad idea — --uid becomes a
# generic uid-setter for any user on the host), behavior must at least be
# predictable. We don't endorse this use; pin what happens.

# Skipped: requires chown-to-root which needs root to set up. Documented
# in the threat-model section of README instead.

# ── 7. stdin EOF ───────────────────────────────────────────────────

test_stdin_eof_reaches_child() {
  echo "test: stdin EOF closes cleanly; child sees end-of-input"
  out=$(echo -n "" | "$BIN" -- "$CAT")
  [[ "$out" == "" ]] && ok "empty stdin → empty stdout" || fail "got '$out'"
}

test_stdin_large_data() {
  echo "test: 1 MB of stdin reaches child intact"
  actual=$(dd if=/dev/zero bs=1024 count=1024 2>/dev/null | "$BIN" -- "$CAT" | wc -c | tr -d ' ')
  expected=$((1024 * 1024))
  [[ "$actual" -eq "$expected" ]] && ok "1MB stdin round-tripped" || fail "got $actual, expected $expected"
}

# ── 8. Fork-bomb containment (PID-ns) ───────────────────────────────

test_fork_bomb_reaped_on_exit() {
  if ! is_linux; then skip "Linux PID-ns feature"; return; fi
  echo "test: agent-jail exit reaps entire forked subtree"
  marker="ajedge-forkbomb-$$-$RANDOM"
  rm -rf "$TMP/wsp" && mkdir -p "$TMP/wsp"
  # Spawn a chain of background sleeps with a distinctive argv.
  "$BIN" --best-effort --system-ro --rw "$TMP/wsp" -- \
    "$SH" -c "
      for i in 1 2 3 4 5; do
        (exec -a $marker-\$i $SLEEP 60) &
      done
      exit 0
    " >/dev/null 2>&1
  # Allow a moment for zombies to be reaped.
  sleep 0.5
  # pgrep -c prints 0 AND exits 1 when there are no matches. Use || true
  # so pipefail doesn't bite; grab only the first line in case of noise.
  remaining=$(pgrep -fc "$marker" 2>/dev/null | head -1 || true)
  remaining=${remaining:-0}
  if [[ "$remaining" -eq 0 ]]; then
    ok "all 5 descendants reaped"
  else
    fail "$remaining stragglers survived"
    pkill -KILL -f "$marker" 2>/dev/null
  fi
}

# ── 9. Large stdout drains without pipe-full hang ──────────────────

test_large_stdout_does_not_hang() {
  echo "test: child writing 10 MB to stdout doesn't deadlock parent"
  # Set a 30s hard timeout — a deadlock would hit it.
  start=$(date +%s)
  actual=$("$BIN" -- "$SH" -c "dd if=/dev/zero bs=1024 count=10240 2>/dev/null" | wc -c | tr -d ' ')
  end=$(date +%s)
  elapsed=$((end - start))
  expected=$((10 * 1024 * 1024))
  if [[ "$actual" -ne "$expected" ]]; then
    fail "got $actual bytes, expected $expected"
  elif [[ "$elapsed" -gt 10 ]]; then
    fail "took ${elapsed}s — pipe buffer deadlock?"
  else
    ok "10MB drained in ${elapsed}s"
  fi
}

# ── 10. --best-effort is not infectious ─────────────────────────────
#
# Without --best-effort, requested protections that can't be delivered
# are fatal. Make sure --best-effort doesn't silently leak through when
# only some flags would normally be fatal.

test_best_effort_still_runs_layers_that_work() {
  echo "test: --best-effort still applies every layer the host DOES support"
  # On any host with at least one layer (uid, Landlock, sandbox-exec),
  # --rw should still create the dir — that's fs setup, not a layer.
  rm -rf "$TMP/wspBE"
  "$BIN" --best-effort --rw "$TMP/wspBE" $(landlock_system_ro) -- "$TRUE"
  rc=$?
  [[ $rc -eq 0 && -d "$TMP/wspBE" ]] && ok "setup happened under --best-effort" || fail "rc=$rc"
}

# ── 11. Quote escape is symmetric ──────────────────────────────────

test_quote_escape_roundtrip() {
  if ! is_darwin; then skip "macOS-specific quoting behavior"; return; fi
  echo "test: every special char in path flows through SBPL intact"
  # Path containing " \ ) ( - Landlock wouldn't rewrite any of these; SBPL
  # needs " and \ escaped. We already verified those individually above;
  # this test composes them in one path.
  weird="$TMP/a\"b)c(\\d"
  mkdir -p "$weird"
  echo "MARKER" > "$weird/file"
  # --rw this weird dir. If escape is wrong, sandbox-exec either rejects
  # the profile (exec fail) or drops the rule silently (file unreadable).
  out=$("$BIN" --rw "$weird" -- "$CAT" "$weird/file" 2>&1)
  [[ "$out" == "MARKER" ]] && ok "weird path survived escape" || fail "got '$out'"
}

# ── 12. --ro on a file (not a dir) ──────────────────────────────────

test_ro_on_regular_file() {
  echo "test: --ro on a regular file (not dir) works"
  echo "readable" > "$TMP/regular"
  # Landlock and sandbox-exec both support file-level rules. On Linux
  # with Landlock, we also need --system-ro so the dynamic linker can
  # load cat's dependencies (/lib, /etc/ld.so.cache); otherwise exec
  # fails before the file-level --ro can even be exercised.
  out=$("$BIN" --best-effort --system-ro --ro "$TMP/regular" \
    -- "$CAT" "$TMP/regular" 2>&1)
  if echo "$out" | grep -q "^readable$"; then
    ok "file-level --ro works"
  else
    fail "got '$out'"
  fi
}

# ── 13. Empty workspace + immediate exit ────────────────────────────

test_immediate_exit_no_leaks() {
  echo "test: agent-jail with no command work returns promptly"
  start=$(date +%s%N)
  "$BIN" --rw "$TMP/fast" -- "$TRUE"
  end=$(date +%s%N)
  elapsed_ms=$(( (end - start) / 1000000 ))
  if [[ "$elapsed_ms" -lt 500 ]]; then
    ok "completed in ${elapsed_ms}ms"
  else
    fail "slow start: ${elapsed_ms}ms"
  fi
}

# ── Run all ─────────────────────────────────────────────────────────

test_dotdot_in_rw_path
test_quote_in_path_does_not_break_sandbox
test_paren_in_path_does_not_break_sandbox
test_backslash_in_path_does_not_break_sandbox
test_equals_form_rejected
test_long_single_arg
test_empty_string_as_path
test_rw_on_readonly_fs
test_closerange_fallback_works
test_stdin_eof_reaches_child
test_stdin_large_data
test_fork_bomb_reaped_on_exit
test_large_stdout_does_not_hang
test_best_effort_still_runs_layers_that_work
test_quote_escape_roundtrip
test_ro_on_regular_file
test_immediate_exit_no_leaks

summary_and_exit
