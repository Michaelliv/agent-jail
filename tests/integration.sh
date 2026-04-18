#!/usr/bin/env bash
# End-to-end integration test for agent-jail. Runs the built binary against real
# spawned subprocesses and checks behavior. Does NOT require root.
set -uo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/lib.sh
source "$DIR/lib.sh"

require_tools true echo sleep sh cat pwd id

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

test_help_exits_0() {
  echo "test: --help exits 0"
  "$BIN" --help >/dev/null && ok "exit 0" || fail "non-zero exit"
}

test_version() {
  echo "test: --version matches build.zig.zon"
  zon_ver=$(grep -oE '\.version = "[0-9]+\.[0-9]+\.[0-9]+[^"]*"' "$DIR/../build.zig.zon" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^"]*')
  out=$("$BIN" --version)
  [[ "$out" == "agent-jail $zon_ver" ]] && ok "got '$out'" || fail "got '$out' expected 'agent-jail $zon_ver'"
}

test_missing_command() {
  echo "test: missing command after -- exits 2"
  "$BIN" --uid 1001 2>/dev/null
  [[ $? -eq 2 ]] && ok "exit 2" || fail "wrong exit"
}

test_unknown_flag() {
  echo "test: unknown flag exits 2"
  "$BIN" --bogus 2>/dev/null
  [[ $? -eq 2 ]] && ok "exit 2" || fail "wrong exit"
}

test_passthrough_exit_code() {
  echo "test: child exit 7 propagates as exit 7"
  "$BIN" -- "$SH" -c 'exit 7'
  [[ $? -eq 7 ]] && ok "exit 7" || fail "wrong exit"
}

test_stdout_passthrough() {
  echo "test: child stdout reaches us"
  out=$("$BIN" -- "$ECHO" "hello sandbox")
  [[ "$out" == "hello sandbox" ]] && ok "got '$out'" || fail "got '$out'"
}

test_rw_creates_dir() {
  echo "test: --rw creates the dir with mode 0700"
  rm -rf "$TMP/wsp"
  "$BIN" --rw "$TMP/wsp" $(landlock_system_ro) -- "$SH" -c "echo data > $TMP/wsp/x && cat $TMP/wsp/x" >/dev/null
  if [[ ! -d "$TMP/wsp" ]]; then fail "dir not created"; return; fi
  m=$(mode_of "$TMP/wsp")
  [[ "$m" == "700" ]] && ok "mode 0700" || fail "mode is $m"
}

test_rw_child_can_write() {
  echo "test: child writes into --rw dir succeed"
  rm -rf "$TMP/wsp2"
  out=$("$BIN" --rw "$TMP/wsp2" $(landlock_system_ro) -- "$SH" -c "echo content > $TMP/wsp2/file && cat $TMP/wsp2/file")
  [[ "$out" == "content" ]] && ok "wrote and read" || fail "got '$out'"
}

test_cwd_flag() {
  echo "test: --cwd changes child's working directory"
  out=$("$BIN" --cwd "$TMP" -- "$PWD_BIN")
  # macOS adds /private prefix to /tmp paths via realpath — accept both.
  [[ "$out" == "$TMP" || "$out" == "/private$TMP" ]] && ok "got '$out'" || fail "got '$out'"
}

test_ro_without_landlock_errors_loudly() {
  echo "test: --ro without Landlock is a loud error (no --best-effort)"
  if [[ "$(uname -s)" == "Linux" ]] && [[ -r /sys/kernel/security/lsm ]] \
     && grep -q landlock /sys/kernel/security/lsm; then
    skip "host has Landlock — this test only meaningful without it"
    return
  fi
  out=$("$BIN" --ro /usr -- "$TRUE" 2>&1)
  rc=$?
  if [[ $rc -eq 1 ]] && echo "$out" | grep -q "requires Landlock"; then
    ok "errored loudly (rc=1, clear message)"
  else
    fail "rc=$rc out='$out'"
  fi
}

test_best_effort_degrades_gracefully() {
  echo "test: --best-effort --ro works everywhere, warns when can't enforce"
  out=$("$BIN" --best-effort --ro /usr -- "$TRUE" 2>&1)
  rc=$?
  [[ $rc -eq 0 ]] && ok "exited 0 (warnings ok)" || fail "rc=$rc out='$out'"
}

test_system_ro_shorthand() {
  echo "test: --system-ro expands to standard system dirs"
  rm -rf "$TMP/wsp3"
  out=$("$BIN" --best-effort --system-ro --rw "$TMP/wsp3" -- "$SH" -c "echo hi > $TMP/wsp3/f && cat $TMP/wsp3/f")
  [[ "$out" == "hi" ]] && ok "system-ro + rw works end-to-end" || fail "got '$out'"
}

test_hide_on_missing_path_noop() {
  echo "test: --hide on a nonexistent path is a no-op"
  "$BIN" --hide "$TMP/nowhere" -- "$TRUE"
  [[ $? -eq 0 ]] && ok "--hide ignored missing path" || fail "wrong exit"
}

test_help_exits_0
test_version
test_missing_command
test_unknown_flag
test_passthrough_exit_code
test_stdout_passthrough
test_rw_creates_dir
test_rw_child_can_write
test_cwd_flag
test_ro_without_landlock_errors_loudly
test_best_effort_degrades_gracefully
test_system_ro_shorthand
test_hide_on_missing_path_noop

summary_and_exit
