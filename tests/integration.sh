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
  echo "test: --version prints version"
  out=$("$BIN" --version)
  [[ "$out" == "agent-jail 0.1.0" ]] && ok "got '$out'" || fail "got '$out'"
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

test_allow_rw_creates_dir() {
  echo "test: --allow-rw creates the dir with mode 0700"
  rm -rf "$TMP/wsp"
  "$BIN" --allow-rw "$TMP/wsp" $(landlock_system_ro) -- "$SH" -c "echo data > $TMP/wsp/x && cat $TMP/wsp/x" >/dev/null
  if [[ ! -d "$TMP/wsp" ]]; then fail "dir not created"; return; fi
  m=$(mode_of "$TMP/wsp")
  [[ "$m" == "700" ]] && ok "mode 0700" || fail "mode is $m"
}

test_allow_rw_child_can_write() {
  echo "test: child writes into --allow-rw dir succeed"
  rm -rf "$TMP/wsp2"
  out=$("$BIN" --allow-rw "$TMP/wsp2" $(landlock_system_ro) -- "$SH" -c "echo content > $TMP/wsp2/file && cat $TMP/wsp2/file")
  [[ "$out" == "content" ]] && ok "wrote and read" || fail "got '$out'"
}

test_cwd_flag() {
  echo "test: --cwd changes child's working directory"
  out=$("$BIN" --cwd "$TMP" -- "$PWD_BIN")
  # macOS adds /private prefix to /tmp paths via realpath — accept both.
  [[ "$out" == "$TMP" || "$out" == "/private$TMP" ]] && ok "got '$out'" || fail "got '$out'"
}

test_help_exits_0
test_version
test_missing_command
test_unknown_flag
test_passthrough_exit_code
test_stdout_passthrough
test_allow_rw_creates_dir
test_allow_rw_child_can_write
test_cwd_flag

summary_and_exit
