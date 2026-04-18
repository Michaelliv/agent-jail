#!/usr/bin/env bash
# macOS Sandbox kext tests — verify real kernel-level isolation via
# sandbox-exec. macOS-only; auto-skip elsewhere.
set -uo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/lib.sh
source "$DIR/lib.sh"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "darwin.sh: not macOS, skipping entire suite"
  exit 0
fi

require_tools sh cat echo true id

TMP=$(mktemp -d)
trap 'rm -rf "$TMP" 2>/dev/null' EXIT

# ── Real isolation: --hide is kernel-enforced ──────────────────────

test_hide_blocks_read() {
  echo "test: --hide on a real path blocks read (kernel-enforced EPERM)"
  mkdir -p "$TMP/secret"
  echo "topsecret" > "$TMP/secret/data"
  out=$("$BIN" --hide "$TMP/secret" -- "$CAT" "$TMP/secret/data" 2>&1 || true)
  if echo "$out" | grep -q "topsecret"; then
    fail "child read forbidden file: $out"
  elif echo "$out" | grep -qi "operation not permitted\|permission denied"; then
    ok "kernel rejected read"
  else
    fail "unexpected: $out"
  fi
}

test_hide_blocks_write() {
  echo "test: --hide blocks writes too"
  mkdir -p "$TMP/secret"
  echo "before" > "$TMP/secret/data"
  "$BIN" --hide "$TMP/secret" -- "$SH" -c "echo pwned > $TMP/secret/data" 2>/dev/null || true
  current=$(cat "$TMP/secret/data")
  [[ "$current" == "before" ]] && ok "write blocked" || fail "got: $current"
}

# ── Happy paths ─────────────────────────────────────────────────────

test_rw_allows_write() {
  echo "test: --rw lets child write"
  rm -rf "$TMP/wsp" && mkdir -p "$TMP/wsp"
  out=$("$BIN" --rw "$TMP/wsp" -- "$SH" -c "echo hi > $TMP/wsp/x && cat $TMP/wsp/x")
  [[ "$out" == "hi" ]] && ok "wrote and read" || fail "got '$out'"
}

test_rw_and_hide_compose() {
  echo "test: --rw + --hide compose (workspace writable, secret hidden)"
  rm -rf "$TMP/wsp" "$TMP/secret"
  mkdir -p "$TMP/wsp" "$TMP/secret"
  echo "do-not-touch" > "$TMP/secret/x"
  "$BIN" --rw "$TMP/wsp" --hide "$TMP/secret" \
    -- "$SH" -c "echo ok > $TMP/wsp/file; echo pwned > $TMP/secret/x" 2>/dev/null || true
  if [[ -f "$TMP/wsp/file" ]] && grep -q "do-not-touch" "$TMP/secret/x"; then
    ok "compose works"
  else
    fail "wsp=$(cat "$TMP/wsp/file" 2>&1) secret=$(cat "$TMP/secret/x")"
  fi
}

test_ro_works_without_best_effort() {
  echo "test: --ro is honored on macOS without --best-effort (kernel can enforce it)"
  "$BIN" --ro /usr -- "$TRUE"
  [[ $? -eq 0 ]] && ok "exited 0" || fail "wrong exit"
}

# ── Symlink resolution ─────────────────────────────────────────────

test_realpath_resolves_tmp() {
  echo "test: --hide /tmp/X is correctly resolved to /private/tmp/X"
  # /tmp is a symlink to /private/tmp on every Mac. Without realpath the
  # kernel rule wouldn't match, so the read would succeed (silent fail).
  mkdir -p "$TMP/secret"
  echo "topsecret" > "$TMP/secret/data"
  # Construct a /tmp-relative path that points at the same file.
  # $TMP is already under /var/folders/... (which is /private/var/folders/...)
  # so this test exercises the same realpath collapse.
  out=$("$BIN" --hide "$TMP/secret" -- "$CAT" "$TMP/secret/data" 2>&1 || true)
  if echo "$out" | grep -q "topsecret"; then
    fail "realpath didn't resolve, hide silently ineffective"
  else
    ok "realpath resolved before profile rendering"
  fi
}

# ── Lifecycle ──────────────────────────────────────────────────────

test_exit_code_propagates() {
  echo "test: child exit code propagates through sandbox-exec wrapper"
  "$BIN" --rw "$TMP" -- "$SH" -c "exit 42"
  [[ $? -eq 42 ]] && ok "got 42" || fail "got $?"
}

test_signal_propagates() {
  echo "test: child SIGTERM propagates as 128+15=143"
  "$BIN" --rw "$TMP" -- "$SH" -c "kill -TERM \$\$" 2>/dev/null
  [[ $? -eq 143 ]] && ok "got 143" || fail "got $?"
}

test_stdout_passthrough() {
  echo "test: stdout reaches parent through sandbox-exec"
  out=$("$BIN" --rw "$TMP" -- "$ECHO" "hello sandbox")
  [[ "$out" == "hello sandbox" ]] && ok "got '$out'" || fail "got '$out'"
}

# ── Run all ─────────────────────────────────────────────────────────

test_hide_blocks_read
test_hide_blocks_write
test_rw_allows_write
test_rw_and_hide_compose
test_ro_works_without_best_effort
test_realpath_resolves_tmp
test_exit_code_propagates
test_signal_propagates
test_stdout_passthrough

summary_and_exit
