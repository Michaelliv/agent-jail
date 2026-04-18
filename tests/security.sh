#!/usr/bin/env bash
# Adversarial security + edge-case tests for agent-jail. Probes the actual
# security properties: do denies actually deny? does uid drop actually drop?
# do symlinks trick us? etc. Root-only tests skip cleanly if not root.
set -uo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/lib.sh
source "$DIR/lib.sh"

require_tools true echo sleep sh cat pwd id

TMP=$(mktemp -d)
# When running as root, mktemp creates 0700 — an unprivileged child can't
# traverse it to reach --allow-rw dirs inside. Make it traversable for the
# root-mode tests (the sandbox dirs themselves stay 0700 via agent-jail).
chmod 0755 "$TMP"
trap 'rm -rf "$TMP" 2>/dev/null' EXIT

# ── Argument parsing edge cases ────────────────────────────────────

test_empty_args() {
  echo "test: just '--' with no command"
  "$BIN" -- 2>/dev/null
  [[ $? -eq 2 ]] && ok "exit 2 on empty command" || fail "wrong exit $?"
}

test_double_dash_in_command() {
  echo "test: '--' appearing after the first '--' is treated as command arg"
  out=$("$BIN" -- "$ECHO" -- foo)
  [[ "$out" == "-- foo" ]] && ok "got '$out'" || fail "got '$out'"
}

test_flag_after_separator_is_arg() {
  echo "test: --uid AFTER -- is passed to child verbatim"
  out=$("$BIN" -- "$ECHO" --uid 99)
  [[ "$out" == "--uid 99" ]] && ok "got '$out'" || fail "got '$out'"
}

test_uid_negative() {
  echo "test: --uid -1 is rejected"
  "$BIN" --uid -1 -- "$TRUE" 2>/dev/null
  [[ $? -eq 2 ]] && ok "rejected negative uid" || fail "wrong exit $?"
}

test_uid_garbage() {
  echo "test: --uid notanumber is rejected"
  "$BIN" --uid notanumber -- "$TRUE" 2>/dev/null
  [[ $? -eq 2 ]] && ok "rejected non-numeric uid" || fail "wrong exit $?"
}

test_uid_huge() {
  echo "test: --uid 999999999999999 is rejected (overflow u32)"
  "$BIN" --uid 999999999999999 -- "$TRUE" 2>/dev/null
  [[ $? -eq 2 ]] && ok "rejected overflow uid" || fail "wrong exit $?"
}

test_value_starts_with_dash() {
  echo "test: --deny --uid is taken as a value (path), not flag"
  mkdir -p "$TMP/--uid"
  "$BIN" --cwd "$TMP" --deny "--uid" -- "$TRUE"
  [[ $? -eq 0 ]] && ok "treats '--uid' as path value" || fail "wrong exit $?"
}

test_repeated_flags_last_wins_for_scalars() {
  echo "test: repeated --cwd uses the last one"
  out=$("$BIN" --cwd /tmp --cwd "$TMP" -- "$PWD_BIN")
  [[ "$out" == "$TMP" || "$out" == "/private$TMP" ]] && ok "last --cwd won" || fail "got '$out'"
}

test_repeated_deny_accumulate() {
  echo "test: repeated --allow-rw all get applied"
  rm -rf "$TMP/a" "$TMP/b" "$TMP/c"
  "$BIN" --allow-rw "$TMP/a" --allow-rw "$TMP/b" --allow-rw "$TMP/c" -- "$TRUE"
  [[ -d "$TMP/a" && -d "$TMP/b" && -d "$TMP/c" ]] && ok "all 3 dirs created" || fail "missing dirs"
}

# ── Behavioral / safety properties ──────────────────────────────────

test_command_not_found() {
  echo "test: nonexistent command surfaces as spawn error"
  "$BIN" -- /no/such/binary/anywhere 2>/dev/null
  rc=$?
  # 127 is the POSIX shell convention for "command not found".
  [[ $rc -eq 127 ]] && ok "exit 127 on missing binary" || fail "got exit $rc"
}

test_signal_to_child() {
  echo "test: child killed by SIGTERM (15) → exit 128+15 = 143"
  "$BIN" -- "$SH" -c 'kill -TERM $$' 2>/dev/null
  rc=$?
  [[ $rc -eq 143 ]] && ok "got 143" || fail "got $rc"
}

test_no_shell_interpretation_of_args() {
  echo "test: argv is passed literally — no shell expansion"
  out=$("$BIN" -- "$ECHO" '$HOME `id` $(whoami)')
  [[ "$out" == '$HOME `id` $(whoami)' ]] && ok "literal" || fail "got '$out'"
}

test_long_command_line() {
  echo "test: large argv is handled"
  args=()
  for i in $(seq 1 500); do args+=("arg$i"); done
  out=$("$BIN" -- "$ECHO" "${args[@]}" | wc -w | tr -d ' ')
  [[ "$out" -eq 500 ]] && ok "all 500 args delivered" || fail "got $out words"
}

test_stderr_separation() {
  echo "test: child stderr stays separate from stdout"
  out=$("$BIN" -- "$SH" -c 'echo OUT; echo ERR >&2' 2>"$TMP/err")
  err=$(cat "$TMP/err")
  [[ "$out" == "OUT" && "$err" == "ERR" ]] && ok "streams separate" || fail "out='$out' err='$err'"
}

test_stdin_passthrough() {
  echo "test: stdin reaches child"
  out=$(echo "ping" | "$BIN" -- "$CAT")
  [[ "$out" == "ping" ]] && ok "stdin reached child" || fail "got '$out'"
}

# ── Filesystem permission setup ─────────────────────────────────────

test_allow_rw_owner_when_no_uid_switch() {
  echo "test: --allow-rw without --uid leaves owner as caller"
  rm -rf "$TMP/wsp"
  "$BIN" --allow-rw "$TMP/wsp" -- "$TRUE"
  owner=$(owner_of "$TMP/wsp")
  caller=$(id -u)
  [[ "$owner" == "$caller" ]] && ok "owned by caller ($owner)" || fail "owner=$owner expected=$caller"
}

test_allow_rw_pre_existing_keeps_contents() {
  echo "test: --allow-rw on pre-existing dir doesn't wipe contents"
  rm -rf "$TMP/wsp"
  mkdir -p "$TMP/wsp"
  echo "before" > "$TMP/wsp/file"
  "$BIN" --allow-rw "$TMP/wsp" -- "$TRUE"
  out=$(cat "$TMP/wsp/file")
  [[ "$out" == "before" ]] && ok "contents preserved" || fail "lost contents"
}

test_allow_rw_nested_creates_parents() {
  echo "test: --allow-rw on nested path creates the chain"
  rm -rf "$TMP/a"
  "$BIN" --allow-rw "$TMP/a/b/c/d" -- "$TRUE"
  [[ -d "$TMP/a/b/c/d" ]] && ok "deep dir created" || fail "not created"
}

test_allow_rw_mode_is_0700() {
  echo "test: --allow-rw dir ends up with mode 0700"
  rm -rf "$TMP/wsp"
  "$BIN" --allow-rw "$TMP/wsp" -- "$TRUE"
  m=$(mode_of "$TMP/wsp")
  [[ "$m" == "700" ]] && ok "mode 0700" || fail "mode is $m"
}

# ── Symlink hazard ─────────────────────────────────────────────────

test_allow_rw_symlink_to_outside() {
  echo "test: --allow-rw rejects pre-existing symlink (no silent hijack)"
  rm -rf "$TMP/victim" "$TMP/link"
  echo "important" > "$TMP/victim"
  before_mode=$(mode_of "$TMP/victim")
  ln -s "$TMP/victim" "$TMP/link"
  "$BIN" --allow-rw "$TMP/link" -- "$TRUE" 2>/dev/null
  rc=$?
  after_mode=$(mode_of "$TMP/victim")
  if [[ "$before_mode" != "$after_mode" ]]; then
    fail "symlink followed: $TMP/victim mode $before_mode → $after_mode (HAZARD)"
  elif [[ $rc -eq 0 ]]; then
    fail "symlink accepted silently (exit 0) — victim mode unchanged but that's luck"
  else
    ok "symlink at allow-rw path rejected (exit $rc, victim mode $after_mode)"
  fi
}

test_deny_does_not_create() {
  echo "test: --deny on nonexistent path is a no-op (doesn't create)"
  rm -rf "$TMP/nope"
  "$BIN" --deny "$TMP/nope" -- "$TRUE"
  rc=$?
  [[ $rc -eq 0 && ! -e "$TMP/nope" ]] && ok "no-op on missing path" || fail "rc=$rc"
}

test_deny_existing_chmods_700() {
  echo "test: --deny on existing dir chmods to 0700"
  rm -rf "$TMP/secret"
  mkdir -p "$TMP/secret"
  chmod 0755 "$TMP/secret"
  "$BIN" --deny "$TMP/secret" -- "$TRUE"
  m=$(mode_of "$TMP/secret")
  [[ "$m" == "700" ]] && ok "chmod to 700" || fail "mode is $m"
}

# ── Real sandbox guarantee (requires root) ──────────────────────────

test_uid_drop_actually_isolates() {
  if ! is_root; then skip "uid drop test (need root)"; return; fi
  echo "test: child runs as the requested uid"
  uid=$(pick_unpriv_uid)
  out=$("$BIN" --uid "$uid" -- "$ID_BIN" -u)
  [[ "$out" == "$uid" ]] && ok "child id -u == $uid" || fail "got '$out'"
}

test_uid_drop_blocks_root_files() {
  if ! is_root; then skip "deny enforcement test (need root)"; return; fi
  echo "test: child as unpriv uid CANNOT read root-owned 0700 dir"
  uid=$(pick_unpriv_uid)
  rm -rf "$TMP/secret"
  mkdir -p "$TMP/secret"
  echo "topsecret" > "$TMP/secret/data"
  "$BIN" --uid "$uid" --deny "$TMP/secret" -- "$CAT" "$TMP/secret/data" 2>/dev/null
  rc=$?
  [[ $rc -ne 0 ]] && ok "read denied (exit $rc)" || fail "AGENT READ DENIED FILE"
}

test_uid_drop_blocks_workspace_escape() {
  if ! is_root; then skip "workspace escape test (need root)"; return; fi
  echo "test: child can write workspace, CANNOT write deny dir"
  uid=$(pick_unpriv_uid)
  rm -rf "$TMP/secret" "$TMP/wsp"
  mkdir -p "$TMP/secret"
  echo "do-not-touch" > "$TMP/secret/important"
  "$BIN" --uid "$uid" --deny "$TMP/secret" --allow-rw "$TMP/wsp" \
    -- "$SH" -c "echo allowed > $TMP/wsp/ok; echo pwn3d > $TMP/secret/important" 2>/dev/null
  if [[ -f "$TMP/wsp/ok" ]] && grep -q "do-not-touch" "$TMP/secret/important"; then
    ok "workspace writable, deny dir untouched"
  else
    fail "workspace=$(cat "$TMP/wsp/ok" 2>&1) secret=$(cat "$TMP/secret/important")"
  fi
}

test_uid_drop_cannot_re_elevate() {
  if ! is_root; then skip "re-elevation test (need root)"; return; fi
  echo "test: child as unpriv uid cannot setuid back to 0"
  uid=$(pick_unpriv_uid)
  if command -v perl >/dev/null; then
    out=$("$BIN" --uid "$uid" -- /usr/bin/perl -e 'POSIX::setuid(0); print($> == 0 ? "ELEVATED" : "ok\n");' 2>&1)
    if [[ "$out" == *"ELEVATED"* ]]; then
      fail "child re-elevated to root!"
    else
      ok "re-elevation blocked"
    fi
  else
    skip "perl not available"
  fi
}

# ── Process lifecycle ──────────────────────────────────────────────

test_killing_agent_jail_reaps_child() {
  echo "test: SIGTERM to agent-jail terminates the long-running child"
  marker="agent-jail-reap-test-$$-$RANDOM"
  "$BIN" -- "$SH" -c "exec -a $marker $SLEEP 30" &
  parent_pid=$!
  sleep 0.5
  kill -TERM "$parent_pid" 2>/dev/null
  sleep 1.5
  if ps -p "$parent_pid" >/dev/null 2>&1; then
    fail "parent $parent_pid still alive"
    return
  fi
  if pgrep -f "$marker" >/dev/null 2>&1; then
    fail "child orphaned after parent killed ($(pgrep -f "$marker"))"
    pkill -KILL -f "$marker" 2>/dev/null
  else
    ok "child reaped"
  fi
  wait 2>/dev/null || true
}

# ── Run all ─────────────────────────────────────────────────────────

test_empty_args
test_double_dash_in_command
test_flag_after_separator_is_arg
test_uid_negative
test_uid_garbage
test_uid_huge
test_value_starts_with_dash
test_repeated_flags_last_wins_for_scalars
test_repeated_deny_accumulate
test_command_not_found
test_signal_to_child
test_no_shell_interpretation_of_args
test_long_command_line
test_stderr_separation
test_stdin_passthrough
test_allow_rw_owner_when_no_uid_switch
test_allow_rw_pre_existing_keeps_contents
test_allow_rw_nested_creates_parents
test_allow_rw_mode_is_0700
test_allow_rw_symlink_to_outside
test_deny_does_not_create
test_deny_existing_chmods_700
test_uid_drop_actually_isolates
test_uid_drop_blocks_root_files
test_uid_drop_blocks_workspace_escape
test_uid_drop_cannot_re_elevate
test_killing_agent_jail_reaps_child

summary_and_exit
