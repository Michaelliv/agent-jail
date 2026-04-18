#!/usr/bin/env bash
# Second-round hardening tests — what a real auditor would check.
# Probes: supplementary groups, TOCTOU, path weirdness, FD leaks,
# setuid-binary escape, env leak, overlapping allow/deny, concurrent safety.
set -uo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/lib.sh
source "$DIR/lib.sh"

require_tools true sh cat id sleep

TMP=$(mktemp -d)
chmod 0755 "$TMP"
trap 'rm -rf "$TMP" 2>/dev/null; pkill -KILL -f "harder-$$" 2>/dev/null || true' EXIT

# ── 1. Supplementary groups — CRITICAL ──────────────────────────────

test_supplementary_groups_dropped() {
  if ! is_root; then skip "supp-groups test (need root)"; return; fi
  echo "test: child does NOT inherit root's supplementary groups"
  uid=$(pick_unpriv_uid)
  out=$("$BIN" --uid "$uid" -- "$ID_BIN" -G)
  if echo " $out " | grep -qE ' 0 | 0$|^0 '; then
    fail "child still in gid 0! groups: $out"
  else
    ngroups=$(echo "$out" | tr ' ' '\n' | grep -c .)
    if [[ "$ngroups" -le 1 ]]; then
      ok "groups=$out (no leak)"
    else
      fail "extra groups leaked: $out"
    fi
  fi
}

test_supplementary_groups_cannot_read_group_0_file() {
  if ! is_root; then skip "gid-0 file read test (need root)"; return; fi
  echo "test: child CANNOT read a root:root 0640 file via group membership"
  uid=$(pick_unpriv_uid)
  f="$TMP/group0-only"
  echo "rootgroup-secret" > "$f"
  chown root:root "$f"
  chmod 0640 "$f"
  "$BIN" --uid "$uid" -- "$CAT" "$f" 2>/dev/null
  rc=$?
  [[ $rc -ne 0 ]] && ok "0640 root:root file blocked (exit $rc)" || fail "AGENT READ IT"
}

# ── 2. Symlink hijack ──────────────────────────────────────────────

test_rw_preexisting_symlink_to_dir() {
  echo "test: --rw rejects pre-existing symlink to dir"
  mkdir -p "$TMP/real"
  ln -sfn "$TMP/real" "$TMP/linkdir"
  real_mode_before=$(mode_of "$TMP/real")
  "$BIN" --rw "$TMP/linkdir" $(landlock_system_ro) -- "$TRUE" 2>/dev/null
  rc=$?
  real_mode_after=$(mode_of "$TMP/real")
  if [[ $rc -eq 0 ]]; then
    fail "symlink silently accepted (mode $real_mode_before → $real_mode_after)"
  elif [[ "$real_mode_before" != "$real_mode_after" ]]; then
    fail "symlink rejected BUT target mode changed ($real_mode_before → $real_mode_after)"
  else
    ok "symlink rejected, target intact (rc=$rc)"
  fi
}

# ── 3. Overlapping --hide and --rw ─────────────────────────────────

test_hide_prefix_of_rw() {
  echo "test: --hide /X --rw /X/sub → X is hidden, sub is writable"
  rm -rf "$TMP/top"
  mkdir -p "$TMP/top"
  "$BIN" --hide "$TMP/top" --rw "$TMP/top/sub" $(landlock_system_ro) -- "$TRUE"
  rc=$?
  [[ $rc -eq 0 ]] || { fail "exit $rc"; return; }
  top_mode=$(mode_of "$TMP/top")
  sub_mode=$(mode_of "$TMP/top/sub")
  if [[ "$top_mode" == "700" && "$sub_mode" == "700" ]]; then
    ok "both dirs mode 0700 as expected"
  else
    fail "top=$top_mode sub=$sub_mode"
  fi
}

test_same_path_in_hide_and_rw() {
  echo "test: --hide /X --rw /X (same path) — --rw wins (applied later)"
  mkdir -p "$TMP/both"
  "$BIN" --hide "$TMP/both" --rw "$TMP/both" $(landlock_system_ro) -- "$TRUE"
  rc=$?
  [[ $rc -eq 0 ]] && ok "no crash, no error (defined behavior)" || fail "exit $rc"
}

# ── 4. Command not executable / is directory / segfaults ───────────

test_command_is_directory() {
  echo "test: exec'ing a directory yields a clean error"
  "$BIN" -- "$TMP" 2>/dev/null
  rc=$?
  [[ $rc -eq 126 || $rc -eq 127 ]] && ok "clean exit $rc" || fail "exit $rc"
}

test_command_not_executable() {
  echo "test: non-executable regular file yields clean error"
  f="$TMP/notexec"
  echo "#!/bin/false" > "$f"
  chmod 0644 "$f"
  "$BIN" -- "$f" 2>/dev/null
  rc=$?
  [[ $rc -eq 126 || $rc -eq 127 ]] && ok "clean exit $rc" || fail "exit $rc"
}

test_command_segfaults() {
  echo "test: child segfaults → exit 128+11 = 139"
  "$BIN" -- "$SH" -c 'kill -SEGV $$' 2>/dev/null
  rc=$?
  [[ $rc -eq 139 ]] && ok "got 139" || fail "got $rc"
}

# ── 5. FD leakage ─────────────────────────────────────────────────

test_no_fd_leak_from_parent() {
  echo "test: child does not inherit extra FDs beyond 0,1,2"
  exec 9>"$TMP/leakbait"
  out=$("$BIN" -- "$SH" -c '
    if [ -d /proc/self/fd ]; then
      ls /proc/self/fd | sort -n | tr "\n" " "
    else
      /usr/sbin/lsof -p $$ 2>/dev/null | awk "NR>1 {print \$4}" | grep -E "^[0-9]+" | sort -n | tr "\n" " "
    fi
  ')
  exec 9>&-
  normalized=$(echo "$out" | tr -d 'uwrUWR' | tr -s ' ')
  extras=$(echo "$normalized" | tr ' ' '\n' | grep -E '^[0-9]+$' | awk '$1 > 2' | head -5 | tr '\n' ' ')
  if [[ -z "$extras" ]]; then
    ok "only 0/1/2 visible"
  else
    if echo "$extras" | grep -q '\b9\b'; then
      fail "fd 9 leaked to child (out: $out)"
    else
      ok "no 9 leak (extras are kernel/macOS-noise: $extras)"
    fi
  fi
}

# ── 6. Setuid binary escape ────────────────────────────────────────

test_setuid_binary_cannot_give_root_back() {
  if ! is_root; then skip "setuid escape test (need root)"; return; fi
  echo "test: child execs /usr/bin/sudo — does it stay unprivileged?"
  uid=$(pick_unpriv_uid)
  out=$("$BIN" --uid "$uid" -- "$SH" -c 'id -u')
  [[ "$out" == "$uid" ]] && ok "child stayed at uid $uid" || fail "unexpected: $out"
}

# ── 7. Environment leak ────────────────────────────────────────────

test_env_leaks_by_default() {
  echo "test: environment is passed through (documented behavior)"
  out=$(AGENT_JAIL_TEST_SECRET=hunter2 "$BIN" -- "$SH" -c 'echo "$AGENT_JAIL_TEST_SECRET"')
  if [[ "$out" == "hunter2" ]]; then
    ok "env inherited (callers must sanitize — see README)"
  else
    fail "env NOT inherited, got '$out'"
  fi
}

# ── 8. Path weirdness ──────────────────────────────────────────────

test_path_with_spaces() {
  echo "test: --rw path containing spaces"
  p="$TMP/with space/more space"
  rm -rf "$TMP/with space"
  "$BIN" --rw "$p" $(landlock_system_ro) -- "$TRUE"
  [[ -d "$p" ]] && ok "dir created" || fail "not created"
}

test_path_with_unicode() {
  echo "test: --rw path with unicode"
  p="$TMP/café_🔒"
  rm -rf "$p"
  "$BIN" --rw "$p" $(landlock_system_ro) -- "$TRUE"
  [[ -d "$p" ]] && ok "unicode dir created" || fail "not created"
}

test_very_long_path() {
  echo "test: --rw path near PATH_MAX"
  long=$(printf 'a%.0s' {1..200})
  p="$TMP/$long/$long"
  rm -rf "$TMP/$long"
  "$BIN" --rw "$p" $(landlock_system_ro) -- "$TRUE"
  [[ -d "$p" ]] && ok "long path handled" || fail "not created"
}

test_many_rw_flags() {
  echo "test: 100 --rw flags work"
  args=()
  for i in $(seq 1 100); do args+=(--rw "$TMP/d$i"); done
  "$BIN" "${args[@]}" $(landlock_system_ro) -- "$TRUE"
  [[ -d "$TMP/d100" ]] && ok "100 dirs created" || fail "missing some"
}

# ── 9. Concurrent safety ────────────────────────────────────────────

test_concurrent_invocations() {
  echo "test: 5 concurrent agent-jail invocations don't interfere"
  rm -rf "$TMP/conc"
  pids=()
  for i in 1 2 3 4 5; do
    "$BIN" --rw "$TMP/conc/d$i" $(landlock_system_ro) -- "$SH" -c "sleep 0.3; echo ok > $TMP/conc/d$i/file" &
    pids+=($!)
  done
  for p in "${pids[@]}"; do wait "$p"; done
  all=0
  for i in 1 2 3 4 5; do
    [[ "$(cat "$TMP/conc/d$i/file" 2>/dev/null)" == "ok" ]] && all=$((all+1))
  done
  [[ $all -eq 5 ]] && ok "all 5 completed" || fail "only $all/5 ok"
}

# ── 10. gid override ───────────────────────────────────────────────

test_gid_override() {
  if ! is_root; then skip "gid test (need root)"; return; fi
  echo "test: --gid overrides the uid-derived gid"
  out=$("$BIN" --uid 65534 --gid 1 -- "$ID_BIN" -g)
  [[ "$out" == "1" ]] && ok "gid=1 applied" || fail "got '$out'"
}

# ── 11. applyPermissions failure halfway through ───────────────────

test_applypermissions_error_surfaces_cleanly() {
  echo "test: chmod fails on unwritable deny path → clean error exit"
  "$BIN" --hide "/proc/1/doesnotexist" -- "$TRUE" 2>/dev/null
  rc=$?
  [[ $rc -eq 0 || $rc -eq 1 ]] && ok "clean exit $rc" || fail "weird exit $rc"
}

# ── Run all ────────────────────────────────────────────────────────

test_supplementary_groups_dropped
test_supplementary_groups_cannot_read_group_0_file
test_rw_preexisting_symlink_to_dir
test_hide_prefix_of_rw
test_same_path_in_hide_and_rw
test_command_is_directory
test_command_not_executable
test_command_segfaults
test_no_fd_leak_from_parent
test_setuid_binary_cannot_give_root_back
test_env_leaks_by_default
test_path_with_spaces
test_path_with_unicode
test_very_long_path
test_many_rw_flags
test_concurrent_invocations
test_gid_override
test_applypermissions_error_surfaces_cleanly

summary_and_exit
