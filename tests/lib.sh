#!/usr/bin/env bash
# Shared helpers for agent-jail test suites. Source from each .sh under tests/.

BIN="${AGENT_JAIL_BIN:-./zig-out/bin/agent-jail}"

PASS=0
FAIL=0
SKIP=0

ok()   { echo "  ok    $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP  $1"; SKIP=$((SKIP+1)); }

is_root() { [[ $(id -u) -eq 0 ]]; }

# stat flags differ between GNU (Linux) and BSD (macOS). GNU `-c` first —
# on Linux `stat -f <path>` prints filesystem stats, not an error.
mode_of()  { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
owner_of() { stat -c '%u' "$1" 2>/dev/null || stat -f '%u'  "$1"; }

pick_unpriv_uid() {
  id -u nobody 2>/dev/null || id -u daemon 2>/dev/null || echo 65534
}

# Resolve portable absolute paths for common coreutils so tests work on both
# Linux (where /bin/true is a real file) and macOS (where it's at /usr/bin/true).
require_tools() {
  for tool in "$@"; do
    local path
    path=$(command -v "$tool") || { echo "missing tool: $tool" >&2; exit 1; }
    # Export uppercased variable: SH, CAT, etc. Dashes become underscores.
    local var
    var=$(echo "$tool" | tr '[:lower:]-' '[:upper:]_')
    # `pwd` and `id` collide with shell builtins → rename.
    case "$tool" in
      pwd) var=PWD_BIN ;;
      id) var=ID_BIN ;;
    esac
    printf -v "$var" '%s' "$path"
    export "$var"
  done
}

summary_and_exit() {
  echo
  echo "$PASS passed, $FAIL failed, $SKIP skipped"
  [[ $FAIL -eq 0 ]] && exit 0 || exit 1
}

# On Linux with Landlock enabled, agent-jail auto-applies a default-deny
# Landlock domain when --allow-rw or --allow-ro is used. Tests that spawn
# real commands (not just $TRUE) need read+exec on the system dirs the
# dynamic linker and libc come from, or exec fails.
#
# Usage:  "$BIN" --allow-rw "$TMP/wsp" $(landlock_system_ro) -- /bin/sh ...
#
# Prints the flags to stdout on Linux+Landlock hosts, empty otherwise.
# Using command substitution (not a bash array) sidesteps the `set -u`
# "unbound variable" footgun that hits empty array expansions.
landlock_system_ro() {
  if [[ "$(uname -s)" == "Linux" ]] && [[ -r /sys/kernel/security/lsm ]] \
     && grep -q landlock /sys/kernel/security/lsm; then
    echo "--allow-ro /usr --allow-ro /lib --allow-ro /lib64 --allow-ro /bin --allow-ro /etc"
  fi
}
