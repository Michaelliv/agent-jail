# uidjail

A portable filesystem sandbox for spawning untrusted subprocesses.

uidjail uses POSIX uid and filesystem permissions — and only those. It works
identically on macOS, Linux, bare metal, Docker, rootless Docker, Render, Fly,
and anywhere else a UNIX kernel runs. No capabilities, no kernel features, no
runtime detection.

## What it does

```
uidjail \
  --uid 1001 \
  --deny /data \
  --allow-rw /data/workspaces/foo \
  --allow-rw /data/sessions/bar \
  -- /usr/local/bin/agent --mode rpc ...
```

Under the hood:

1. `chmod 0700` on every `--deny` path (chowned to caller when `--uid` is set).
2. `mkdir -p` + `chown uid:gid` + `chmod 0700` on every `--allow-rw` path.
3. `fork()`. In the child:
   - `chdir(--cwd)` if given.
   - `setpgid(0, 0)` — fresh process group so signal forwarding can reach the whole tree.
   - Close every FD ≥ 3 — nothing the caller had open leaks into the sandbox.
   - `setgroups(0, NULL)` — drop supplementary group list (else child stays in caller's groups, e.g. `wheel` or `0`).
   - `setresgid(gid)` then `setresuid(uid)` — kernel enforces; can't be undone.
   - `execvp(cmd, args)`.
4. In the parent: install signal handlers for TERM/INT/HUP/QUIT that forward
   to the child's process group, then `waitpid` and exit with its status.

Every `open()`, `read()`, `write()` against a denied path returns EACCES — the
kernel's permission check, the same code path that has enforced UNIX file
security since the 1970s. It cannot be bypassed by any userspace mechanism.

## What it doesn't do

uidjail covers exactly one threat: **a spawned subprocess reading or writing
files it shouldn't.** It explicitly does NOT:

- Isolate PIDs (the sandboxed process can `ps` and see other processes — it
  can't signal or read their memory, but it sees them)
- Isolate networking (use iptables, nftables, or `unshare -n` if you need it)
- Limit resources (use cgroups or ulimit)
- Drop capabilities (the sandbox uid has none to begin with)
- Filter syscalls (use seccomp if you need it)
- Hide denied paths (they return EACCES, not ENOENT)
- Sanitize the environment (env vars pass through; sanitize before invoking)
- Resolve users by name (pass numeric `--uid` / `--gid`)

If you need any of these, layer uidjail with the right tool for the job —
bwrap, firejail, nsjail, landlock, gVisor. uidjail is the portable foundation,
not the whole stack.

## Why it's portable

Every other sandbox tool depends on a specific kernel feature:

- **bwrap / firejail / nsjail** — mount namespaces, need `CAP_SYS_ADMIN` or
  unprivileged userns. Don't work on Render, Fly, Cloud Run, or any managed
  container platform.
- **landrun / island** — Landlock LSM, needs the kernel feature compiled AND
  enabled in the LSM stack. Off by default on Oracle Linux UEK and several
  other distros.
- **sandbox-exec** — macOS only.

POSIX uid + permissions is the one mechanism guaranteed to behave identically
on every UNIX. The kernel's `permission()` check is universal and cannot be
turned off.

## Install

```
zig build -Doptimize=ReleaseSmall
sudo cp zig-out/bin/uidjail /usr/local/bin/
```

Cross-compile:

```
zig build -Dtarget=x86_64-linux-musl   -Doptimize=ReleaseSmall
zig build -Dtarget=aarch64-linux-musl  -Doptimize=ReleaseSmall
zig build -Dtarget=x86_64-macos        -Doptimize=ReleaseSmall
zig build -Dtarget=aarch64-macos       -Doptimize=ReleaseSmall
```

Requires Zig 0.16+. Single static binary, ~210 KB stripped, no runtime deps.

## CLI

```
Usage:
  uidjail [options] -- COMMAND [ARGS...]

Options:
  --uid N         Sandbox uid; the child is dropped to this uid before exec.
  --gid N         Sandbox gid; defaults to --uid if omitted.
  --deny PATH     Path the sandboxed process must not access (chmod 0700).
                  Repeatable. Nonexistent paths are no-ops.
  --allow-rw PATH Path the sandboxed process can read+write. Created if
                  missing, chowned to sandbox uid, chmod 0700. Repeatable.
  --cwd PATH      Working directory for the child.
  -h, --help      Show help.
  -V, --version   Show version.
```

## Examples

### Run as nobody, deny `/etc/secrets`

```
uidjail --uid 65534 --deny /etc/secrets -- cat /etc/secrets/api-key
# cat: /etc/secrets/api-key: Permission denied
```

### Allow a workspace, deny everything sensitive

```
uidjail \
  --uid 1001 \
  --deny /var/lib/myapp \
  --allow-rw /var/lib/myapp/workspaces/job-42 \
  -- ./untrusted-script.sh
```

### Run unsandboxed (no `--uid`) — useful for `--allow-rw` setup as caller

```
uidjail --allow-rw /tmp/scratch -- /bin/sh -c 'echo hi > /tmp/scratch/x'
```

## Threat model

uidjail assumes:

- The host kernel correctly enforces POSIX file permissions (i.e. the kernel
  is not compromised).
- The sandboxed subprocess does not have CAP_DAC_OVERRIDE, CAP_FOWNER, or any
  way to escalate to root. uidjail enforces this by running the child as an
  unprivileged uid.
- The sandboxed subprocess cannot acquire setuid binaries on the system that
  let it bypass uid restrictions. If your `/usr/bin/sudo` is misconfigured to
  allow the sandbox uid to run arbitrary commands, uidjail does not protect
  you.

uidjail does NOT assume:

- Any specific kernel version
- Any specific LSM (SELinux, AppArmor, Landlock, etc.)
- Any specific container runtime
- Root is needed at runtime — only required when `--uid` is used (to call
  setuid/setgid) or when chowning paths the caller doesn't already own.

## Tests

Three suites, all expected green:

```
zig build test                              # unit
./tests/integration.sh                      # 9 end-to-end
./tests/security.sh                         # 27 (4 root-only, skipped if not root)
./tests/harder.sh                           # 18 (4 root-only, skipped if not root)

# Run root-only tests (the ones that prove the sandbox actually isolates):
sudo ./tests/security.sh
sudo ./tests/harder.sh
```

CI runs all of the above on macOS and Linux on every push.

## License

MIT.
