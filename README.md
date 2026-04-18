# uidjail

A portable filesystem sandbox for spawning untrusted subprocesses.

One static binary, ~215 KB, no runtime dependencies. Picks the strongest
backend available at runtime and fails loud when the requested guarantee
can't be delivered.

| Backend | When | What it does |
|---|---|---|
| **uid switch** | `--uid N` | `setresuid` / `setresgid` to the sandbox uid after dropping supplementary groups; the POSIX permission check enforces the boundary. Works on any UNIX kernel. Needs root at invocation time. |
| **Landlock** | `--allow-ro` / `--allow-rw` on Linux 5.13+ | Applies a Landlock LSM ruleset with path-beneath rules before exec. Works **unprivileged** — no root, no caps, no `--privileged` container flag. The only mechanism that works on Render, Fly, and other managed platforms. |
| **Defense in depth** | `--uid` + `--allow-*` on Linux with Landlock | Both layers active in the same child: kernel enforces uid drop AND path restrictions. |

## Example

```
uidjail \
  --uid 1001 \
  --allow-rw /var/lib/myapp/workspaces/job-42 \
  --allow-ro /usr --allow-ro /lib --allow-ro /lib64 --allow-ro /etc \
  -- /usr/local/bin/agent --mode rpc ...
```

On Linux, this runs `agent` with uid=1001 AND a Landlock domain that only
permits read+write under the workspace and read+exec under the system dirs.
Every other `open()` / `read()` / `write()` returns EACCES at the kernel
boundary.

On macOS (or Linux without Landlock), the same invocation drops to uid=1001
and chmods the allow-rw dir; Landlock is unavailable so `--allow-ro` is a
hard error — we refuse to run without the isolation you asked for.

## What it doesn't do

uidjail covers one thing: **a spawned subprocess reading or writing files
it shouldn't.** It explicitly does NOT:

- Isolate PIDs (use `unshare -p` or a container for that)
- Isolate networking (use iptables, nftables, or `unshare -n`)
- Limit resources (use cgroups or ulimit)
- Filter syscalls (use seccomp)
- Hide denied paths (uid-switch returns EACCES; Landlock returns EACCES)
- Sanitize the environment (env vars pass through — sanitize before invoking)
- Resolve users by name (pass numeric `--uid` / `--gid`)

If you need any of these, layer uidjail with the right tool for the job.
uidjail is the portable filesystem-isolation piece, not the whole stack.

## Why the three backends

Every sandboxing tool depends on a specific kernel mechanism:

- **bwrap / firejail / nsjail** — mount namespaces, need `CAP_SYS_ADMIN` or
  unprivileged user namespaces. Don't work on Render, Fly, Cloud Run, or
  any managed container platform that blocks namespace creation.
- **sandbox-exec** — macOS only.
- **Landlock (kernel LSM)** — unprivileged, works everywhere Linux 5.13+
  ships with the LSM enabled. Off by default on some enterprise distros
  (Oracle Linux UEK, some RHEL builds).
- **POSIX uid + permissions** — universal but requires root to set up.

uidjail treats these as a dispatch table: the caller states the guarantee
they want (`--uid` for uid switch, `--allow-*` for path isolation), and
uidjail picks what the host can deliver, or errors clearly.

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

Requires Zig 0.16+. Single static binary ~215 KB stripped, no runtime deps.

## CLI

```
Usage:
  uidjail [options] -- COMMAND [ARGS...]

Options:
  --uid N         Drop to this uid before exec (needs root).
  --gid N         Drop to this gid (defaults to --uid).
  --deny PATH     chmod 0700 this path (uid-switch mode only). Repeatable.
                  Nonexistent paths are no-ops.
  --allow-rw PATH Sandbox may read+write under PATH. Repeatable. Creates
                  the dir if missing, chmods 0700, chowns to sandbox uid.
                  Under Landlock, grants path-beneath rw+exec.
  --allow-ro PATH Sandbox may read+execute under PATH (Landlock-only).
                  Repeatable. Requires Linux 5.13+ with Landlock enabled.
  --cwd PATH      Working directory for the child.
  -h, --help      Show help.
  -V, --version   Show version.
```

## Examples

### Production: sandbox an agent on Render / Fly (no root, no privileged)

```
uidjail \
  --allow-rw /data/workspace \
  --allow-ro /usr --allow-ro /lib --allow-ro /lib64 --allow-ro /etc --allow-ro /bin \
  -- /app/agent
```

Kernel-enforced. Works inside a default Docker container.

### Self-hosted with root: belt-and-suspenders

```
uidjail \
  --uid 65534 \
  --allow-rw /data/workspace \
  --allow-ro /usr --allow-ro /lib --allow-ro /lib64 --allow-ro /etc \
  -- /app/agent
```

Child runs as nobody AND is Landlock-restricted. Two independent layers.

### Classic uid switch (macOS, older Linux without Landlock)

```
uidjail --uid 65534 --deny /etc/secrets -- cat /etc/secrets/api-key
# cat: /etc/secrets/api-key: Permission denied
```

## Threat model

uidjail assumes:

- The host kernel correctly enforces POSIX permissions AND (when used)
  Landlock path rules. I.e. the kernel is not compromised.
- The sandboxed subprocess cannot acquire CAP_DAC_OVERRIDE, CAP_FOWNER, or
  equivalent. uid switch guarantees this by dropping to an unprivileged uid;
  Landlock guarantees this via `PR_SET_NO_NEW_PRIVS`.
- setuid binaries the sandbox can exec cannot be used to escalate. `PR_SET_NO_NEW_PRIVS`
  (set by the Landlock path) makes this kernel-enforced. uid-switch alone
  does NOT set `PR_SET_NO_NEW_PRIVS`, so if you rely only on uid switch
  make sure the sandbox can't reach a vulnerable setuid binary.

uidjail does NOT assume:

- Any specific kernel version (uid-switch works everywhere; Landlock auto-skips
  on pre-5.13 kernels unless `--allow-ro` was requested, in which case we
  refuse to run).
- Any container runtime. Managed platforms (Render, Fly, Cloud Run) all work
  with the Landlock backend.

## Tests

```
zig build test                              # unit (Zig)
./tests/integration.sh                      # 9 end-to-end
./tests/security.sh                         # 27 probes (4 root-only, skipped)
./tests/harder.sh                           # 18 adversarial (4 root-only)
./tests/landlock.sh                         # 12 Landlock-backend probes (skipped
                                            #   on non-Landlock hosts)

# Root-only probes (prove the sandbox actually isolates):
sudo ./tests/security.sh
sudo ./tests/harder.sh
sudo ./tests/landlock.sh
```

CI runs all suites on macOS and Linux on every push. The Landlock suite runs
on ubuntu-latest (which ships Landlock enabled) and skips on hosts without it.

## License

MIT.
