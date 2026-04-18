# agent-jail

A portable filesystem sandbox for spawning untrusted subprocesses.

One static binary, ~215 KB, no runtime dependencies. Picks the strongest
backend available at runtime and fails loud when the requested guarantee
can't be delivered — unless you pass `--best-effort`, in which case it
warns and continues with what the host can do.

## The one-line invocation

This single command is meant to run everywhere — macOS dev laptop, Linux
dev box, default Docker container, Render, Fly, Oracle Linux, anything:

```
agent-jail \
  --best-effort --system-ro \
  --rw /data/workspace \
  --rw /data/session \
  --hide /data/secrets \
  -- /app/agent
```

agent-jail applies every layer the host supports and prints a one-line
warning to stderr for every layer it can't. On Linux with Landlock it's
a kernel-enforced sandbox; on macOS it's a filesystem-setup primitive plus
a warning; on managed container platforms it's a Landlock sandbox with no
root required.

## The flags

Three verbs describe what the sandbox can do with a path:

| Flag | Meaning |
|---|---|
| `--rw PATH` | Sandbox can read and write under `PATH`. Created if missing, `chmod 0700`, `chown` to `--uid`. Repeatable. |
| `--ro PATH` | Sandbox can read (and execute) under `PATH`. Enforced by Landlock only. Repeatable. |
| `--hide PATH` | Sandbox can't touch `PATH`. `chmod 0700` under uid-switch; no-op under Landlock (default-deny). Repeatable. |

Plus one shorthand and some operational knobs:

| Flag | Meaning |
|---|---|
| `--system-ro` | Expands to `--ro` on `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/etc`, `/usr/sbin`. Paths that don't exist on this host are skipped. |
| `--uid N` | Drop to uid `N` before exec. Needs root. |
| `--gid N` | Drop to gid `N` (defaults to `--uid`). |
| `--cwd PATH` | Working directory for the child. |
| `--best-effort` | Don't fail when a requested protection can't be delivered. Warn once on stderr and continue with whatever backend(s) do apply. Without this flag, missing capabilities are fatal. |
| `-h, --help` | Show help. |
| `-V, --version` | Show version. |

## The backends

agent-jail doesn't have one "sandbox" mechanism — it picks from three at
runtime based on what the host supports and what you asked for.

| Backend | When it's used | What it does |
|---|---|---|
| **uid switch** | `--uid N` and caller is root | `setgroups(0)` / `setresgid` / `setresuid` in the child before exec; POSIX permission check enforces the boundary. Works on any UNIX kernel. |
| **Landlock** | `--rw` / `--ro` / `--system-ro` on Linux 5.13+ with the LSM enabled | Kernel-enforced path-beneath rules applied in the child before exec. Works **unprivileged** — no root, no caps, no `--privileged` container flag. The only mechanism that works on Render, Fly, and other managed platforms. |
| **Defense in depth** | `--uid` + `--rw`/`--ro` on Linux with Landlock | Both layers active in the same child: kernel enforces uid drop AND path restrictions. |

### Strict vs. best-effort

By default, if you ask for `--ro /usr` and the host doesn't have Landlock,
agent-jail refuses to run. That's deliberate: you asked for a guarantee,
and silently dropping it would ship a false sense of security.

`--best-effort` changes this: agent-jail prints a one-line warning per
missing layer and continues. Intended for calling code (like vex) that
wants one invocation to work across every host it might be deployed to
and is OK with degraded protection on weaker hosts.

When you run with `--best-effort` in production, you should also log
stderr so the warnings are visible — otherwise you won't notice when a
kernel update drops Landlock.

## What it doesn't do

agent-jail covers one thing: **a spawned subprocess reading or writing
files it shouldn't.** It explicitly does NOT:

- Isolate PIDs (use `unshare -p` or a container for that)
- Isolate networking (use iptables, nftables, or `unshare -n`)
- Limit resources (use cgroups or ulimit)
- Filter syscalls (use seccomp)
- Sanitize the environment (env vars pass through — sanitize before invoking)
- Resolve users by name (pass numeric `--uid` / `--gid`)

If you need any of these, layer agent-jail with the right tool for the
job. agent-jail is the portable filesystem-isolation piece, not the whole
stack.

## Why not bwrap / firejail / nsjail / sandbox-exec?

Every sandboxing tool depends on a specific kernel mechanism:

- **bwrap / firejail / nsjail** — mount namespaces, need `CAP_SYS_ADMIN`
  or unprivileged user namespaces. Don't work on Render, Fly, Cloud Run,
  or any managed container platform that blocks namespace creation.
- **sandbox-exec** — macOS only.
- **Landlock** — Linux 5.13+ with the LSM enabled. Off by default on
  some enterprise distros (Oracle Linux UEK, some RHEL builds).
- **POSIX uid + permissions** — universal but requires root.

agent-jail treats these as a dispatch table: the caller states the
guarantee they want, and agent-jail picks what the host can deliver (or
errors clearly, or warns under `--best-effort`).

## Install

```
zig build -Doptimize=ReleaseSmall
sudo cp zig-out/bin/agent-jail /usr/local/bin/
```

Cross-compile:

```
zig build -Dtarget=x86_64-linux-musl  -Doptimize=ReleaseSmall
zig build -Dtarget=aarch64-linux-musl -Doptimize=ReleaseSmall
zig build -Dtarget=x86_64-macos       -Doptimize=ReleaseSmall
zig build -Dtarget=aarch64-macos      -Doptimize=ReleaseSmall
```

Requires Zig 0.16+. Single static binary ~215 KB stripped, no runtime deps.

## Threat model

agent-jail assumes:

- The host kernel correctly enforces POSIX permissions AND (when used)
  Landlock path rules. I.e. the kernel is not compromised.
- The sandboxed subprocess cannot acquire `CAP_DAC_OVERRIDE`,
  `CAP_FOWNER`, or equivalent. uid switch guarantees this by dropping to
  an unprivileged uid; Landlock guarantees this via `PR_SET_NO_NEW_PRIVS`.
- setuid binaries the sandbox can exec cannot be used to escalate.
  `PR_SET_NO_NEW_PRIVS` (set by the Landlock path) makes this
  kernel-enforced. uid-switch alone does NOT set `PR_SET_NO_NEW_PRIVS`,
  so if you rely only on uid switch, make sure the sandbox can't reach a
  vulnerable setuid binary.

agent-jail does NOT assume any specific kernel version or container
runtime. Managed platforms all work with the Landlock backend.

## Tests

```
zig build test                              # unit (Zig)
./tests/integration.sh                      # 14 end-to-end
./tests/security.sh                         # 27 probes (4 root-only)
./tests/harder.sh                           # 18 adversarial (4 root-only)
./tests/landlock.sh                         # 11 Landlock-backend probes

# Root-only probes (prove the sandbox actually isolates):
sudo ./tests/security.sh
sudo ./tests/harder.sh
sudo ./tests/landlock.sh
```

CI runs all suites on macOS and Linux on every push. The Landlock suite
runs on ubuntu-latest (Landlock enabled) and skips on hosts without it.

## License

MIT.
