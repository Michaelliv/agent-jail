# agent-jail

A portable filesystem sandbox for spawning untrusted subprocesses.

One static binary, ~215 KB, no runtime dependencies. Picks the strongest
backend available at runtime and fails loud when the requested guarantee
can't be delivered — unless you pass `--best-effort`, in which case it
warns and continues with what the host can do.

## The one-line invocation

One command, runs everywhere — macOS, Linux, default Docker container,
managed platforms (Render, Fly), Oracle Linux:

```
agent-jail \
  --best-effort --system-ro \
  --rw /data/workspace \
  --rw /data/session \
  --hide /data/secrets \
  -- /app/agent
```

agent-jail applies every layer the host supports and warns on stderr for
every layer it can't. On Linux with Landlock: a kernel-enforced sandbox.
On macOS: a kernel-enforced sandbox via the Sandbox kext (sandbox-exec).
On managed container platforms: a Landlock sandbox with no root required.

## The flags

Three verbs describe what the sandbox can do with a path:

| Flag | Meaning |
|---|---|
| `--rw PATH` | Sandbox can read and write under `PATH`. Created if missing. Repeatable. |
| `--ro PATH` | Sandbox can read (and execute) under `PATH`. Enforced by Landlock or the macOS Sandbox kext. Repeatable. |
| `--hide PATH` | Sandbox can't touch `PATH`. Enforced by Landlock (default-deny), the macOS Sandbox kext, or POSIX uid-switch. Repeatable. |

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

## The layers

agent-jail composes up to four layers in one child, picked at runtime
from host support and flags.

| Layer | When it's used | What it does |
|---|---|---|
| **uid switch** | `--uid N` and caller is root | `setgroups(0)` / `setresgid` / `setresuid` in the child before exec; POSIX permission check enforces the boundary. Works on any UNIX kernel. |
| **Landlock** | `--rw` / `--ro` / `--system-ro` on Linux 5.13+ with the LSM enabled | Kernel-enforced path-beneath rules applied in the child before exec. Works **unprivileged** — no root, no caps, no `--privileged` container flag. The only mechanism that works on Render, Fly, and other managed platforms. |
| **PID namespace** | Any sandboxing flags on Linux with unprivileged user namespaces enabled (default on most distros + container runtimes) | Double-fork through `unshare(CLONE_NEWUSER \| CLONE_NEWNS \| CLONE_NEWPID)` so the child runs as PID 1 in a fresh PID namespace. The child's `/proc` only shows its own subtree, and `kill(2)` can only reach processes it itself spawned — sibling agents and the host are invisible and unreachable. |
| **Sandbox kext** | Any path verb on macOS | Renders an SBPL profile from `--rw`/`--ro`/`--hide` and exec's `sandbox-exec(1)`. The macOS kernel honors the rules the same way it does for Chromium and Docker. Works unprivileged. |

### Strict vs. best-effort

By default, agent-jail refuses to run when a requested guarantee (e.g.
`--ro` without Landlock) can't be enforced. `--best-effort` prints a
one-line stderr warning per missing layer and continues with what the
host can deliver. Capture stderr in production — that's how you find
out when a kernel update drops Landlock.

## What it doesn't do

agent-jail covers filesystem isolation (everywhere) and process-tree
isolation (Linux). It explicitly does NOT:

- Isolate networking (use iptables, nftables, or `unshare -n`)
- Limit resources (use cgroups or ulimit)
- Filter syscalls (use seccomp)
- Sanitize the environment (env vars pass through — sanitize before invoking)
- Resolve users by name (pass numeric `--uid` / `--gid`)

Layer agent-jail with the right tool when you need more.

## Why not bwrap / firejail / nsjail directly?

Every sandboxing tool depends on a specific kernel mechanism:

- **bwrap / firejail / nsjail** — mount namespaces, need `CAP_SYS_ADMIN`
  or unprivileged user namespaces. Don't work on Render, Fly, Cloud Run,
  or any managed container platform that blocks namespace creation.
- **sandbox-exec** — macOS only, profile DSL is Scheme with sparse docs.
- **Landlock** — Linux 5.13+ with the LSM enabled. Off by default on
  some enterprise distros (Oracle Linux UEK, some RHEL builds).
- **POSIX uid + permissions** — universal but requires root.

agent-jail treats these as a dispatch table: the caller states the
guarantee they want; agent-jail picks what the host can deliver, errors
clearly, or warns under `--best-effort`. On macOS it does drive
sandbox-exec under the hood — but you write `--rw`/`--ro`/`--hide` and
never touch SBPL.

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

## Tests

```
zig build test                              # unit (Zig)
./tests/integration.sh                      # 13 end-to-end
./tests/security.sh                         # 27 probes (4 root-only)
./tests/harder.sh                           # 18 adversarial (4 root-only)
./tests/landlock.sh                         # 11 Landlock-backend probes
./tests/pidns.sh                            # 4 PID-namespace probes (Linux only)
./tests/darwin.sh                           # 10 Sandbox-kext probes (macOS only)
./tests/edge.sh                             # 17 edge cases: SBPL injection,
                                            #   dotdot paths, stdin/stdout
                                            #   size, fork-bomb reaping,
                                            #   weird unicode, path-max, ...

# Root-only probes (prove the sandbox actually isolates):
sudo ./tests/security.sh
sudo ./tests/harder.sh
sudo ./tests/landlock.sh
```

CI runs all suites on macOS and Linux on every push.

## License

MIT.
