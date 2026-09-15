# Unix socket verification

## System exercised

`tests/unix-socket.py` invokes the built CLI. The real argument parser,
backend selection, profile renderer, fork/exec path, macOS sandbox, and
AF_UNIX sockets all participate. There are no mocked repository modules.
Linux fallback tests run in a standard ARM64 Docker container, without
extra capabilities. `AGENT_JAIL_BIN` selects the binary under test, as in
the shell suites.

## Test changes

Seven added scenarios: Unicode/control-character paths; missing CLI values;
invalid grants aborting the entire launch; directory grants not granting
subtrees; duplicate/reordered/129-entry allowlists; parallel independent
invocations; and symlink retargeting after a synchronized launch.

The descendant check is a separate test and forks a child rather than only
exec-replacing the shell. Datagram connect/sendto cases use independent
subtests. The no-flag control exercises both bare execution and an active
filesystem sandbox. These changes prevent an early failure from hiding a
later check or a control from bypassing the profile being tested.

Two added allocator-boundary tests inject failure at each allocation in
profile construction and filtered-path construction. They call the exported
helpers with Zig's checking/failing allocator, not mocked implementations.

## Mutation results

Each row changes production source in an isolated temporary copy, builds it,
runs the unchanged tests, and discards the copy. Every mutant built
successfully: build errors are not counted as detections. All 19 were
detected. The original checkout contains no mutations.

| ID | Deliberate break | Observed failure |
|---|---|---|
| M01 | Delete Unix default-deny rule | Foreign stream/datagram/sendto connections succeed; descendant, parallel, and retargeting denials fail |
| M02 | Turn endpoint allow rules into deny rules | Explicitly allowed stream/datagram connections fail |
| M03 | Drop `unix_sockets` while assembling the sandbox profile | Foreign connections succeed; invalid-grant launch executes |
| M04 | Skip invalid grants instead of aborting | Empty/missing/dangling/cyclic/oversized grants launch the marker command, in strict and best-effort modes |
| M05 | Use supplied path instead of its canonical path | `/tmp` and symlink grants fail to connect to their allowed endpoints |
| M06 | Replace `literal` with `subpath` | A directory grant permits a foreign socket beneath it |
| M07 | Remove quote/backslash escaping | Special-character endpoint grants fail through the real profile compiler |
| M08 | Truncate the allowlist to 64 entries | The endpoint at entry 129 is denied |
| M09 | Emit Unix default-deny with no socket flags | Socket access fails under an unrelated filesystem sandbox |
| M10 | Deny all outbound networking instead of Unix sockets only | The local TCP control fails |
| M11 | Consume `--` as a flag value | Missing-value assertions fail for all eight value-taking flags |
| M12 | Drop socket policy under `--best-effort` | Foreign sockets become reachable on macOS; invalid grants launch |
| M13 | Remove refusal of unsupported strict mode | Linux strict invocation succeeds instead of returning 1 |
| M14 | Delete degradation warning | Linux best-effort warning assertion fails |
| M15 | Refuse unsupported best-effort too | Linux best-effort invocation exits 1 instead of connecting |
| M16 | Return profile `ArrayList.items` rather than an owned slice | Zig allocator detects an invalid free |
| M17 | Return filtered-path `ArrayList.items` rather than an owned slice | Zig allocator detects an invalid free |
| M18 | Remove profile cleanup on error | Zig allocator detects leaks on invalid grants and injected allocation failures |
| M19 | Remove filtered-path cleanup on error | Allocation-failure sweep detects a leaked path-list allocation |

M01–M12 run through the macOS CLI, M13–M15 through the Linux CLI, and
M16–M19 through allocator-contract unit tests. Memory ownership
is not observable through the short-lived CLI because its arena hides
incorrect individual frees; those tests therefore use the exported helper
contracts with Zig's real checking allocator.

Local detailed evidence: `/tmp/jail-mutation-evidence/M01.log` through
`M19.log`, plus `results.json` with exact before/after source replacements.
The temporary mutation driver is `/tmp/run-jail-mutations.py`.

## Restored-build verification

- Zig unit tests: 28 passed, 2 platform skips; all build steps succeeded.
- macOS socket CLI suite: 16 passed, 1 Linux-only skip.
- Linux socket CLI suite: 3 passed, 14 macOS-only skips, both as UID 0 and UID 65534.
- All existing shell suites invoked on macOS exit 0; their platform/root-only skips remain explicit.
- ReleaseSmall builds succeed for x86_64/aarch64 Linux-musl and x86_64/aarch64 macOS.
- Changed Zig files pass formatting; `git diff --check` passes.

## Limits — not an exhaustive proof

- Every added behavioral test has been observed failing against a relevant
  mutation. This does not mean every supporting assertion (for example,
  startup-handshake diagnostics) was independently mutation-tested.
- Linux socket enforcement is absent. Tests prove refusal/warning behavior,
  not isolation. No test claims otherwise.
- The socket grant is a pathname grant, not immutable endpoint identity.
  The caller must protect the canonical endpoint and its parent directories
  against replacement. Symlink retargeting is tested, but replacement at
  the canonical allowed pathname is outside the guarantee.
- Allocation failures are swept for the two changed allocation-returning
  helpers with representative inputs. This is not a process-wide OOM test.
  Fork failure, signal timing, and every kernel/SBPL failure are not injected.
- Parallel invocations and one synchronized retargeting interleaving are
  covered; this is not an exploration of all scheduler interleavings.
- The suite exercises 129 grants and a 5001-byte invalid path, not the OS
  maximum argv/profile/socket-path sizes. The implementation specifies no
  application count cap. Resource exhaustion at OS limits remains unproven.
- Native enforcement is verified on the current ARM64 macOS host; all four
  targets compile, but x86_64 runtime enforcement and other macOS releases
  require their own machines. Privileged macOS callers are not exercised.
