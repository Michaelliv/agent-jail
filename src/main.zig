//! agent-jail — portable filesystem sandbox for spawning untrusted subprocesses.
//!
//! Picks the strongest layers available at runtime: uid switch on any POSIX
//! host with root, Landlock on Linux 5.13+, a fresh PID namespace on Linux
//! with unprivileged user namespaces enabled, and the macOS Sandbox kext
//! via sandbox-exec on Darwin. Layers compose.
//!
//! Fail-loud by default: if a requested guarantee can't be delivered, we
//! refuse to run. --best-effort degrades to a stderr warning instead.

const std = @import("std");

const Args = @import("args.zig");
const sandbox = @import("sandbox.zig");

pub fn main(init: std.process.Init) !u8 {
    var stderr_buf: [1024]u8 = undefined;
    var stderr_w = std.Io.File.stderr().writer(init.io, &stderr_buf);
    const stderr = &stderr_w.interface;

    var stdout_buf: [256]u8 = undefined;
    var stdout_w = std.Io.File.stdout().writer(init.io, &stdout_buf);
    const stdout = &stdout_w.interface;

    var arena_state = std.heap.ArenaAllocator.init(init.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argv = try init.minimal.args.toSlice(arena);

    const parsed = Args.parse(arena, argv) catch |err| switch (err) {
        error.HelpRequested => {
            try printUsage(stderr);
            return 0;
        },
        error.VersionRequested => {
            try stdout.writeAll("agent-jail 0.4.0\n");
            try stdout.flush();
            return 0;
        },
        else => |e| {
            try stderr.print("agent-jail: {s}\n", .{@errorName(e)});
            try printUsage(stderr);
            return 2;
        },
    };

    if (parsed.command.len == 0) {
        try stderr.writeAll("agent-jail: missing command after --\n");
        try stderr.flush();
        return 2;
    }

    // --ro is enforced by Landlock (Linux) or the macOS Sandbox kext.
    // Without one of those, the kernel can't honor the read-only contract;
    // refuse to run unless --best-effort.
    const wants_ro = parsed.ro.len > 0;
    const plan = sandbox.pickPlan(parsed);
    const ro_enforced = switch (plan.backend) {
        .landlock, .uid_and_landlock, .sandbox_exec => true,
        .none, .uid_switch => false,
    };
    if (wants_ro and !ro_enforced) {
        if (parsed.best_effort) {
            try stderr.writeAll(
                \\agent-jail: warning: no kernel mechanism available to enforce
                \\  --ro/--system-ro on this host. Continuing under --best-effort.
                \\
            );
            try stderr.flush();
        } else {
            try stderr.writeAll(
                \\agent-jail: --ro needs Landlock (Linux 5.13+) or the macOS
                \\  Sandbox kext. Host lacks both. Pass --best-effort to proceed
                \\  without enforcement.
                \\
            );
            try stderr.flush();
            return 1;
        }
    }

    const ids: sandbox.Ids = .{
        .uid = parsed.uid orelse 0,
        .gid = parsed.gid orelse parsed.uid orelse 0,
    };

    sandbox.applyPermissions(parsed, ids) catch |err| {
        try stderr.print("agent-jail: applyPermissions failed: {s}\n", .{@errorName(err)});
        try stderr.flush();
        return 1;
    };

    return sandbox.spawnAndWait(init.gpa, parsed, ids, plan) catch |err| {
        try stderr.print("agent-jail: spawn failed: {s}\n", .{@errorName(err)});
        try stderr.flush();
        return 1;
    };
}

fn printUsage(w: *std.Io.Writer) !void {
    try w.writeAll(
        \\agent-jail — portable filesystem sandbox for spawning untrusted subprocesses
        \\
        \\Usage:
        \\  agent-jail [options] -- COMMAND [ARGS...]
        \\
        \\Paths (each repeatable):
        \\  --rw PATH              Sandbox may read+write under PATH. Created if
        \\                         missing, chmod'd to 0700, chown'd to --uid.
        \\  --ro PATH              Sandbox may read+execute under PATH.
        \\                         Enforced by Landlock only.
        \\  --list PATH            Sandbox may open PATH as a directory handle
        \\                         and list entries, but cannot read any file
        \\                         under it. Typically `--list /` so runtimes
        \\                         (Bun, Node, DuckDB) can resolve cwd without
        \\                         exposing the host filesystem for reads.
        \\                         No-op on macOS (default-allow covers it).
        \\  --hide PATH            Sandbox can't touch PATH. chmod 0700 under
        \\                         uid-switch; on Landlock the same effect is
        \\                         obtained by simply not granting PATH (the
        \\                         allowlist default-denies it).
        \\  --system-ro            Shorthand: --ro on standard system dirs
        \\                         (/usr /lib /lib64 /bin /sbin /etc /usr/sbin).
        \\                         Missing paths are skipped.
        \\
        \\Identity:
        \\  --uid N                Drop to this uid before exec (needs root).
        \\  --gid N                Drop to this gid (defaults to --uid).
        \\
        \\Process:
        \\  --cwd PATH             Working directory for the child.
        \\  --best-effort          Don't fail when a requested protection can't
        \\                         be delivered by the host. Warn once on stderr
        \\                         and continue with whatever backend(s) apply.
        \\
        \\Info:
        \\  -h, --help             Show this help.
        \\  -V, --version          Show version.
        \\
        \\Layers picked automatically at runtime (any combination):
        \\  uid switch      POSIX host where agent-jail runs as root
        \\  Landlock        Linux 5.13+ with the Landlock LSM enabled
        \\  PID namespace   Linux with unprivileged user namespaces enabled;
        \\                  child sees only its own subtree in /proc and
        \\                  can only signal processes it itself spawned
        \\  Sandbox kext    macOS via sandbox-exec(1); --rw/--ro/--hide are
        \\                  rendered into an SBPL profile the kernel enforces
        \\
        \\Idiomatic single-line invocation (works on every host with --best-effort):
        \\  agent-jail --best-effort --system-ro \\
        \\    --rw /data/workspace --rw /data/session --hide /data/vex \\
        \\    -- /app/agent
        \\
    );
    try w.flush();
}
