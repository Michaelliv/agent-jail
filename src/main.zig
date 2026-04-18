//! agent-jail — portable filesystem sandbox for spawning untrusted subprocesses.
//!
//! Picks the strongest backend available at runtime: uid switch on any
//! POSIX host with root, Landlock on Linux 5.13+, or both layered.
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
            try stdout.writeAll("agent-jail 0.1.1\n");
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

    // --ro requires Landlock. Without --best-effort, refuse to run when
    // it isn't available; with it, warn and continue.
    const wants_landlock = parsed.ro.len > 0;
    const backend = sandbox.pickBackend(parsed);
    const have_landlock = backend == .landlock or backend == .uid_and_landlock;
    if (wants_landlock and !have_landlock) {
        if (parsed.best_effort) {
            try stderr.writeAll(
                \\agent-jail: warning: Landlock unavailable on this host;
                \\  --ro/--system-ro paths will not be enforced. Continuing
                \\  under --best-effort with remaining layers (if any).
                \\
            );
            try stderr.flush();
        } else {
            try stderr.writeAll(
                \\agent-jail: --ro requires Landlock (Linux 5.13+ with
                \\  CONFIG_SECURITY_LANDLOCK=y and 'landlock' in the LSM list).
                \\  Host lacks support. Pass --best-effort to proceed without it.
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

    return sandbox.spawnAndWait(init.gpa, parsed, ids) catch |err| {
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
        \\  --hide PATH            Sandbox can't touch PATH. chmod 0700 under
        \\                         uid-switch; no-op under Landlock (default-deny).
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
        \\Backends are picked at runtime:
        \\  uid switch      any POSIX host where agent-jail runs as root
        \\  Landlock        Linux 5.13+ with the Landlock LSM enabled
        \\  both            Linux root + Landlock (defense in depth)
        \\
        \\Idiomatic single-line invocation (works on every host with --best-effort):
        \\  agent-jail --best-effort --system-ro \\
        \\    --rw /data/workspace --rw /data/session --hide /data/vex \\
        \\    -- /app/agent
        \\
    );
    try w.flush();
}
