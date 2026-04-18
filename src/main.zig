//! agent-jail — portable filesystem sandbox for spawning untrusted subprocesses.
//!
//! Picks the strongest backend available at runtime:
//!   - uid switch (any POSIX) when --uid is set and caller is root
//!   - Landlock (Linux 5.13+) when --allow-ro/--allow-rw are set
//!   - both layered, when both apply (defense in depth)
//!
//! Fails loud if the user requested a guarantee the host can't deliver.
//! See src/sandbox.zig and src/landlock.zig for the mechanism details.

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
            try stdout.writeAll("agent-jail 0.1.0\n");
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

    // Fail loud if the user asked for Landlock-backed isolation but the
    // kernel can't deliver it. (--uid alone works anywhere without a
    // backend probe; the setuid syscall itself surfaces permission errors.)
    const wants_landlock = parsed.allow_ro.len > 0;
    const backend = sandbox.pickBackend(parsed);
    if (wants_landlock and backend != .landlock and backend != .uid_and_landlock) {
        try stderr.writeAll(
            \\agent-jail: --allow-ro requires Landlock (Linux 5.13+ with
            \\  CONFIG_SECURITY_LANDLOCK=y and 'landlock' in the LSM list).
            \\  Host lacks support. Refusing to run without it.
            \\
        );
        try stderr.flush();
        return 1;
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
        \\Options:
        \\  --uid N                Drop to this uid before exec (needs root)
        \\  --gid N                Drop to this gid (defaults to --uid)
        \\  --deny PATH            chmod 0700 this path (uid-switch mode only)
        \\  --allow-rw PATH        Sandbox may read+write under PATH
        \\  --allow-ro PATH        Sandbox may read+execute under PATH
        \\  --cwd PATH             Working directory for the child
        \\  -h, --help             Show this help
        \\  -V, --version          Show version
        \\
        \\Backends (auto-selected):
        \\  --uid + --allow-*     → uid switch + Landlock (Linux, defense in depth)
        \\  --uid                 → uid switch (any POSIX)
        \\  --allow-*             → Landlock (Linux 5.13+, unprivileged)
        \\
    );
    try w.flush();
}
