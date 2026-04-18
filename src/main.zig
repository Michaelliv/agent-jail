//! uidjail — portable filesystem sandbox via POSIX uid + permissions.
//!
//! Spawns a child process under an unprivileged uid. Optional `--deny` and
//! `--allow-rw` paths get chowned/chmodded so the kernel's permission check
//! enforces the sandbox boundary — no kernel features beyond POSIX needed.

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
            try stdout.writeAll("uidjail 0.1.0\n");
            try stdout.flush();
            return 0;
        },
        else => |e| {
            try stderr.print("uidjail: {s}\n", .{@errorName(e)});
            try printUsage(stderr);
            return 2;
        },
    };

    if (parsed.command.len == 0) {
        try stderr.writeAll("uidjail: missing command after --\n");
        try stderr.flush();
        return 2;
    }

    const ids: sandbox.Ids = .{
        .uid = parsed.uid orelse 0,
        .gid = parsed.gid orelse parsed.uid orelse 0,
    };

    sandbox.applyPermissions(parsed, ids) catch |err| {
        try stderr.print("uidjail: applyPermissions failed: {s}\n", .{@errorName(err)});
        try stderr.flush();
        return 1;
    };

    return sandbox.spawnAndWait(init.gpa, parsed, ids) catch |err| {
        try stderr.print("uidjail: spawn failed: {s}\n", .{@errorName(err)});
        try stderr.flush();
        return 1;
    };
}

fn printUsage(w: *std.Io.Writer) !void {
    try w.writeAll(
        \\uidjail — portable filesystem sandbox via POSIX uid + permissions
        \\
        \\Usage:
        \\  uidjail [options] -- COMMAND [ARGS...]
        \\
        \\Options:
        \\  --uid N                Sandbox uid (required)
        \\  --gid N                Sandbox gid (defaults to uid)
        \\  --deny PATH            Path the sandboxed process must not access
        \\  --allow-rw PATH        Path the sandboxed process can read+write
        \\  --cwd PATH             Working directory for the child
        \\  -h, --help             Show this help
        \\  -V, --version          Show version
        \\
    );
    try w.flush();
}
