//! CLI argument parsing. See `printUsage` in main.zig for the full flag
//! reference.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

pub const Error = error{
    HelpRequested,
    VersionRequested,
    MissingValue,
    UnknownFlag,
    InvalidNumber,
    OutOfMemory,
};

/// Paths `--system-ro` expands to. Non-existent entries are skipped at
/// apply-time, so the same list works on Linux, macOS, Alpine, etc.
pub const SYSTEM_RO_PATHS = [_][]const u8{
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc",
    "/usr/sbin",
};

pub const Parsed = struct {
    uid: ?u32 = null,
    gid: ?u32 = null,
    hide: []const []const u8 = &.{},
    rw: []const []const u8 = &.{},
    ro: []const []const u8 = &.{},
    /// `--list PATH` grants the sandbox permission to open PATH as a
    /// directory handle (Landlock READ_DIR only) without granting any
    /// file reads under it. Exists to satisfy runtimes that start with
    /// `openat("/", O_DIRECTORY)` for cwd resolution — Bun, Node, DuckDB,
    /// Python imports, Go's filepath.Walk — on hosts where Landlock is
    /// the only available backend. On macOS the default-allow policy
    /// already permits this; `--list` is a no-op there.
    list: []const []const u8 = &.{},
    /// If nonempty, outbound Unix socket connections are restricted to these paths.
    unix_sockets: []const []const u8 = &.{},
    cwd: ?[]const u8 = null,
    best_effort: bool = false,
    command: []const []const u8 = &.{},
};

pub fn parse(arena: Allocator, argv: []const [:0]const u8) Error!Parsed {
    var hide: std.ArrayList([]const u8) = .empty;
    var rw: std.ArrayList([]const u8) = .empty;
    var ro: std.ArrayList([]const u8) = .empty;
    var list: std.ArrayList([]const u8) = .empty;
    var unix_sockets: std.ArrayList([]const u8) = .empty;

    var uid: ?u32 = null;
    var gid: ?u32 = null;
    var cwd: ?[]const u8 = null;
    var best_effort = false;
    var command: []const []const u8 = &.{};

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];

        if (mem.eql(u8, arg, "--")) {
            const rest = argv[i + 1 ..];
            const out = try arena.alloc([]const u8, rest.len);
            for (rest, 0..) |s, j| out[j] = s;
            command = out;
            break;
        }
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) return error.HelpRequested;
        if (mem.eql(u8, arg, "-V") or mem.eql(u8, arg, "--version")) return error.VersionRequested;

        if (mem.eql(u8, arg, "--uid")) {
            const v = try takeValue(argv, &i);
            uid = std.fmt.parseInt(u32, v, 10) catch return error.InvalidNumber;
        } else if (mem.eql(u8, arg, "--gid")) {
            const v = try takeValue(argv, &i);
            gid = std.fmt.parseInt(u32, v, 10) catch return error.InvalidNumber;
        } else if (mem.eql(u8, arg, "--hide")) {
            try hide.append(arena, try takeValue(argv, &i));
        } else if (mem.eql(u8, arg, "--rw")) {
            try rw.append(arena, try takeValue(argv, &i));
        } else if (mem.eql(u8, arg, "--ro")) {
            try ro.append(arena, try takeValue(argv, &i));
        } else if (mem.eql(u8, arg, "--list")) {
            try list.append(arena, try takeValue(argv, &i));
        } else if (mem.eql(u8, arg, "--unix-socket")) {
            try unix_sockets.append(arena, try takeValue(argv, &i));
        } else if (mem.eql(u8, arg, "--system-ro")) {
            for (SYSTEM_RO_PATHS) |p| try ro.append(arena, p);
        } else if (mem.eql(u8, arg, "--cwd")) {
            cwd = try takeValue(argv, &i);
        } else if (mem.eql(u8, arg, "--best-effort")) {
            best_effort = true;
        } else {
            return error.UnknownFlag;
        }
    }

    return .{
        .uid = uid,
        .gid = gid,
        .hide = hide.items,
        .rw = rw.items,
        .ro = ro.items,
        .list = list.items,
        .unix_sockets = unix_sockets.items,
        .cwd = cwd,
        .best_effort = best_effort,
        .command = command,
    };
}

fn takeValue(argv: []const [:0]const u8, i: *usize) Error![]const u8 {
    if (i.* + 1 >= argv.len or mem.eql(u8, argv[i.* + 1], "--")) return error.MissingValue;
    i.* += 1;
    return argv[i.*];
}

test "parse minimal" {
    const a = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argv = [_][:0]const u8{ "agent-jail", "--uid", "1001", "--", "/bin/echo", "hi" };
    const parsed = try parse(arena, &argv);

    try std.testing.expectEqual(@as(?u32, 1001), parsed.uid);
    try std.testing.expectEqual(@as(usize, 2), parsed.command.len);
    try std.testing.expectEqualStrings("/bin/echo", parsed.command[0]);
    try std.testing.expectEqualStrings("hi", parsed.command[1]);
}

test "parse rw/ro/hide" {
    const a = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argv = [_][:0]const u8{
        "agent-jail",
        "--uid",
        "1001",
        "--hide",
        "/data",
        "--rw",
        "/data/work",
        "--rw",
        "/data/sess",
        "--ro",
        "/usr",
        "--",
        "/bin/sh",
    };
    const parsed = try parse(arena, &argv);

    try std.testing.expectEqual(@as(usize, 1), parsed.hide.len);
    try std.testing.expectEqual(@as(usize, 2), parsed.rw.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.ro.len);
    try std.testing.expectEqualStrings("/data/work", parsed.rw[0]);
}

test "--system-ro expands to multiple paths" {
    const a = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argv = [_][:0]const u8{ "agent-jail", "--system-ro", "--", "/bin/true" };
    const parsed = try parse(arena, &argv);
    try std.testing.expectEqual(SYSTEM_RO_PATHS.len, parsed.ro.len);
    try std.testing.expectEqualStrings("/usr", parsed.ro[0]);
}

test "--best-effort parses to bool" {
    const a = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argv = [_][:0]const u8{ "agent-jail", "--best-effort", "--", "/bin/true" };
    const parsed = try parse(arena, &argv);
    try std.testing.expect(parsed.best_effort);
}

test "unix socket paths are repeatable and absent by default" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const bare = [_][:0]const u8{ "agent-jail", "--", "true" };
    try std.testing.expectEqual(@as(usize, 0), (try parse(arena, &bare)).unix_sockets.len);
    const argv = [_][:0]const u8{ "agent-jail", "--unix-socket", "/tmp/a", "--unix-socket", "/tmp/b", "--", "true" };
    const parsed = try parse(arena, &argv);
    try std.testing.expectEqual(@as(usize, 2), parsed.unix_sockets.len);
    try std.testing.expectEqualStrings("/tmp/a", parsed.unix_sockets[0]);
    try std.testing.expectEqualStrings("/tmp/b", parsed.unix_sockets[1]);
}

test "every value-taking flag rejects a missing value or command delimiter" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for ([_][:0]const u8{ "--uid", "--gid", "--hide", "--rw", "--ro", "--list", "--unix-socket", "--cwd" }) |flag| {
        const missing = [_][:0]const u8{ "agent-jail", flag };
        const delimiter = [_][:0]const u8{ "agent-jail", flag, "--", "true" };
        try std.testing.expectError(error.MissingValue, parse(arena, &missing));
        try std.testing.expectError(error.MissingValue, parse(arena, &delimiter));
    }
}
