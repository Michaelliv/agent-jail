//! CLI argument parsing for agent-jail.
//!
//! Three path verbs describe what the sandbox can do with a path:
//!   --rw PATH     can read and write
//!   --ro PATH     can read (and execute) only
//!   --hide PATH   can't touch at all
//!
//! Plus:
//!   --system-ro   shorthand for `--ro` on the standard system dirs
//!                 (/usr /lib /lib64 /bin /sbin /etc /usr/sbin). Missing
//!                 paths on a given host are silently skipped.
//!   --uid N       drop to this uid (needs root)
//!   --gid N       drop to this gid (defaults to --uid)
//!   --cwd PATH    working directory for the child
//!   --best-effort don't fail if a requested protection isn't available
//!                 on the host; warn on stderr and continue
//!
//! The old names (--allow-rw / --allow-ro / --deny) are accepted as hidden
//! aliases so an existing muscle memory keeps working.

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

/// Paths the standard `--system-ro` shorthand expands to. Any path that
/// doesn't exist at apply-time is skipped — this list is a superset of
/// what Linux distros and macOS put in these locations.
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
    cwd: ?[]const u8 = null,
    best_effort: bool = false,
    command: []const []const u8 = &.{},
};

pub fn parse(arena: Allocator, argv: []const [:0]const u8) Error!Parsed {
    var hide: std.ArrayList([]const u8) = .empty;
    var rw: std.ArrayList([]const u8) = .empty;
    var ro: std.ArrayList([]const u8) = .empty;

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
        } else if (mem.eql(u8, arg, "--hide") or mem.eql(u8, arg, "--deny")) {
            try hide.append(arena, try takeValue(argv, &i));
        } else if (mem.eql(u8, arg, "--rw") or mem.eql(u8, arg, "--allow-rw")) {
            try rw.append(arena, try takeValue(argv, &i));
        } else if (mem.eql(u8, arg, "--ro") or mem.eql(u8, arg, "--allow-ro")) {
            try ro.append(arena, try takeValue(argv, &i));
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
        .cwd = cwd,
        .best_effort = best_effort,
        .command = command,
    };
}

fn takeValue(argv: []const [:0]const u8, i: *usize) Error![]const u8 {
    if (i.* + 1 >= argv.len) return error.MissingValue;
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
        "--uid",  "1001",
        "--hide", "/data",
        "--rw",   "/data/work",
        "--rw",   "/data/sess",
        "--ro",   "/usr",
        "--",     "/bin/sh",
    };
    const parsed = try parse(arena, &argv);

    try std.testing.expectEqual(@as(usize, 1), parsed.hide.len);
    try std.testing.expectEqual(@as(usize, 2), parsed.rw.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.ro.len);
    try std.testing.expectEqualStrings("/data/work", parsed.rw[0]);
}

test "legacy aliases still parse" {
    const a = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argv = [_][:0]const u8{
        "agent-jail",
        "--deny",     "/data",
        "--allow-rw", "/work",
        "--allow-ro", "/usr",
        "--",         "/bin/true",
    };
    const parsed = try parse(arena, &argv);
    try std.testing.expectEqual(@as(usize, 1), parsed.hide.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.rw.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.ro.len);
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

test "missing value" {
    const a = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argv = [_][:0]const u8{ "agent-jail", "--uid" };
    try std.testing.expectError(error.MissingValue, parse(arena, &argv));
}
