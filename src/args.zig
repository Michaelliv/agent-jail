//! CLI argument parsing for agent-jail.

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

pub const Parsed = struct {
    uid: ?u32 = null,
    gid: ?u32 = null,
    deny: []const []const u8 = &.{},
    allow_rw: []const []const u8 = &.{},
    allow_ro: []const []const u8 = &.{},
    cwd: ?[]const u8 = null,
    command: []const []const u8 = &.{},
};

pub fn parse(arena: Allocator, argv: []const [:0]const u8) Error!Parsed {
    var deny: std.ArrayList([]const u8) = .empty;
    var allow_rw: std.ArrayList([]const u8) = .empty;
    var allow_ro: std.ArrayList([]const u8) = .empty;

    var uid: ?u32 = null;
    var gid: ?u32 = null;
    var cwd: ?[]const u8 = null;
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
        } else if (mem.eql(u8, arg, "--deny")) {
            try deny.append(arena, try takeValue(argv, &i));
        } else if (mem.eql(u8, arg, "--allow-rw")) {
            try allow_rw.append(arena, try takeValue(argv, &i));
        } else if (mem.eql(u8, arg, "--allow-ro")) {
            try allow_ro.append(arena, try takeValue(argv, &i));
        } else if (mem.eql(u8, arg, "--cwd")) {
            cwd = try takeValue(argv, &i);
        } else {
            return error.UnknownFlag;
        }
    }

    return .{
        .uid = uid,
        .gid = gid,
        .deny = deny.items,
        .allow_rw = allow_rw.items,
        .allow_ro = allow_ro.items,
        .cwd = cwd,
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

test "parse deny+allow" {
    const a = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argv = [_][:0]const u8{
        "agent-jail",
        "--uid",                "1001",
        "--deny",               "/data",
        "--allow-rw",           "/data/work",
        "--allow-rw",           "/data/sess",
        "--",                   "/bin/sh",
    };
    const parsed = try parse(arena, &argv);

    try std.testing.expectEqual(@as(usize, 1), parsed.deny.len);
    try std.testing.expectEqual(@as(usize, 2), parsed.allow_rw.len);
    try std.testing.expectEqualStrings("/data/work", parsed.allow_rw[0]);
}

test "missing value" {
    const a = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argv = [_][:0]const u8{ "agent-jail", "--uid" };
    try std.testing.expectError(error.MissingValue, parse(arena, &argv));
}
