//! macOS sandbox backend: synthesize a Sandbox kext profile (SBPL) from
//! the agent-jail CLI verbs, then exec sandbox-exec(1).
//!
//! sandbox-exec is part of macOS — same status as chmod or kill. Apple
//! has marked it deprecated since 10.5 and it still works on every
//! shipping version (verified through Sequoia 15). Chromium, Docker, and
//! every macOS sandboxing tool sit on it for the same reason: the
//! framework alternative (sandbox_init_with_parameters) is SPI with no
//! API contract, and the kernel mechanism is identical either way.
//!
//! The profile vocabulary maps directly:
//!   --rw PATH   →  (allow file-read* file-write* (subpath "<realpath>"))
//!   --ro PATH   →  (allow file-read*             (subpath "<realpath>"))
//!   --hide PATH →  (deny  file-read* file-write* (subpath "<realpath>"))
//!   --list PATH →  no-op. On macOS, default-allow already permits
//!                  `openat(PATH, O_DIRECTORY)`. The flag exists only
//!                  for Linux parity; accepting it on both platforms
//!                  lets callers write one set of arguments.
//!
//! Rule order matters on macOS too: deny rules go FIRST, then rw/ro
//! carve out exceptions. SBPL evaluates later-wins for overlapping
//! subpaths, so an allow at `/data/workspaces/japanika` correctly
//! overrides a deny at `/data`. This order lets callers say
//! `--hide /data --rw /data/workspaces/own` and get exactly that.
//!
//! `realpath(3)` is mandatory: the kernel matches against the resolved
//! path, not the symlink. /tmp is a symlink to /private/tmp on every Mac,
//! so a profile that mentions /tmp without resolving silently has no
//! effect. realpath collapses the symlink chain.
//!
//! "(allow default)" + targeted denies is the only model that lets the
//! sandboxed child reach /usr/lib, /System, dyld, and the dynamic linker
//! cache. SBPL has no analogue to Landlock's default-deny + grant pattern
//! that doesn't break almost every binary. agent-jail's --hide is the
//! security primitive on Darwin; --rw / --ro are advisory passthroughs
//! that the kernel honors but doesn't actively need (they're already
//! reachable under default).

const std = @import("std");
const builtin = @import("builtin");

pub const Error = error{
    PathTooLong,
    OutOfMemory,
    InvalidSocketPath,
};

/// True on macOS. Other Apple platforms (iOS, tvOS) also ship the Sandbox
/// kext, but agent-jail isn't built for them, so we keep this narrow.
pub fn isAvailable() bool {
    return builtin.os.tag == .macos;
}

pub const Policy = struct {
    rw: []const []const u8,
    ro: []const []const u8,
    hide: []const []const u8,
    /// Accepted for cross-platform parity with Landlock's `--list`.
    /// macOS doesn't need it — default-allow permits dir-handle opens
    /// without a rule — so we render nothing.
    list: []const []const u8 = &.{},
    unix_sockets: []const []const u8 = &.{},
};

/// Render the policy as a Sandbox profile string. The caller owns the
/// returned slice (allocated from `arena`).
pub fn renderProfile(arena: std.mem.Allocator, policy: Policy) Error![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(arena);

    try buf.appendSlice(arena, "(version 1)\n(allow default)\n");

    // Order: hides first, then rw/ro carve out exceptions. SBPL
    // evaluates in order and later rules override earlier ones for
    // overlapping subpaths. So `--hide /data --rw /data/workspaces/own`
    // renders deny-then-allow, and the nested allow wins for the own
    // workspace while peers stay denied.
    for (policy.hide) |p| try writeRule(arena, &buf, "deny", "file-read* file-write*", p);
    for (policy.rw) |p| try writeRule(arena, &buf, "allow", "file-read* file-write*", p);
    for (policy.ro) |p| try writeRule(arena, &buf, "allow", "file-read*", p);
    // `--list` is a no-op on macOS (see header comment).

    if (policy.unix_sockets.len > 0) {
        try buf.appendSlice(arena, "(deny network-outbound (remote unix-socket))\n");
        for (policy.unix_sockets) |p| {
            var resolved_buf: [std.fs.max_path_bytes]u8 = undefined;
            // Never silently drop a requested socket grant. The endpoint must
            // exist before spawning so symlinks resolve to the kernel's path.
            const resolved = realpath(p, &resolved_buf) catch return error.InvalidSocketPath;
            try buf.appendSlice(arena, "(allow network-outbound (remote unix-socket (literal ");
            try writeQuoted(arena, &buf, resolved);
            try buf.appendSlice(arena, ")))\n");
        }
    }

    return buf.toOwnedSlice(arena);
}

fn writeRule(
    arena: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    verb: []const u8,
    operations: []const u8,
    path: []const u8,
) Error!void {
    var resolved_buf: [std.fs.max_path_bytes]u8 = undefined;
    // Missing paths are silently skipped — matches Linux behavior where
    // --ro on a nonexistent path is filtered out and --hide is documented
    // as a no-op on missing paths. The kernel doesn't need a rule for a
    // path that doesn't exist anyway.
    const resolved = realpath(path, &resolved_buf) catch return;

    try buf.print(arena, "({s} {s} (subpath ", .{ verb, operations });
    try writeQuoted(arena, buf, resolved);
    try buf.appendSlice(arena, "))\n");
}

// Filesystem and socket rules share SBPL string escaping; paths are data,
// never profile expressions, even when they contain quotes or backslashes.
fn writeQuoted(arena: std.mem.Allocator, buf: *std.ArrayList(u8), value: []const u8) Error!void {
    try buf.append(arena, '"');
    for (value) |ch| switch (ch) {
        '"', '\\' => {
            try buf.append(arena, '\\');
            try buf.append(arena, ch);
        },
        else => try buf.append(arena, ch),
    };
    try buf.append(arena, '"');
}

/// Resolve symlinks via realpath(3). Returns a slice into `out` of the
/// resolved path (no trailing NUL).
fn realpath(path: []const u8, out: *[std.fs.max_path_bytes]u8) ![]const u8 {
    var pathz_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pathz = std.fmt.bufPrintZ(&pathz_buf, "{s}", .{path}) catch return error.OutOfMemory;

    const ret = c.realpath(pathz.ptr, out);
    if (ret == null) return error.OutOfMemory;
    var i: usize = 0;
    while (i < out.len and out[i] != 0) : (i += 1) {}
    return out[0..i];
}

const c = struct {
    extern "c" fn realpath(path: [*:0]const u8, resolved: *[std.fs.max_path_bytes]u8) ?[*]u8;
};

// ── Tests ───────────────────────────────────────────────────────────

test "renderProfile emits the expected SBPL skeleton" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Use real, existing paths so realpath can resolve them.
    const out = try renderProfile(arena, .{
        .rw = &.{"/tmp"},
        .ro = &.{"/usr"},
        .hide = &.{"/etc"},
    });

    try std.testing.expect(std.mem.indexOf(u8, out, "(version 1)") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "(allow default)") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "file-read* file-write*") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "(deny ") != null);
    // /tmp must be resolved to /private/tmp on macOS.
    try std.testing.expect(std.mem.indexOf(u8, out, "/private/tmp") != null);
}

test "empty policy returns an owned slice without socket restrictions" {
    // Without an allowlist, Unix socket access is unrestricted.
    const out = try renderProfile(std.testing.allocator, .{ .rw = &.{}, .ro = &.{}, .hide = &.{} });
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("(version 1)\n(allow default)\n", out);
}

test "SBPL quoting escapes expression delimiters in every path rule" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try writeQuoted(std.testing.allocator, &buf, "a\"b\\c");
    try std.testing.expectEqualStrings("\"a\\\"b\\\\c\"", buf.items);
}

test "profile construction releases allocations at every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            const out = try renderProfile(allocator, .{
                .rw = &.{ "/tmp", "/tmp", "/tmp", "/tmp" },
                .ro = &.{"/usr"},
                .hide = &.{},
                .unix_sockets = &.{ "/tmp", "/tmp" },
            });
            defer allocator.free(out);
        }
    }.run, .{});
}

test "missing socket grants are errors rather than silently omitted rules" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    try std.testing.expectError(error.InvalidSocketPath, renderProfile(std.testing.allocator, .{
        .rw = &.{},
        .ro = &.{},
        .hide = &.{},
        .unix_sockets = &.{"/definitely/missing/agent-jail.sock"},
    }));
}
