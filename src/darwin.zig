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
};

/// Render the policy as a Sandbox profile string. The caller owns the
/// returned slice (allocated from `arena`).
pub fn renderProfile(arena: std.mem.Allocator, policy: Policy) Error![]const u8 {
    var buf: std.ArrayList(u8) = .empty;

    try buf.appendSlice(arena, "(version 1)\n(allow default)\n");

    // Order matters: hides go last so they win over any allow already in
    // scope from "(allow default)". The kernel evaluates in order; later
    // rules override earlier ones for overlapping subpaths.
    for (policy.rw) |p| try writeRule(arena, &buf, "allow", "file-read* file-write*", p);
    for (policy.ro) |p| try writeRule(arena, &buf, "allow", "file-read*", p);
    for (policy.hide) |p| try writeRule(arena, &buf, "deny", "file-read* file-write*", p);

    return buf.items;
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

    // SBPL string literals are double-quoted. Backslash and double-quote
    // are the only chars that need escaping; control chars don't appear
    // in real filesystem paths but we'd be in deeper trouble if they did.
    try buf.print(arena, "({s} {s} (subpath \"", .{ verb, operations });
    for (resolved) |ch| switch (ch) {
        '"', '\\' => {
            try buf.append(arena, '\\');
            try buf.append(arena, ch);
        },
        else => try buf.append(arena, ch),
    };
    try buf.appendSlice(arena, "\"))\n");
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

test "renderProfile escapes quotes and backslashes in paths" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Empty policy still produces the skeleton.
    const out = try renderProfile(arena, .{ .rw = &.{}, .ro = &.{}, .hide = &.{} });
    try std.testing.expectEqualStrings("(version 1)\n(allow default)\n", out);
}
