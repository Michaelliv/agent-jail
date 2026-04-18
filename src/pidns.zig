//! PID-namespace backend: confines `kill(2)` and `/proc` visibility.
//!
//! After unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID) and a second
//! fork, the grandchild is PID 1 in a fresh PID namespace. From its POV:
//!
//!   - `ps`, `/proc/<pid>`, `kill(pid, sig)` only see/affect processes
//!     spawned inside this namespace. Sibling agents and the host are
//!     invisible and unreachable.
//!   - When the grandchild (PID 1) dies, the kernel SIGKILLs every other
//!     process in the namespace. No leaked descendants.
//!
//! The user namespace is what makes this work without root: an
//! unprivileged unshare(CLONE_NEWUSER) grants CAP_SYS_ADMIN inside the
//! new namespace, which is what CLONE_NEWPID and the /proc remount need.
//! On distros that disable unprivileged user namespaces (some hardened
//! Debian/RHEL) the unshare returns EPERM; the caller should degrade
//! under --best-effort.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const Error = error{
    /// Kernel doesn't support unprivileged user namespaces (EPERM/ENOSYS).
    NotSupported,
    /// uid/gid map write failed; namespace is half-set-up, must abort.
    MapFailed,
    /// /proc remount failed.
    ProcMountFailed,
    Unexpected,
};

/// True if PID-namespace isolation can plausibly be applied on this host.
/// Available on Linux; everywhere else this returns false and the caller
/// should skip the layer entirely.
pub fn isAvailable() bool {
    return builtin.os.tag == .linux;
}

/// Enter a fresh user + mount + PID namespace. Must be called from the
/// fork child; takes effect for the *next* fork (per CLONE_NEWPID
/// semantics), so the caller must fork again to land in the new namespace
/// as PID 1.
///
/// Steps:
/// 1. unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID)
/// 2. Map the outer uid/gid to root inside the new user namespace, so
///    subsequent privileged operations (mount, etc.) are permitted.
/// 3. Remount root MS_PRIVATE so our /proc remount doesn't leak out.
/// 4. Mount a fresh procfs over /proc reflecting the new PID namespace.
///
/// On failure, the caller should refuse to proceed (we'd otherwise exec
/// in a half-isolated state, which is worse than no isolation).
pub fn enter() Error!void {
    if (builtin.os.tag != .linux) return error.NotSupported;

    const outer_uid = linux.getuid();
    const outer_gid = linux.getgid();

    const flags: usize = linux.CLONE.NEWUSER | linux.CLONE.NEWNS | linux.CLONE.NEWPID;
    if (errnoFrom(linux.unshare(flags))) |e| {
        return switch (e) {
            .PERM, .NOSYS, .INVAL => error.NotSupported,
            else => error.Unexpected,
        };
    }

    try writeIdMap("/proc/self/setgroups", "deny");
    try writeIdMapNumeric("/proc/self/uid_map", 0, outer_uid, 1);
    try writeIdMapNumeric("/proc/self/gid_map", 0, outer_gid, 1);

    // Make root MS_PRIVATE so the /proc remount stays scoped to this
    // mount namespace. Without this the new procfs can leak back to the
    // host on systems where /proc is mounted shared.
    {
        const slash: [*:0]const u8 = "/";
        const none: [*:0]const u8 = "none";
        const rc = linux.mount(none, slash, null, linux.MS.REC | linux.MS.PRIVATE, 0);
        if (errnoFrom(rc) != null) return error.ProcMountFailed;
    }

    // Mount fresh procfs. The kernel binds it to whichever PID namespace
    // the *next* mount of "proc" comes from — for us, the new one.
    {
        const proc_str: [*:0]const u8 = "proc";
        const proc_path: [*:0]const u8 = "/proc";
        const rc = linux.mount(proc_str, proc_path, proc_str, 0, 0);
        if (errnoFrom(rc) != null) return error.ProcMountFailed;
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Decode a Linux raw-syscall return into an errno when negative, else
/// null. Linux returns -errno encoded as a large unsigned value; the
/// idiom is to cast to isize and check the sign.
fn errnoFrom(rc: usize) ?std.c.E {
    const sig: isize = @bitCast(rc);
    if (sig >= 0) return null;
    return @enumFromInt(@as(u16, @intCast(-sig)));
}

fn writeIdMap(path: [*:0]const u8, contents: []const u8) Error!void {
    const fd_rc = linux.open(path, .{ .ACCMODE = .WRONLY }, 0);
    if (errnoFrom(fd_rc) != null) return error.MapFailed;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);
    const w = linux.write(fd, contents.ptr, contents.len);
    if (errnoFrom(w) != null) return error.MapFailed;
}

fn writeIdMapNumeric(path: [*:0]const u8, inner: u32, outer: u32, count: u32) Error!void {
    var buf: [64]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{d} {d} {d}", .{ inner, outer, count }) catch return error.MapFailed;
    try writeIdMap(path, s);
}

// ── Tests ───────────────────────────────────────────────────────────

test "isAvailable matches platform" {
    const expected = builtin.os.tag == .linux;
    try std.testing.expectEqual(expected, isAvailable());
}

test "errnoFrom decodes negative as errno, non-negative as null" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // 0 → success → null
    try std.testing.expect(errnoFrom(0) == null);
    // small positive (e.g. an fd) → success → null
    try std.testing.expect(errnoFrom(5) == null);
    // -EPERM (encoded as ~0 - 0 wraparound) → errno
    const neg_perm: usize = @bitCast(@as(isize, -1));
    try std.testing.expect(errnoFrom(neg_perm) != null);
}
