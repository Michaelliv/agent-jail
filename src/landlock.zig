//! Landlock backend: unprivileged filesystem sandboxing via the Landlock LSM.
//!
//! Landlock (Linux 5.13+) lets a thread restrict its own future filesystem
//! access — and the access of all its descendants — without needing root or
//! CAP_SYS_ADMIN. It's the only mainline Linux mechanism that does this.
//!
//! Semantics we implement:
//! - Default-deny. The child can access nothing by default.
//! - Each `--rw PATH` opens a hierarchy with full read+write+exec rights.
//! - Each `--ro PATH` opens a hierarchy with read+exec rights only.
//! - `--hide` is a no-op under Landlock (default-deny already covers it);
//!   it only has meaning in uid-switch mode.
//!
//! ABI best-effort: we probe the kernel's supported Landlock version and
//! strip unsupported bits from the handled-access mask so older kernels
//! keep working with reduced protection rather than erroring.
//!
//! This module only applies the ruleset — it does NOT call execvp. Caller
//! is expected to invoke `apply` in the fork child right before exec.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const Error = error{
    NotSupported,           // kernel has no Landlock (ENOSYS or ABI < 1)
    Disabled,               // Landlock compiled but not in LSM stack (EOPNOTSUPP)
    PathNotFound,           // --allow-* target doesn't exist
    PermissionDenied,
    PathTooLong,
    Unexpected,
};

// ── UAPI bit-flag constants (from include/uapi/linux/landlock.h) ────

pub const ACCESS_FS = struct {
    pub const EXECUTE: u64 = 1 << 0;
    pub const WRITE_FILE: u64 = 1 << 1;
    pub const READ_FILE: u64 = 1 << 2;
    pub const READ_DIR: u64 = 1 << 3;
    pub const REMOVE_DIR: u64 = 1 << 4;
    pub const REMOVE_FILE: u64 = 1 << 5;
    pub const MAKE_CHAR: u64 = 1 << 6;
    pub const MAKE_DIR: u64 = 1 << 7;
    pub const MAKE_REG: u64 = 1 << 8;
    pub const MAKE_SOCK: u64 = 1 << 9;
    pub const MAKE_FIFO: u64 = 1 << 10;
    pub const MAKE_BLOCK: u64 = 1 << 11;
    pub const MAKE_SYM: u64 = 1 << 12;
    pub const REFER: u64 = 1 << 13; // ABI 2+
    pub const TRUNCATE: u64 = 1 << 14; // ABI 3+
    pub const IOCTL_DEV: u64 = 1 << 15; // ABI 5+
};

/// Full write set (used when we want "rw" on a hierarchy).
pub const RW_ACCESS: u64 =
    ACCESS_FS.EXECUTE | ACCESS_FS.WRITE_FILE | ACCESS_FS.READ_FILE |
    ACCESS_FS.READ_DIR | ACCESS_FS.REMOVE_DIR | ACCESS_FS.REMOVE_FILE |
    ACCESS_FS.MAKE_CHAR | ACCESS_FS.MAKE_DIR | ACCESS_FS.MAKE_REG |
    ACCESS_FS.MAKE_SOCK | ACCESS_FS.MAKE_FIFO | ACCESS_FS.MAKE_BLOCK |
    ACCESS_FS.MAKE_SYM | ACCESS_FS.REFER | ACCESS_FS.TRUNCATE |
    ACCESS_FS.IOCTL_DEV;

/// Read-only set: read files, list dirs, execute.
pub const RO_ACCESS: u64 =
    ACCESS_FS.EXECUTE | ACCESS_FS.READ_FILE | ACCESS_FS.READ_DIR;

/// Subset of RW_ACCESS that only applies to file objects (not dirs). When we
/// add a rule on a path that's actually a file, the non-file bits have to be
/// stripped, or landlock_add_rule returns EINVAL.
const FILE_ACCESS: u64 =
    ACCESS_FS.EXECUTE | ACCESS_FS.WRITE_FILE | ACCESS_FS.READ_FILE |
    ACCESS_FS.TRUNCATE | ACCESS_FS.IOCTL_DEV;

pub const CREATE_RULESET_VERSION: u32 = 1 << 0;

pub const RULE_PATH_BENEATH: c_int = 1;

// ── UAPI structs ────────────────────────────────────────────────────

pub const RulesetAttr = extern struct {
    handled_access_fs: u64,
    handled_access_net: u64 = 0,
    scoped: u64 = 0,
};

pub const PathBeneathAttr = extern struct {
    allowed_access: u64,
    parent_fd: i32,
};

// ── prctl / flags ────────────────────────────────────────────────────

const PR_SET_NO_NEW_PRIVS: c_int = 38;

// O_PATH, O_CLOEXEC — values from std.posix.O.
const O_PATH_CLOEXEC: u32 = @bitCast(std.posix.O{ .PATH = true, .CLOEXEC = true });

// O_DIRECTORY: open only succeeds if path is a directory. Lets us ask "is
// this a dir?" without pulling in struct stat, whose layout differs per arch.
const O_DIRECTORY_PATH_CLOEXEC: u32 = @bitCast(std.posix.O{ .DIRECTORY = true, .PATH = true, .CLOEXEC = true });

// ── Syscall wrappers ─────────────────────────────────────────────────

fn sysLandlockCreateRuleset(attr: ?*const RulesetAttr, size: usize, flags: u32) isize {
    return @bitCast(linux.syscall3(
        .landlock_create_ruleset,
        @intFromPtr(attr),
        size,
        flags,
    ));
}

fn sysLandlockAddRule(ruleset_fd: c_int, rule_type: c_int, rule_attr: *const anyopaque, flags: u32) isize {
    return @bitCast(linux.syscall4(
        .landlock_add_rule,
        @intCast(ruleset_fd),
        @intCast(rule_type),
        @intFromPtr(rule_attr),
        flags,
    ));
}

fn sysLandlockRestrictSelf(ruleset_fd: c_int, flags: u32) isize {
    return @bitCast(linux.syscall2(
        .landlock_restrict_self,
        @intCast(ruleset_fd),
        flags,
    ));
}

extern "c" fn prctl(option: c_int, ...) c_int;
extern "c" fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
extern "c" fn close(fd: c_int) c_int;

fn errnoFromRc(rc: isize) std.c.E {
    return @enumFromInt(@as(u16, @intCast(-rc)));
}

// ── ABI probe ────────────────────────────────────────────────────────

/// Returns the supported Landlock ABI version (1+) or an error.
/// - `NotSupported` if the syscall is ENOSYS (pre-5.13 kernel, or LSM not
///   compiled, or arch missing the syscall number).
/// - `Disabled` if Landlock is compiled but not enabled in the boot LSM list.
pub fn probeAbi() Error!u32 {
    const rc = sysLandlockCreateRuleset(null, 0, CREATE_RULESET_VERSION);
    if (rc < 0) {
        return switch (errnoFromRc(rc)) {
            .NOSYS => error.NotSupported,
            .OPNOTSUPP => error.Disabled,
            else => error.Unexpected,
        };
    }
    return @intCast(rc);
}

/// Quick availability check: true if Landlock will actually restrict this
/// process. Doesn't distinguish "not supported" from "disabled".
pub fn isAvailable() bool {
    _ = probeAbi() catch return false;
    return true;
}

// ── Public API ──────────────────────────────────────────────────────

pub const Policy = struct {
    /// Paths the sandboxed process may read+write+execute under.
    allow_rw: []const []const u8,
    /// Paths the sandboxed process may read+execute under (no write).
    allow_ro: []const []const u8,
};

/// Apply a Landlock policy to the current thread and its descendants.
///
/// Must be called in a context where the caller is about to exec or is the
/// sole consumer of the thread — once enforced, restrictions can never be
/// relaxed.
///
/// Behavior:
/// 1. Probe Landlock ABI. Strip access bits the kernel doesn't know.
/// 2. Create a ruleset with handled_access_fs covering everything our policy
///    could want to grant (ensures ruleset is the authority for those rights).
/// 3. For each allow_rw path: open O_PATH and add a path-beneath rule with
///    RW_ACCESS masked to supported bits.
/// 4. For each allow_ro path: same, with RO_ACCESS.
/// 5. prctl(PR_SET_NO_NEW_PRIVS) so the kernel will accept restrict_self.
/// 6. landlock_restrict_self. From this point the thread (and its future
///    descendants) can only access what the ruleset grants.
pub fn apply(policy: Policy) Error!void {
    const abi = try probeAbi();

    // Best-effort: strip access bits the running kernel doesn't support.
    var handled: u64 = RW_ACCESS; // superset — covers both rw and ro.
    if (abi < 2) handled &= ~ACCESS_FS.REFER;
    if (abi < 3) handled &= ~ACCESS_FS.TRUNCATE;
    if (abi < 5) handled &= ~ACCESS_FS.IOCTL_DEV;

    const ruleset = RulesetAttr{ .handled_access_fs = handled };
    const ruleset_fd_rc = sysLandlockCreateRuleset(&ruleset, @sizeOf(RulesetAttr), 0);
    if (ruleset_fd_rc < 0) return switch (errnoFromRc(ruleset_fd_rc)) {
        .NOSYS => error.NotSupported,
        .OPNOTSUPP => error.Disabled,
        else => error.Unexpected,
    };
    const ruleset_fd: c_int = @intCast(ruleset_fd_rc);
    defer _ = close(ruleset_fd);

    // Each allow path → one path-beneath rule.
    for (policy.allow_rw) |p| try addPathRule(ruleset_fd, p, RW_ACCESS & handled);
    for (policy.allow_ro) |p| try addPathRule(ruleset_fd, p, RO_ACCESS & handled);

    if (prctl(PR_SET_NO_NEW_PRIVS, @as(c_int, 1), @as(c_int, 0), @as(c_int, 0), @as(c_int, 0)) != 0) {
        return error.PermissionDenied;
    }

    const rc = sysLandlockRestrictSelf(ruleset_fd, 0);
    if (rc < 0) return switch (errnoFromRc(rc)) {
        .PERM => error.PermissionDenied,
        else => error.Unexpected,
    };
}

fn addPathRule(ruleset_fd: c_int, path: []const u8, access: u64) Error!void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{path}) catch return error.PathTooLong;

    // Detect directory-ness by trying O_DIRECTORY first. If it succeeds, the
    // path is a directory and we can keep all access bits. If it fails with
    // ENOTDIR, it's a file — open plain O_PATH and strip dir-only bits.
    var is_dir = true;
    var fd = open(z.ptr, @bitCast(O_DIRECTORY_PATH_CLOEXEC));
    if (fd < 0) {
        const e = @as(std.c.E, @enumFromInt(std.c._errno().*));
        if (e == .NOTDIR) {
            is_dir = false;
            fd = open(z.ptr, @bitCast(O_PATH_CLOEXEC));
            if (fd < 0) return switch (@as(std.c.E, @enumFromInt(std.c._errno().*))) {
                .NOENT => error.PathNotFound,
                .ACCES, .PERM => error.PermissionDenied,
                else => error.Unexpected,
            };
        } else return switch (e) {
            .NOENT => error.PathNotFound,
            .ACCES, .PERM => error.PermissionDenied,
            else => error.Unexpected,
        };
    }
    defer _ = close(fd);

    const final_access = if (is_dir) access else (access & FILE_ACCESS);

    if (final_access == 0) return; // nothing granted → skip (kernel rejects empty)

    const rule = PathBeneathAttr{
        .allowed_access = final_access,
        .parent_fd = fd,
    };
    const rc = sysLandlockAddRule(ruleset_fd, RULE_PATH_BENEATH, &rule, 0);
    if (rc < 0) return switch (errnoFromRc(rc)) {
        .NOENT => error.PathNotFound,
        .ACCES, .PERM => error.PermissionDenied,
        else => error.Unexpected,
    };
}

// ── Tests ────────────────────────────────────────────────────────────

test "probeAbi returns version or well-typed error" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const result = probeAbi();
    _ = result catch |err| switch (err) {
        error.NotSupported, error.Disabled, error.Unexpected => return,
        else => return err,
    };
}
