//! Sandboxing core: permission setup + spawn with backend dispatch.
//!
//! Two backends, either or both may apply per call:
//!   - uid switch: chown/chmod hide+rw paths, then in the child call
//!     setgroups(0)/setresgid/setresuid before exec. POSIX, any UNIX.
//!   - Landlock: in the child, apply a landlock ruleset with path-beneath
//!     rules right before exec. Linux 5.13+, unprivileged.
//!
//! We do our own fork + execvp because std.process.spawn doesn't close
//! caller-inherited FDs (>= 3) and doesn't drop supplementary groups —
//! both real security holes for a sandbox tool. Manual fork lets us
//! control the full child-side setup: chdir, new process group, close all
//! non-stdio FDs, Landlock (if requested), setgroups(0), setresgid,
//! setresuid, then exec. The kernel transitions identity and applies the
//! Landlock domain; the child can never relax either.

const std = @import("std");
const builtin = @import("builtin");
const Args = @import("args.zig");
const landlock = @import("landlock.zig");

pub const Ids = struct {
    uid: u32,
    gid: u32,
};

pub const Error = error{
    AccessDenied,
    FileNotFound,
    ForkFailed,
    OutOfMemory,
    PathTooLong,
    Unexpected,
};

/// What mechanism will actually sandbox the child. Resolved by `pickBackend`
/// from the Args + runtime capability probe.
pub const Backend = enum {
    /// No sandboxing params → just spawn the child as-is.
    none,
    /// --uid was set; drop uid/gid via setresuid in the child. Needs root.
    uid_switch,
    /// Linux 5.13+ with Landlock LSM enabled. Applies a path-beneath ruleset
    /// in the child right before exec. Works unprivileged.
    landlock,
    /// --uid AND Landlock both requested / available: defense in depth.
    uid_and_landlock,
};

// ── Public API ──────────────────────────────────────────────────────

/// Apply chown/chmod to the deny and allow_rw paths so the kernel's permission
/// check enforces the sandbox boundary for the child.
///
/// - `deny`: chown to caller (typically root), mode 0700 → child uid sees EACCES.
/// - `allow_rw`: created if missing, chown to sandbox uid, mode 0700 → child uid
///   has full access; everyone else (including root's supp groups, per file
///   mode bits) is restricted.
pub fn applyPermissions(args: Args.Parsed, ids: Ids) Error!void {
    // No uid switch requested → skip chown entirely. chown(2) requires root
    // even to set a file to its current owner, so calling it unconditionally
    // would fail in unsandboxed mode.
    const switching_uid = args.uid != null;

    const caller_uid: u32 = c.getuid();
    const caller_gid: u32 = c.getgid();

    for (args.hide) |path| {
        if (switching_uid) try chownIfExists(path, caller_uid, caller_gid);
        try chmodIfExists(path, 0o700);
    }

    for (args.rw) |path| {
        try mkdirP(path);
        // Refuse to chmod/chown a symlink: would silently retarget the
        // sandbox to wherever the link points (e.g. /etc/passwd).
        if (try isSymlink(path)) return error.AccessDenied;
        if (switching_uid) try chown(path, ids.uid, ids.gid);
        try chmod(path, 0o700);
    }

    // ro paths: must already exist (caller shouldn't ask us to create
    // /usr if missing). Under --best-effort, a missing path is a warning.
    for (args.ro) |path| {
        if (pathExists(path)) continue;
        if (args.best_effort) {
            writeStderr("agent-jail: warning: --ro path missing, skipping: ");
            writeStderr(path);
            writeStderr("\n");
            continue;
        }
        return error.FileNotFound;
    }
}

/// Return a copy of `ro` with non-existent paths filtered out. Used by the
/// child before calling landlock.apply, so --system-ro works uniformly on
/// hosts that don't have /lib64 or /usr/sbin (macOS, Alpine, etc).
pub fn existingRoPaths(arena: std.mem.Allocator, ro: []const []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (ro) |p| if (pathExists(p)) try out.append(arena, p);
    return out.items;
}

/// Decide which backend(s) apply given the CLI args and host capabilities.
/// Call AFTER applyPermissions (which is cheap + harmless for all backends).
pub fn pickBackend(args: Args.Parsed) Backend {
    const wants_uid = args.uid != null;
    const wants_paths = args.rw.len > 0 or args.ro.len > 0;

    if (!wants_uid and !wants_paths) return .none;

    const ll_ok = builtin.os.tag == .linux and landlock.isAvailable();

    if (wants_uid and ll_ok and wants_paths) return .uid_and_landlock;
    if (wants_uid) return .uid_switch;
    if (ll_ok) return .landlock;
    return .none; // fell through: caller should have errored earlier
}

/// Fork, set up the sandbox in the child, exec, wait for the child.
/// Returns the child's exit code (or 128+signal if it was signalled, or 127
/// if exec failed).
///
/// Signal forwarding: handlers for TERM/INT/HUP/QUIT in the parent relay to
/// the entire child process group so killing agent-jail reaps the whole tree
/// rather than orphaning it to init.
///
/// Not safe to call concurrently from multiple threads in the same process —
/// signal forwarding uses a process-global `child_pid` slot.
pub fn spawnAndWait(gpa: std.mem.Allocator, args: Args.Parsed, ids: Ids) Error!u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const argvz = arena.alloc(?[*:0]const u8, args.command.len + 1) catch return error.OutOfMemory;
    for (args.command, 0..) |s, i| {
        const z = arena.allocSentinel(u8, s.len, 0) catch return error.OutOfMemory;
        @memcpy(z, s);
        argvz[i] = z.ptr;
    }
    argvz[args.command.len] = null;

    var cwdz_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwdz: ?[*:0]const u8 = if (args.cwd) |p| blk: {
        const z = std.fmt.bufPrintZ(&cwdz_buf, "{s}", .{p}) catch return error.PathTooLong;
        break :blk z.ptr;
    } else null;

    const pid = c.fork();
    if (pid < 0) return error.ForkFailed;

    if (pid == 0) {
        // ── child ──────────────────────────────────────────────────
        childSetup(args, ids, cwdz);
        _ = c.execvp(argvz[0].?, argvz.ptr);
        // execvp only returns on failure.
        writeStderr("agent-jail: exec failed\n");
        c.exit(127);
    }

    // ── parent ────────────────────────────────────────────────────
    signal_forward.install(pid);
    defer signal_forward.uninstall();

    var status: c_int = 0;
    while (true) {
        const rc = c.waitpid(pid, &status, 0);
        if (rc == -1) {
            if (c.lastErrno() == .INTR) continue;
            return error.Unexpected;
        }
        break;
    }

    if (wifexited(status)) return @intCast(wexitstatus(status));
    if (wifsignaled(status)) return 128 + @as(u8, @intCast(wtermsig(status) & 0x7f));
    return 1;
}

// ── Child setup ─────────────────────────────────────────────────────

/// Child-side setup between fork and exec:
/// 1. chdir (if --cwd) so it runs in the right directory.
/// 2. setpgid(0, 0) — fresh process group for signal forwarding.
/// 3. Close every FD >= 3 so nothing leaks from parent into the sandbox.
/// 4. setgroups(0) — drop supplementary groups (root only; ignored otherwise).
/// 5. setresgid → setresuid (in that order; once uid drops we can't set gid).
fn childSetup(args: Args.Parsed, ids: Ids, cwdz: ?[*:0]const u8) void {
    if (cwdz) |p| {
        if (c.chdir(p) != 0) {
            writeStderr("agent-jail: chdir failed\n");
            c.exit(127);
        }
    }

    _ = c.setpgid(0, 0);
    closeFdsAboveStdio();

    // Apply Landlock BEFORE uid switch: landlock_restrict_self only requires
    // PR_SET_NO_NEW_PRIVS or CAP_SYS_ADMIN, and we still have caps here if we
    // started as root. After setuid the effective caps drop anyway.
    if (builtin.os.tag == .linux) applyLandlockIfRequested(args);

    if (args.uid != null) {
        _ = c.setgroups(0, null);
        if (c.setGidAll(ids.gid) != 0) {
            writeStderr("agent-jail: set gid failed\n");
            c.exit(127);
        }
        if (c.setUidAll(ids.uid) != 0) {
            writeStderr("agent-jail: set uid failed\n");
            c.exit(127);
        }
    }
}

/// If the user asked for path-based sandboxing (--rw/--ro) and Landlock
/// is usable, apply it. Silent skip otherwise — parent has already decided
/// via pickBackend whether that's acceptable.
fn applyLandlockIfRequested(args: Args.Parsed) void {
    if (builtin.os.tag != .linux) return;
    if (args.rw.len == 0 and args.ro.len == 0) return;
    if (!landlock.isAvailable()) return;

    // Filter --ro paths that don't exist on this host (e.g. /lib64 on
    // Alpine). Without this, landlock_add_rule returns ENOENT and fails
    // the whole call. Under --best-effort we've already warned in
    // applyPermissions; here we just trim.
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const ro_existing = existingRoPaths(arena_state.allocator(), args.ro) catch args.ro;

    landlock.apply(.{
        .allow_rw = args.rw,
        .allow_ro = ro_existing,
    }) catch |err| {
        // Landlock failure is fatal in the child — the caller asked for
        // isolation and we couldn't deliver it. Better to error than ship a
        // false sense of security.
        var msg_buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "agent-jail: landlock failed: {s}\n", .{@errorName(err)}) catch "agent-jail: landlock failed\n";
        writeStderr(msg);
        c.exit(127);
    };
}

/// Close every FD >= 3. Uses Linux's `close_range(3, ~0, 0)` syscall if
/// available (single syscall, O(1)); falls back to a close(2) loop up to
/// RLIMIT_NOFILE on macOS/BSD/older Linux.
fn closeFdsAboveStdio() void {
    if (builtin.os.tag == .linux) {
        // syscall number 436 on every architecture Linux 5.9+ supports.
        const SYS_close_range: usize = 436;
        const rc = std.os.linux.syscall3(
            @enumFromInt(SYS_close_range),
            3,
            std.math.maxInt(c_uint),
            0,
        );
        if (rc == 0) return; // success
        // ENOSYS on pre-5.9 kernels: fall through to loop.
    }

    var rl: c.Rlimit = .{ .rlim_cur = 4096, .rlim_max = 4096 };
    _ = c.getrlimit(c.RLIMIT_NOFILE, &rl);
    const limit: c_int = @intCast(@min(rl.rlim_cur, 65536));
    var fd: c_int = 3;
    while (fd < limit) : (fd += 1) {
        _ = c.close(fd);
    }
}

fn writeStderr(s: []const u8) void {
    _ = c.write(2, s.ptr, s.len);
}

// ── Signal forwarding ───────────────────────────────────────────────

/// Forward termination signals from the parent to the child's process group.
/// A process-global `child_pid` is required because POSIX signal handlers
/// take only the signal number — no userdata pointer. Safe because agent-jail
/// wraps exactly one child per invocation, single-threaded.
const signal_forward = struct {
    var child_pid: std.c.pid_t = 0;
    const forwarded = [_]std.c.SIG{ .TERM, .INT, .HUP, .QUIT };

    fn install(pid: std.c.pid_t) void {
        child_pid = pid;
        var act: std.c.Sigaction = undefined;
        act.handler = .{ .handler = handle };
        _ = std.c.sigemptyset(&act.mask);
        act.flags = 0;
        for (forwarded) |sig| _ = std.c.sigaction(sig, &act, null);
    }

    fn uninstall() void {
        child_pid = 0;
        var act: std.c.Sigaction = undefined;
        act.handler = .{ .handler = std.c.SIG.DFL };
        _ = std.c.sigemptyset(&act.mask);
        act.flags = 0;
        for (forwarded) |sig| _ = std.c.sigaction(sig, &act, null);
    }

    fn handle(sig: std.c.SIG) callconv(.c) void {
        if (child_pid <= 0) return;
        // Negative pid → signal the whole process group.
        _ = std.c.kill(-child_pid, sig);
    }
};

// ── wait(2) status decoding ─────────────────────────────────────────

fn wifexited(s: c_int) bool {
    return (s & 0x7f) == 0;
}
fn wexitstatus(s: c_int) c_int {
    return (s >> 8) & 0xff;
}
fn wifsignaled(s: c_int) bool {
    const low = s & 0x7f;
    return low != 0 and low != 0x7f;
}
fn wtermsig(s: c_int) c_int {
    return s & 0x7f;
}

// ── Path-level POSIX wrappers ───────────────────────────────────────

fn chown(path: []const u8, uid: u32, gid: u32) Error!void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{path}) catch return error.PathTooLong;
    if (c.chown(z.ptr, uid, gid) == 0) return;
    return errnoToError();
}

fn chmod(path: []const u8, mode: u16) Error!void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{path}) catch return error.PathTooLong;
    if (c.chmod(z.ptr, mode) == 0) return;
    return errnoToError();
}

fn chownIfExists(path: []const u8, uid: u32, gid: u32) Error!void {
    chown(path, uid, gid) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
}

fn chmodIfExists(path: []const u8, mode: u16) Error!void {
    chmod(path, mode) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
}

/// Idempotent `mkdir -p` via libc: walks the path, creating each component
/// with mode 0700. An existing directory at any level is fine; anything
/// else (a file in the way, permission error) surfaces. Caller chmod's the
/// final leaf afterwards so the mkdir mode is not load-bearing.
fn mkdirP(path: []const u8) Error!void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    if (path.len == 0 or path.len >= buf.len) return error.PathTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;

    var i: usize = 1; // skip any leading '/'
    while (i <= path.len) : (i += 1) {
        if (i == path.len or path[i] == '/') {
            const saved = buf[i];
            buf[i] = 0;
            const rc = c.mkdir(@ptrCast(&buf), 0o700);
            buf[i] = saved;
            if (rc != 0) switch (c.lastErrno()) {
                .EXIST => {}, // already there — fine
                .NOENT => return error.FileNotFound,
                .ACCES, .PERM => return error.AccessDenied,
                else => return error.Unexpected,
            };
        }
    }
}

fn errnoToError() Error {
    return switch (c.lastErrno()) {
        .NOENT => error.FileNotFound,
        .ACCES, .PERM => error.AccessDenied,
        else => error.Unexpected,
    };
}

fn pathExists(path: []const u8) bool {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{path}) catch return false;
    return c.access(z.ptr, 0) == 0; // F_OK = 0
}

/// Is the given path a symlink? Checked via readlink(2): returns the link
/// target if it is a symlink, fails with EINVAL if not. Avoids the per-
/// platform `struct stat` layout mess.
fn isSymlink(path: []const u8) Error!bool {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{path}) catch return error.PathTooLong;
    var dummy: [1]u8 = undefined;
    const rc = c.readlink(z.ptr, &dummy, dummy.len);
    if (rc >= 0) return true;
    return switch (c.lastErrno()) {
        .INVAL => false, // not a symlink
        .NOENT => false, // doesn't exist (shouldn't happen post-mkdirP)
        .ACCES, .PERM => error.AccessDenied,
        else => error.Unexpected,
    };
}

// ── libc syscall shims ──────────────────────────────────────────────
//
// std.Io in 0.16 doesn't expose path-level chown/chmod/mkdir, and its
// std.process.spawn doesn't close caller FDs or drop supplementary groups.
// Going through libc directly gives us precise control — these are stable
// POSIX syscalls, identical on Linux/macOS/BSD.

const c = struct {
    // Process lifecycle.
    extern "c" fn fork() std.c.pid_t;
    extern "c" fn execvp(file: [*:0]const u8, argv: [*]const ?[*:0]const u8) c_int;
    extern "c" fn waitpid(pid: std.c.pid_t, status: *c_int, opts: c_int) std.c.pid_t;
    extern "c" fn exit(status: c_int) noreturn;

    // Identity.
    extern "c" fn getuid() u32;
    extern "c" fn getgid() u32;
    extern "c" fn setgroups(size: usize, list: ?[*]const u32) c_int;
    extern "c" fn setpgid(pid: std.c.pid_t, pgid: std.c.pid_t) c_int;

    // uid/gid setters. Linux/FreeBSD have setresuid/gid (real+effective+saved
    // in one call); macOS/BSD only ship setreuid/gid (real+effective). For a
    // drop-privileges-forever use, saved = effective is fine either way.
    const use_setres = switch (builtin.os.tag) {
        .linux, .freebsd => true,
        else => false,
    };
    extern "c" fn setresgid(rgid: u32, egid: u32, sgid: u32) c_int;
    extern "c" fn setresuid(ruid: u32, euid: u32, suid: u32) c_int;
    extern "c" fn setregid(rgid: u32, egid: u32) c_int;
    extern "c" fn setreuid(ruid: u32, euid: u32) c_int;

    pub fn setGidAll(gid: u32) c_int {
        return if (use_setres) setresgid(gid, gid, gid) else setregid(gid, gid);
    }
    pub fn setUidAll(uid: u32) c_int {
        return if (use_setres) setresuid(uid, uid, uid) else setreuid(uid, uid);
    }

    // Filesystem.
    extern "c" fn chown(path: [*:0]const u8, owner: u32, group: u32) c_int;
    extern "c" fn chmod(path: [*:0]const u8, mode: u16) c_int;
    extern "c" fn chdir(path: [*:0]const u8) c_int;
    extern "c" fn mkdir(path: [*:0]const u8, mode: u16) c_int;
    extern "c" fn readlink(path: [*:0]const u8, buf: [*]u8, bufsiz: usize) isize;
    pub extern "c" fn access(path: [*:0]const u8, mode: c_int) c_int;

    // FDs + I/O.
    extern "c" fn close(fd: c_int) c_int;
    extern "c" fn write(fd: c_int, buf: [*]const u8, len: usize) isize;

    // Resource limits.
    pub const Rlimit = extern struct {
        rlim_cur: u64,
        rlim_max: u64,
    };
    /// RLIMIT_NOFILE's numeric value is 7 on Linux, 8 on macOS. Comptime.
    pub const RLIMIT_NOFILE: c_int = switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos, .visionos => 8,
        else => 7,
    };
    extern "c" fn getrlimit(resource: c_int, rlim: *Rlimit) c_int;

    /// Thread-local errno via std.c._errno(). Portable across glibc/musl/
    /// darwin/bsd — they all expose a function returning *c_int to the TLS
    /// errno slot.
    pub fn lastErrno() std.c.E {
        return @enumFromInt(std.c._errno().*);
    }
};

// ── tests ────────────────────────────────────────────────────────────

test "chown nonexistent → FileNotFound" {
    try std.testing.expectError(error.FileNotFound, chown("/definitely/does/not/exist/12345", 0, 0));
}

test "chmod nonexistent → FileNotFound" {
    try std.testing.expectError(error.FileNotFound, chmod("/definitely/does/not/exist/12345", 0o700));
}

test "mkdirP rejects empty and oversized paths" {
    try std.testing.expectError(error.PathTooLong, mkdirP(""));
    const huge = [_]u8{'a'} ** (std.fs.max_path_bytes + 1);
    try std.testing.expectError(error.PathTooLong, mkdirP(&huge));
}
