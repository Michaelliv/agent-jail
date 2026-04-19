//! Sandboxing core: permission setup + spawn with backend dispatch.
//!
//! Four layers, any combination may apply per call:
//!   - uid switch: chown/chmod hide+rw paths, then in the child call
//!     setgroups(0)/setresgid/setresuid before exec. POSIX, any UNIX.
//!   - Landlock: in the child, apply a landlock ruleset with path-beneath
//!     rules right before exec. Linux 5.13+, unprivileged.
//!   - PID namespace: on Linux, layer a fresh user+mount+PID namespace via
//!     a double-fork so the child's view of `/proc` and reach of `kill(2)`
//!     stops at its own subtree. See pidns.zig.
//!   - Sandbox kext: on macOS, render an SBPL profile and exec via
//!     sandbox-exec(1). See darwin.zig.
//!
//! Child-side setup runs between a manual fork and execvp: chdir, new
//! process group, close all non-stdio FDs, Landlock (if requested),
//! setgroups(0), setresgid, setresuid, then exec. std.process.spawn is
//! not used because it leaves caller FDs open and keeps supplementary
//! groups.

const std = @import("std");
const builtin = @import("builtin");
const Args = @import("args.zig");
const landlock = @import("landlock.zig");
const pidns = @import("pidns.zig");
const darwin = @import("darwin.zig");

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
///
/// Orthogonal to this: PID-namespace isolation is layered on automatically
/// on Linux whenever any sandbox params are present and unprivileged user
/// namespaces are permitted. See `Plan.pid_isolation`.
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
    /// macOS Sandbox kext via sandbox-exec(1). Renders an SBPL profile from
    /// --rw/--ro/--hide and exec's sandbox-exec instead of the command
    /// directly. See darwin.zig.
    sandbox_exec,
};

/// Resolved sandboxing plan: the filesystem/identity backend plus whether
/// to also enter a fresh PID namespace. PID-ns is layered on top of any
/// other backend; it confines `kill` and `/proc` to the agent's own subtree.
pub const Plan = struct {
    backend: Backend,
    pid_isolation: bool,
};

// ── Public API ──────────────────────────────────────────────────────

/// Apply chown/chmod to the hide and rw paths so the kernel's permission
/// check enforces the sandbox boundary for the child.
///
/// - `hide`: chmod 0700 (best-effort — silent skip if we don't own it),
///           plus chown to caller when uid switching.
/// - `rw`:   created if missing, mode 0700 (only on paths we created or
///           when uid switching), chown to sandbox uid when switching.
///
/// The chmods on pre-existing `--rw` paths are deliberately skipped
/// without uid switching — they'd fail loudly on root-owned paths like
/// `--rw /dev`, and they'd be wrong on shared dirs the caller passed in.
/// Hide chmods tolerate AccessDenied for the same reason; the canonical
/// `--hide /etc` shouldn't refuse to run.
pub fn applyPermissions(args: Args.Parsed, ids: Ids) Error!void {
    // chown(2) requires root even to set a file to its current owner, so
    // skip it entirely when we aren't switching uid.
    const switching_uid = args.uid != null;

    const caller_uid: u32 = c.getuid();
    const caller_gid: u32 = c.getgid();

    for (args.hide) |path| {
        if (switching_uid) try chownIfExists(path, caller_uid, caller_gid);
        // Always try chmod — even without uid switching, locking a
        // caller-owned path to 0700 hides it from other host users.
        // Tolerate AccessDenied (path isn't ours; nothing to do without
        // root) so e.g. `--hide /etc` doesn't error out.
        chmodIfExists(path, 0o700) catch |err| switch (err) {
            error.AccessDenied => {},
            else => return err,
        };
    }

    for (args.rw) |path| {
        const created = try mkdirPCreated(path);
        // Reject symlinks at the top of an rw path: following one would
        // silently retarget the sandbox to the link target.
        if (try isSymlink(path)) return error.AccessDenied;
        if (switching_uid) try chown(path, ids.uid, ids.gid);
        // Lock down to 0700, but only on paths we just created (and so
        // own). Pre-existing paths might be root-owned (--rw /dev) or
        // shared with other tools, where chmod would fail or be wrong.
        if (switching_uid or created) try chmod(path, 0o700);
    }

    // ro paths must already exist; missing is fatal unless --best-effort.
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

/// Return `ro` with non-existent paths filtered out. landlock_add_rule
/// fails the whole call on ENOENT, and --system-ro lists paths not
/// present on every host (e.g. /lib64 on Alpine).
pub fn existingRoPaths(arena: std.mem.Allocator, ro: []const []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (ro) |p| if (pathExists(p)) try out.append(arena, p);
    return out.items;
}

/// Decide which backend(s) apply given the CLI args and host capabilities.
pub fn pickBackend(args: Args.Parsed) Backend {
    const wants_uid = args.uid != null;
    const wants_paths = args.rw.len > 0 or args.ro.len > 0 or
        args.hide.len > 0 or args.list.len > 0;

    if (!wants_uid and !wants_paths) return .none;

    // macOS: any path verb routes through sandbox-exec. uid is layered
    // separately in childSetup, so --uid + paths still works — the kernel
    // sees both the SBPL profile and the dropped uid.
    if (darwin.isAvailable() and wants_paths) return .sandbox_exec;

    const ll_ok = builtin.os.tag == .linux and landlock.isAvailable();

    if (wants_uid and ll_ok and wants_paths) return .uid_and_landlock;
    if (wants_uid) return .uid_switch;
    if (ll_ok) return .landlock;
    return .none;
}

/// Full plan: filesystem/identity backend plus whether to enter a PID
/// namespace. PID-ns activates whenever the user asked for any sandboxing
/// (--rw/--ro/--uid) on Linux AND a pre-flight probe confirms unshare +
/// uid_map writes succeed end-to-end. The probe avoids committing the
/// real spawn to a double-fork flow on hosts where the namespace setup is
/// half-broken (some CI runners, restricted containers).
pub fn pickPlan(args: Args.Parsed) Plan {
    const backend = pickBackend(args);
    const pid_isolation = backend != .none and pidns.probe();
    return .{ .backend = backend, .pid_isolation = pid_isolation };
}

/// Fork, set up the sandbox in the child, exec, wait for the child.
/// Returns the child's exit code, 128+signal if signalled, or 127 on exec
/// failure.
///
/// TERM/INT/HUP/QUIT received by the parent are forwarded to the child's
/// process group, so killing agent-jail reaps the whole tree.
///
/// When `plan.pid_isolation` is set, the structure is parent → intermediate
/// → real child: the intermediate enters a fresh user+mount+PID namespace
/// and forks again so the grandchild is PID 1 in the new namespace. The
/// intermediate is a thin shim that waits on the grandchild and re-exits
/// with its status.
///
/// Not safe to call from multiple threads: signal forwarding uses a
/// process-global slot.
pub fn spawnAndWait(gpa: std.mem.Allocator, args: Args.Parsed, ids: Ids, plan: Plan) Error!u8 {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Build argv. For sandbox-exec, prepend ["sandbox-exec", "-p", profile]
    // so the spawn target becomes sandbox-exec itself, which then re-execs
    // the real command under the rendered profile.
    const exec_argv = if (plan.backend == .sandbox_exec)
        try buildSandboxExecArgv(arena, args)
    else
        args.command;

    const argvz = arena.alloc(?[*:0]const u8, exec_argv.len + 1) catch return error.OutOfMemory;
    for (exec_argv, 0..) |s, i| {
        const z = arena.allocSentinel(u8, s.len, 0) catch return error.OutOfMemory;
        @memcpy(z, s);
        argvz[i] = z.ptr;
    }
    argvz[exec_argv.len] = null;

    var cwdz_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwdz: ?[*:0]const u8 = if (args.cwd) |p| blk: {
        const z = std.fmt.bufPrintZ(&cwdz_buf, "{s}", .{p}) catch return error.PathTooLong;
        break :blk z.ptr;
    } else null;

    const pid = c.fork();
    if (pid < 0) return error.ForkFailed;

    if (pid == 0) {
        // ── outer child ────────────────────────────────────────────
        if (plan.pid_isolation) {
            runIntermediate(args, ids, cwdz, argvz);
        } else {
            childSetup(args, ids, cwdz);
            _ = c.execvp(argvz[0].?, argvz.ptr);
            writeStderr("agent-jail: exec failed\n");
            c.exit(127);
        }
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

fn buildSandboxExecArgv(arena: std.mem.Allocator, args: Args.Parsed) Error![]const []const u8 {
    const profile = darwin.renderProfile(arena, .{
        .rw = args.rw,
        .ro = args.ro,
        .hide = args.hide,
        .list = args.list,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.PathTooLong => return error.PathTooLong,
    };

    // [sandbox-exec, -p, <profile>, <command...>]
    var out = arena.alloc([]const u8, 3 + args.command.len) catch return error.OutOfMemory;
    out[0] = "sandbox-exec";
    out[1] = "-p";
    out[2] = profile;
    for (args.command, 0..) |s, i| out[3 + i] = s;
    return out;
}

/// Intermediate process for PID-namespace isolation.
///
/// CLONE_NEWPID semantics: unshare() doesn't move the calling process into
/// the new PID namespace; it makes the *next* fork land there as PID 1. So
/// the intermediate enters the namespace, forks the real child, then waits
/// and re-exits with the child's status.
///
/// `pickPlan` only sets `pid_isolation = true` after a successful probe,
/// so reaching `pidns.enter` failure here is unexpected. Treat it as
/// fatal: a half-set-up namespace is worse than no isolation, and the
/// probe should have caught any environment that can't deliver it.
fn runIntermediate(
    args: Args.Parsed,
    ids: Ids,
    cwdz: ?[*:0]const u8,
    argvz: []?[*:0]const u8,
) noreturn {
    pidns.enter() catch |err| {
        var msg_buf: [160]u8 = undefined;
        const msg = std.fmt.bufPrint(
            &msg_buf,
            "agent-jail: pidns.enter failed after probe succeeded ({s})\n",
            .{@errorName(err)},
        ) catch "agent-jail: pidns.enter failed\n";
        writeStderr(msg);
        c.exit(1);
    };

    const inner = c.fork();
    if (inner < 0) {
        writeStderr("agent-jail: inner fork failed\n");
        c.exit(1);
    }

    if (inner == 0) {
        // ── grandchild ── PID 1 in the new namespace ──────────────
        childSetup(args, ids, cwdz);
        _ = c.execvp(argvz[0].?, argvz.ptr);
        writeStderr("agent-jail: exec failed\n");
        c.exit(127);
    }

    // Intermediate: wait for the grandchild and propagate its status. We
    // act as the namespace's init equivalent for status reporting; if we
    // died first the grandchild would still be reaped by the kernel (PID 1
    // death → namespace teardown), but the parent would lose the exit code.
    var status: c_int = 0;
    while (true) {
        const rc = c.waitpid(inner, &status, 0);
        if (rc == -1) {
            if (c.lastErrno() == .INTR) continue;
            c.exit(1);
        }
        break;
    }
    if (wifexited(status)) c.exit(@intCast(wexitstatus(status)));
    if (wifsignaled(status)) {
        // Re-raise the signal so the outer parent sees "died by signal"
        // semantics and reports 128+sig accordingly.
        const sig = wtermsig(status);
        _ = c.kill(c.getpid(), sig);
    }
    c.exit(1);
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

    // Landlock must be applied before the uid switch: landlock_restrict_self
    // needs either CAP_SYS_ADMIN or PR_SET_NO_NEW_PRIVS, and effective caps
    // drop on setuid.
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

/// Apply Landlock if --rw / --ro / --list were given and the host
/// supports it. Silent skip otherwise; the parent decided via
/// pickBackend whether that was acceptable.
fn applyLandlockIfRequested(args: Args.Parsed) void {
    if (builtin.os.tag != .linux) return;
    if (args.rw.len == 0 and args.ro.len == 0 and args.list.len == 0) return;
    if (!landlock.isAvailable()) return;

    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const ro_existing = existingRoPaths(arena_state.allocator(), args.ro) catch args.ro;
    const list_existing = existingRoPaths(arena_state.allocator(), args.list) catch args.list;

    landlock.apply(.{
        .rw = args.rw,
        .ro = ro_existing,
        .list = list_existing,
    }) catch |err| {
        // Fatal: the caller asked for isolation we can't deliver.
        var msg_buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "agent-jail: landlock failed: {s}\n", .{@errorName(err)}) catch "agent-jail: landlock failed\n";
        writeStderr(msg);
        c.exit(127);
    };
}

/// Close every FD >= 3. Prefers close_range(2) on Linux 5.9+, falls back
/// to a close(2) loop up to RLIMIT_NOFILE.
fn closeFdsAboveStdio() void {
    if (builtin.os.tag == .linux) {
        const SYS_close_range: usize = 436;
        const rc = std.os.linux.syscall3(
            @enumFromInt(SYS_close_range),
            3,
            std.math.maxInt(c_uint),
            0,
        );
        if (rc == 0) return;
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

/// Forward termination signals from the parent to the child's process
/// group. The `child_pid` slot is process-global because POSIX signal
/// handlers take no userdata pointer; safe given agent-jail wraps one
/// child per invocation.
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
        _ = std.c.kill(-child_pid, sig); // negative pid = whole pgroup
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

/// Idempotent `mkdir -p`. Each component is created mode 0700; caller
/// chmods the leaf afterwards, so the mkdir mode is not load-bearing.
/// Returns true iff the leaf component was created by this call (i.e.
/// did not already exist). Intermediate components don't affect the result.
fn mkdirPCreated(path: []const u8) Error!bool {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    if (path.len == 0 or path.len >= buf.len) return error.PathTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;

    var leaf_created = false;
    var i: usize = 1; // skip leading '/'
    while (i <= path.len) : (i += 1) {
        if (i == path.len or path[i] == '/') {
            const is_leaf = i == path.len;
            const saved = buf[i];
            buf[i] = 0;
            const rc = c.mkdir(@ptrCast(&buf), 0o700);
            buf[i] = saved;
            if (rc == 0) {
                if (is_leaf) leaf_created = true;
            } else switch (c.lastErrno()) {
                .EXIST => {},
                .NOENT => return error.FileNotFound,
                .ACCES, .PERM => return error.AccessDenied,
                else => return error.Unexpected,
            }
        }
    }
    return leaf_created;
}

fn mkdirP(path: []const u8) Error!void {
    _ = try mkdirPCreated(path);
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
    return c.access(z.ptr, 0) == 0; // F_OK
}

/// Probe via readlink(2): succeeds if path is a symlink, fails EINVAL if
/// not. Avoids pulling in per-platform `struct stat`.
fn isSymlink(path: []const u8) Error!bool {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{path}) catch return error.PathTooLong;
    var dummy: [1]u8 = undefined;
    const rc = c.readlink(z.ptr, &dummy, dummy.len);
    if (rc >= 0) return true;
    return switch (c.lastErrno()) {
        .INVAL, .NOENT => false,
        .ACCES, .PERM => error.AccessDenied,
        else => error.Unexpected,
    };
}

// ── libc shims ──────────────────────────────────────────────────────

const c = struct {
    // Process lifecycle.
    extern "c" fn fork() std.c.pid_t;
    extern "c" fn execvp(file: [*:0]const u8, argv: [*]const ?[*:0]const u8) c_int;
    extern "c" fn waitpid(pid: std.c.pid_t, status: *c_int, opts: c_int) std.c.pid_t;
    extern "c" fn exit(status: c_int) noreturn;
    extern "c" fn getpid() std.c.pid_t;
    pub extern "c" fn kill(pid: std.c.pid_t, sig: c_int) c_int;

    // Identity.
    extern "c" fn getuid() u32;
    extern "c" fn getgid() u32;
    extern "c" fn setgroups(size: usize, list: ?[*]const u32) c_int;
    extern "c" fn setpgid(pid: std.c.pid_t, pgid: std.c.pid_t) c_int;

    // setresuid/gid (Linux/FreeBSD) sets real+effective+saved; setreuid/gid
    // (macOS/BSD) only sets real+effective. Equivalent for a permanent drop.
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
    /// RLIMIT_NOFILE: 7 on Linux, 8 on macOS.
    pub const RLIMIT_NOFILE: c_int = switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos, .visionos => 8,
        else => 7,
    };
    extern "c" fn getrlimit(resource: c_int, rlim: *Rlimit) c_int;

    /// Thread-local errno via std.c._errno(). Portable across glibc, musl,
    /// darwin, and bsd.
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
