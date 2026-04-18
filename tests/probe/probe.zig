//! Deterministic sandbox probe used by the agent-jail test suite.
//!
//! Each invocation attempts one syscall and exits with a code that
//! encodes the kernel's answer. No JSON, no heuristics — just raw
//! errno → exit-code mapping so shell tests can assert exactly what
//! the kernel allowed or denied.
//!
//! Verbs:
//!   probe read   PATH     open(PATH, O_RDONLY) + read 1 byte
//!   probe write  PATH     open(PATH, O_WRONLY|O_CREAT) + write 1 byte
//!   probe mkdir  PATH     mkdir(PATH, 0700)
//!   probe unlink PATH     unlink(PATH)
//!   probe stat   PATH     access(PATH, F_OK) — admits existence?
//!   probe signal PID      kill(PID, 0) — can we signal?
//!   probe setuid N        setuid(N) — should EPERM after a drop
//!   probe uid             prints getuid() to stdout, exit 0
//!   probe env    NAME     prints getenv(NAME) or "(unset)", exit 0
//!
//! Exit codes uniform across syscall verbs:
//!     0  allowed
//!    13  EACCES
//!     2  ENOENT / ESRCH
//!    30  EROFS
//!     1  EPERM
//!    17  EEXIST
//!   125  any other errno (with errno printed to stderr)
//!   126  usage error

const std = @import("std");

const EXIT_USAGE: u8 = 126;
const EXIT_OTHER: u8 = 125;

// POSIX open(2) flags — portable values.
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100; // Linux value; macOS overrides below.
const O_CREAT_MAC: c_int = 0x0200;

fn oCreat() c_int {
    return switch (@import("builtin").os.tag) {
        .macos, .ios, .tvos, .watchos, .visionos => O_CREAT_MAC,
        else => O_CREAT,
    };
}

fn errnoExit() u8 {
    return switch (@as(std.c.E, @enumFromInt(std.c._errno().*))) {
        .ACCES => 13,
        .NOENT => 2,
        .SRCH => 2,
        .ROFS => 30,
        .PERM => 1,
        .EXIST => 17,
        else => |e| blk: {
            var buf: [64]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "probe: unmapped errno: {s}\n", .{@tagName(e)}) catch "probe: unmapped errno\n";
            _ = c.write(2, msg.ptr, msg.len);
            break :blk EXIT_OTHER;
        },
    };
}

fn toZ(buf: *[std.fs.max_path_bytes]u8, path: []const u8) ?[*:0]const u8 {
    const z = std.fmt.bufPrintZ(buf, "{s}", .{path}) catch return null;
    return z.ptr;
}

fn doRead(path: []const u8) u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = toZ(&buf, path) orelse return EXIT_USAGE;
    const fd = c.open(z, O_RDONLY, 0);
    if (fd < 0) return errnoExit();
    defer _ = c.close(fd);
    var b: [1]u8 = undefined;
    const n = c.read(fd, &b, 1);
    if (n < 0) return errnoExit();
    return 0;
}

fn doWrite(path: []const u8) u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = toZ(&buf, path) orelse return EXIT_USAGE;
    const fd = c.open(z, O_WRONLY | oCreat(), 0o600);
    if (fd < 0) return errnoExit();
    defer _ = c.close(fd);
    const n = c.write(fd, "x".ptr, 1);
    if (n < 0) return errnoExit();
    return 0;
}

fn doMkdir(path: []const u8) u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = toZ(&buf, path) orelse return EXIT_USAGE;
    if (c.mkdir(z, 0o700) == 0) return 0;
    return errnoExit();
}

fn doUnlink(path: []const u8) u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = toZ(&buf, path) orelse return EXIT_USAGE;
    if (c.unlink(z) == 0) return 0;
    return errnoExit();
}

fn doStat(path: []const u8) u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = toZ(&buf, path) orelse return EXIT_USAGE;
    if (c.access(z, 0) == 0) return 0;
    return errnoExit();
}

fn doSignal(pid_str: []const u8) u8 {
    const pid = std.fmt.parseInt(i32, pid_str, 10) catch return EXIT_USAGE;
    if (c.kill(pid, 0) == 0) return 0;
    return errnoExit();
}

fn doSetuid(n_str: []const u8) u8 {
    const n = std.fmt.parseInt(u32, n_str, 10) catch return EXIT_USAGE;
    if (c.setuid(n) == 0) return 0;
    return errnoExit();
}

fn doUid() u8 {
    var buf: [32]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{d}\n", .{c.getuid()}) catch return EXIT_OTHER;
    _ = c.write(1, s.ptr, s.len);
    return 0;
}

fn doEnv(name: []const u8) u8 {
    var buf: [256]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{name}) catch return EXIT_USAGE;
    if (c.getenv(z.ptr)) |ptr| {
        const s = std.mem.span(ptr);
        _ = c.write(1, s.ptr, s.len);
    } else {
        const msg = "(unset)";
        _ = c.write(1, msg.ptr, msg.len);
    }
    _ = c.write(1, "\n".ptr, 1);
    return 0;
}

pub fn main(init: std.process.Init) !u8 {
    var arena = std.heap.ArenaAllocator.init(init.gpa);
    defer arena.deinit();
    const argv = try init.minimal.args.toSlice(arena.allocator());

    if (argv.len < 2) return EXIT_USAGE;
    const verb = argv[1];
    const arg1: ?[]const u8 = if (argv.len >= 3) argv[2] else null;

    if (std.mem.eql(u8, verb, "read"))   return doRead(arg1 orelse return EXIT_USAGE);
    if (std.mem.eql(u8, verb, "write"))  return doWrite(arg1 orelse return EXIT_USAGE);
    if (std.mem.eql(u8, verb, "mkdir"))  return doMkdir(arg1 orelse return EXIT_USAGE);
    if (std.mem.eql(u8, verb, "unlink")) return doUnlink(arg1 orelse return EXIT_USAGE);
    if (std.mem.eql(u8, verb, "stat"))   return doStat(arg1 orelse return EXIT_USAGE);
    if (std.mem.eql(u8, verb, "signal")) return doSignal(arg1 orelse return EXIT_USAGE);
    if (std.mem.eql(u8, verb, "setuid")) return doSetuid(arg1 orelse return EXIT_USAGE);
    if (std.mem.eql(u8, verb, "uid"))    return doUid();
    if (std.mem.eql(u8, verb, "env"))    return doEnv(arg1 orelse return EXIT_USAGE);

    return EXIT_USAGE;
}

const c = struct {
    extern "c" fn open(path: [*:0]const u8, flags: c_int, mode: c_int) c_int;
    extern "c" fn close(fd: c_int) c_int;
    extern "c" fn read(fd: c_int, buf: [*]u8, len: usize) isize;
    extern "c" fn write(fd: c_int, buf: [*]const u8, len: usize) isize;
    extern "c" fn mkdir(path: [*:0]const u8, mode: u16) c_int;
    extern "c" fn unlink(path: [*:0]const u8) c_int;
    extern "c" fn access(path: [*:0]const u8, mode: c_int) c_int;
    extern "c" fn kill(pid: i32, sig: c_int) c_int;
    extern "c" fn setuid(uid: u32) c_int;
    extern "c" fn getuid() u32;
    extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;
};
