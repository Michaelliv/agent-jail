const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "agent-jail",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    b.installArtifact(exe);

    // Deterministic syscall prober used by the shell test suite. Built
    // alongside agent-jail so `zig build` produces both binaries, and
    // `zig build probe` builds just the probe.
    const probe = b.addExecutable(.{
        .name = "probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/probe/probe.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    b.installArtifact(probe);
    const probe_step = b.step("probe", "Build the test probe binary");
    probe_step.dependOn(&b.addInstallArtifact(probe, .{}).step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run agent-jail");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run unit tests");
    const test_files = [_][]const u8{ "src/main.zig", "src/args.zig", "src/sandbox.zig", "src/landlock.zig", "src/pidns.zig", "src/darwin.zig" };
    for (test_files) |path| {
        const tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(path),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });
        const run_tests = b.addRunArtifact(tests);
        test_step.dependOn(&run_tests.step);
    }
}
