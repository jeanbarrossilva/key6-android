const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize_mode = b.standardOptimizeOption(.{});
    const dependency_args = .{
        .target = target,
        .optimize = optimize_mode,
    };

    const uuid_module = b.dependency("uuid", dependency_args).module("uuid");

    const core_module = b.addModule("core", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "uuid", .module = uuid_module },
        },
    });
    const core_exe = b.addExecutable(.{
        .name = "core",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize_mode,
            .imports = &.{
                .{ .name = "core", .module = core_module },
            },
        }),
    });
    b.installArtifact(core_exe);
    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(core_exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args|
        run_cmd.addArgs(args);
    const test_module = b.addTest(.{ .root_module = core_module });
    const run_test_module = b.addRunArtifact(test_module);
    const test_exe = b.addTest(.{
        .root_module = test_module.root_module,
    });
    const test_exe_run = b.addRunArtifact(test_exe);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_test_module.step);
    test_step.dependOn(&test_exe_run.step);
}
