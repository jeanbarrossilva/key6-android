const autofmt = @import("autofmt");
const build = @import("build");
const clap = @import("clap");
const std = @import("std");

const parameters = clap.parseParamsComptime(
    \\-h, --help    Display information on how to use this program.
    \\-p, --print   Print the paths of files that have been formatted after formatting them.
    \\-s, --staged  Only formats files that will be included in the next Git commit.
    \\<PATH>
);
const formatters = [_]autofmt.Formatter{
    .{
        .identifier = "kt",
        .extensions = &.{ ".kt", ".kts" },
        .arguments = &.{ "ktlint", "--format" },
    },
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const project_root = std.process.Child.Cwd{
        .path = std.fs.path.dirname(build.root_path) orelse build.root_path,
    };
    const parser = comptime .{ .PATH = clap.parsers.string };
    var diagnostic = clap.Diagnostic{};
    const input = clap.parse(
        clap.Help,
        &parameters,
        parser,
        init.minimal.args,
        .{
            .allocator = allocator,
            .diagnostic = &diagnostic,
        },
    ) catch |err| {
        try diagnostic.reportToFile(io, .stderr(), err);
        return err;
    };
    defer input.deinit();
    if (input.args.help != 0)
        return clap.helpToFile(io, .stdout(), clap.Help, &parameters, .{});
    const file_inclusion: autofmt.FileInclusion =
        if (input.args.staged == 0) .all else .staged;
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = if (input.args.print == 0)
        null
    else
        std.Io.File.stdout().writer(io, &stdout_buffer);
    const paths: []const []const u8 = @ptrCast(&input.positionals);
    const path_filter: autofmt.PathFilter =
        if (paths.len == 0) .all else .{ .specific = paths };
    try autofmt.run(
        allocator,
        io,
        project_root,
        &stdout_writer,
        file_inclusion,
        path_filter,
        &formatters,
    );
}
