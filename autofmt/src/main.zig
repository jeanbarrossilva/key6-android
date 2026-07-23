const autofmt = @import("autofmt");
const build = @import("build");
const clap = @import("clap");
const std = @import("std");

const parameters = clap.parseParamsComptime(
    \\-h, --help    Display information on how to use this program.
    \\-s, --staged  Only formats files that will be included in the next Git commit.
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
    var diagnostic = clap.Diagnostic{};
    const options = clap.parse(
        clap.Help,
        &parameters,
        clap.parsers.default,
        init.minimal.args,
        .{
            .allocator = allocator,
            .diagnostic = &diagnostic,
        },
    ) catch |err| {
        try diagnostic.reportToFile(io, .stderr(), err);
        return err;
    };
    defer options.deinit();
    if (options.args.help != 0)
        return;
    const file_inclusion: autofmt.FileInclusion =
        if (options.args.staged == 0) .all else .staged;
    for (formatters) |formatter| {
        const paths_view = try file_inclusion.paths(
            allocator,
            io,
            project_root,
            formatter,
        );
        defer paths_view.deinit();
        try formatter.format(allocator, io, project_root, paths_view.paths);
    }
}
