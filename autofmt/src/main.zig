const std = @import("std");
const autofmt = @import("autofmt");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const cwd_path = try std.Io.Dir.cwd().realPathFileAlloc(
        io,
        ".",
        allocator,
    );
    defer allocator.free(cwd_path);
    const cwd = std.process.Child.Cwd{
        .path = std.fs.path.dirname(cwd_path).?,
    };
    const formatters = [_]autofmt.Formatter{
        .{
            .identifier = "kt",
            .extensions = &.{ ".kt", ".kts" },
            .argv = &.{ "ktfmt", "--format" },
        },
    };
    if (try autofmt.staging.StagedPathsView.spawn(
        allocator,
        io,
        cwd,
    )) |staged_paths_view| {
        for (formatters) |formatter|
            try formatter.format(allocator, io, cwd, staged_paths_view.paths);
        staged_paths_view.deinit(allocator);
    }
}
