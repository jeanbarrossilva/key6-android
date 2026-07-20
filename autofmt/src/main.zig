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
    if (try autofmt.staging.StagedFilesView.spawn(
        allocator,
        io,
        cwd,
    )) |staged_files_view| {
        for (formatters) |code_formatter| {
            try code_formatter.format(
                allocator,
                io,
                cwd,
                staged_files_view.paths,
            );
        }
        staged_files_view.deinit(allocator);
    }
}
