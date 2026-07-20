const autofmt = @import("autofmt");
const std = @import("std");

const formatters = [_]autofmt.Formatter{
    .{
        .identifier = "kt",
        .extensions = &.{ ".kt", ".kts" },
        .argv = &.{ "ktfmt", "--format" },
    },
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const cwd_path = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
    defer allocator.free(cwd_path);
    const project_root = std.process.Child.Cwd{
        .path = std.fs.path.dirname(cwd_path).?,
    };
    const staged_paths_view =
        try autofmt.staging.StagedPathsView.spawn(allocator, io, project_root);
    for (formatters) |formatter| {
        var formattable_file_paths = std.ArrayList([]const u8).empty;
        defer formattable_file_paths.deinit(allocator);
        for (staged_paths_view.paths) |path| {
            for (formatter.extensions) |extension| {
                if (!std.mem.eql(u8, std.fs.path.extension(path), extension))
                    continue;
                try formattable_file_paths.append(allocator, path);
                break;
            }
        }
        try formatter.format(
            allocator,
            io,
            project_root,
            staged_paths_view.paths,
        );
    }
    staged_paths_view.deinit(allocator);
}
