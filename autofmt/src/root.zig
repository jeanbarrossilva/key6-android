pub const Formatter = @import("core/formatter.zig").Formatter;
pub const PathFilter = @import("core/path_filter.zig").PathFilter;
pub const PathsView = @import("core/paths_view.zig").PathsView;
pub const std = @import("std");

pub const FileInclusion = enum {
    all,
    staged,

    fn pathsView(
        self: FileInclusion,
        allocator: std.mem.Allocator,
        io: std.Io,
        cwd: std.process.Child.Cwd,
        output_writer: ?*std.Io.Writer,
        filter: PathFilter,
        formatter: Formatter,
    ) !PathsView {
        return switch (self) {
            .all => .all(
                allocator,
                io,
                cwd,
                output_writer,
                filter,
                formatter.extensions,
            ),
            .staged => .staged(
                allocator,
                io,
                cwd,
                output_writer,
                filter,
                formatter.extensions,
            ),
        };
    }
};

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    cwd: std.process.Child.Cwd,
    output_file_writer: *?std.Io.File.Writer,
    file_inclusion: FileInclusion,
    path_filter: PathFilter,
    formatters: []const Formatter,
) !void {
    const output_writer = if (output_file_writer.*) |*file_writer|
        &file_writer.interface
    else
        null;
    for (formatters) |formatter| {
        try formatter.validate();
        var paths_view = try file_inclusion.pathsView(
            allocator,
            io,
            cwd,
            output_writer,
            path_filter,
            formatter,
        );
        defer paths_view.deinit();
        try formatter.format(allocator, io, cwd, paths_view.paths());
    }
}
