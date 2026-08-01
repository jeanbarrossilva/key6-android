// Copyright © Jean Silva
//
// This file is part of the Key6 open-source project.
//
// Key6 is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// Key6 is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see https://www.gnu.org/licenses.

pub const configuration = @import("core/configuration/root.zig");
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
        formatter: configuration.Formatter,
    ) !PathsView {
        return switch (self) {
            .all => .all(
                allocator,
                io,
                cwd,
                output_writer,
                filter,
                formatter.extensions,
                formatter.exclusions,
            ),
            .staged => .staged(
                allocator,
                io,
                cwd,
                output_writer,
                filter,
                formatter.extensions,
                formatter.exclusions,
            ),
        };
    }
};
pub const PathFilter = @import("core/path_filter.zig").PathFilter;
pub const PathsView = @import("core/PathsView.zig");
pub const std = @import("std");

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    cwd: std.process.Child.Cwd,
    output_file_writer: *?std.Io.File.Writer,
    file_inclusion: FileInclusion,
    path_filter: PathFilter,
    formatters: []const configuration.Formatter,
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
