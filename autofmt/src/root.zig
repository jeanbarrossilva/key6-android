const staging = @import("staging.zig");
const std = @import("std");

pub const FileInclusion = enum {
    all,
    staged,

    const PathsView = struct {
        allocator: ?std.mem.Allocator,
        staged_paths_view: ?staging.StagedPathsView,
        paths: []const []const u8,

        const empty = PathsView{
            .allocator = null,
            .staged_paths_view = null,
            .paths = &.{},
        };

        pub fn deinit(self: @This()) void {
            if (self.staged_paths_view) |staged_paths_view|
                staged_paths_view.deinit();
        }
    };

    pub fn paths(
        self: FileInclusion,
        allocator: std.mem.Allocator,
        io: std.Io,
        cwd: std.process.Child.Cwd,
        formatter: Formatter,
    ) !PathsView {
        return switch (self) {
            .all => .empty,
            .staged => _: {
                const view =
                    try staging.StagedPathsView.spawn(allocator, io, cwd);
                var list = std.ArrayList([]const u8).empty;
                defer list.deinit(allocator);
                for (view.paths) |path| {
                    for (formatter.extensions) |extension| {
                        if (!std.mem.eql(
                            u8,
                            std.fs.path.extension(path),
                            extension,
                        ))
                            continue;
                        try list.append(allocator, path);
                        break;
                    }
                }
                break :_ .{
                    .allocator = allocator,
                    .staged_paths_view = view,
                    .paths = try list.toOwnedSlice(allocator),
                };
            },
        };
    }
};
pub const Formatter = struct {
    identifier: []const u8,
    extensions: []const []const u8,
    arguments: []const []const u8,

    pub fn format(
        self: Formatter,
        allocator: std.mem.Allocator,
        io: std.Io,
        cwd: std.process.Child.Cwd,
        paths: []const []const u8,
    ) !void {
        const has_paths = paths.len > 0;
        const arguments = if (has_paths) _: {
            var with_paths =
                try allocator.alloc([]const u8, self.arguments.len + paths.len);
            @memcpy(with_paths[0..self.arguments.len], self.arguments);
            @memcpy(with_paths[self.arguments.len..], paths);
            break :_ with_paths;
        } else _: {
            break :_ self.arguments;
        };
        defer {
            if (has_paths)
                allocator.free(arguments);
        }
        _ = try std.process.run(allocator, io, .{
            .argv = arguments,
            .cwd = cwd,
        });
    }
};
