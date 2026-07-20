pub const staging = @import("staging.zig");

const std = @import("std");

pub const Formatter = struct {
    identifier: []const u8,
    extensions: []const []const u8,
    argv: []const []const u8,

    pub fn format(
        self: Formatter,
        allocator: std.mem.Allocator,
        io: std.Io,
        cwd: std.process.Child.Cwd,
        paths: []const []const u8,
    ) !void {
        const argv_with_paths =
            try allocator.alloc([]const u8, self.argv.len + paths.len);
        defer allocator.free(argv_with_paths);
        @memcpy(argv_with_paths[0..self.argv.len], self.argv);
        @memcpy(argv_with_paths[self.argv.len..], paths);
        _ = try std.process.run(allocator, io, .{
            .argv = argv_with_paths,
            .cwd = cwd,
        });
    }
};
