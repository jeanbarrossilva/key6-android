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
        var formattable_file_paths = std.ArrayList([]const u8).empty;
        defer formattable_file_paths.deinit(allocator);
        for (paths) |path| {
            for (self.extensions) |extension| {
                if (isSuffixed(path, extension))
                    try formattable_file_paths.append(allocator, path);
            }
        }
        const argv_with_paths = try allocator.alloc(
            []const u8,
            self.argv.len + formattable_file_paths.items.len,
        );
        defer allocator.free(argv_with_paths);
        @memcpy(argv_with_paths[0..self.argv.len], self.argv);
        @memcpy(argv_with_paths[self.argv.len..], formattable_file_paths.items);
        _ = try std.process.run(allocator, io, .{
            .argv = argv_with_paths,
            .cwd = cwd,
        });
    }
};

fn isSuffixed(self: []const u8, prefix: []const u8) bool {
    return self.len >= prefix.len and std.mem.eql(
        u8,
        prefix,
        self[self.len - prefix.len .. self.len],
    );
}
