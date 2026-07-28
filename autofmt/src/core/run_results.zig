const Self = std.process.RunResult;
const std = @import("std");

pub fn validate(self: Self, allocator: std.mem.Allocator, io: std.Io) !void {
    if (self.stderr.len == 0)
        return;
    const stderr_buffer = try allocator.alloc(u8, self.stderr.len);
    defer allocator.free(stderr_buffer);
    var stderr_file_writer =
        std.Io.File.stderr().writer(io, stderr_buffer);
    const stderr_writer = &stderr_file_writer.interface;
    try stderr_writer.writeAll(self.stderr);
    try stderr_writer.flush();
    return error.ErroredSubprocess;
}

pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
    allocator.free(self.stdout);
    allocator.free(self.stderr);
}
