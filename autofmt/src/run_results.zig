const std = @import("std");

pub fn deinit(self: std.process.RunResult, allocator: std.mem.Allocator) void {
    allocator.free(self.stdout);
    allocator.free(self.stderr);
}
