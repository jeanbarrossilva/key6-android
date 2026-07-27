const std = @import("std");

pub fn deinit(self: std.mem.Allocator, result: std.process.RunResult) void {
    self.free(result.stdout);
    self.free(result.stderr);
}
