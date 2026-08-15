const Self = []const u8;
const std = @import("std");

pub fn isBlank(self: Self) bool {
    for (self) |char|
        if (!std.ascii.isWhitespace(char))
            return false;
    return true;
}

pub fn repeat(
    self: Self,
    allocator: std.mem.Allocator,
    count: usize,
) error{OutOfMemory}![]const u8 {
    const repeated = try allocator.alloc(u8, self.len * count);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const end_index = self.len * (i + 1);
        @memcpy(repeated[end_index - self.len .. end_index], self);
    }
    return repeated;
}

test isBlank {
    try std.testing.expect(isBlank(""));
    try std.testing.expect(isBlank(" "));
    try std.testing.expect(isBlank("  "));
    try std.testing.expect(!isBlank("Key6"));
}

test "repeat(): doesn't repeat empty string" {
    const repeated = try repeat("", std.testing.allocator, 4);
    try std.testing.expectEqualSlices(u8, &.{}, repeated);
    std.testing.allocator.free(repeated);
}

test "repeat(): repeats non-blank string" {
    const repeated = try repeat("🐴", std.testing.allocator, 4);
    try std.testing.expectEqualSlices(u8, "🐴🐴🐴🐴", repeated);
    std.testing.allocator.free(repeated);
}
